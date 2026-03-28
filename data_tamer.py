"""
IoMT Medical NIDS Simulator — Data Taming Pipeline
═══════════════════════════════════════════════════════════════════════════════

WHAT IS "DATA TAMING"?
─────────────────────
Raw simulator output is messy for machine learning:
  • Feature scales wildly differ: bytes range 0–10M, z-scores 0–10
  • Class imbalance: benign > attack by 10–50×
  • Outliers from attack spikes can distort normalizers
  • Some flows carry NaN / None / empty strings
  • Certain features are low-variance / near-zero (useless for ML)

Data Taming applies a configurable chain of steps to produce a ML-ready
dataset while preserving interpretability.

STEPS
─────
  1. Sanitise    — fix types, fill NaN, cast strings → float
  2. Cap outliers — winsorize each feature at [1%, 99%] or a custom fence
  3. Select       — drop zero-variance, redundant, or label-leaking columns
  4. Normalise   — choose one of:
                   MinMax  → scale each feature to [0, 1]
                   Standard → z-score (mean=0, std=1)
                   Robust  → median/IQR (robust to remaining outliers)
  5. Balance     — oversample minority class (SMOTE-lite random), or
                   undersample majority class, or hybrid
  6. Report      — print full audit trail: before/after stats, class dist

OUTPUT
──────
  tamed_windows.csv      ML-ready feature matrix
  tamer_config.json      Fitted scaler params (for inference-time transform)
  taming_report.txt      Human-readable audit trail

Usage
─────
  from data_tamer import DataTamer
  tamer = DataTamer(strategy="robust", balance="undersample")
  tamer.fit(windows_df_or_dicts)
  clean = tamer.transform(windows)
  tamer.save_config("output/tamer_config.json")
  tamer.print_report()
"""

import csv
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────

# Columns that are labels / IDs — never normalised or dropped
LABEL_COLS = {"label", "attack_id", "scenario_id",
              "window_start", "window_end"}

# Columns to always drop (timestamps that leak time-ordering info)
ALWAYS_DROP = {"window_start", "window_end"}

# Minimum variance below which a feature is dropped
MIN_VARIANCE = 1e-8

# Winsorize fences (percentile)
WINSOR_LOW  = 0.01   # 1st percentile
WINSOR_HIGH = 0.99   # 99th percentile

# Label value that represents "attack" (for balancing)
ATTACK_LABELS = {"attack", "transition"}


# ──────────────────────────────────────────────────────────────────────
# Scaler parameter dataclass
# ──────────────────────────────────────────────────────────────────────

@dataclass
class FeatureScalerParam:
    """Fitted parameters for a single feature."""
    feature: str
    strategy: str           # "minmax" | "standard" | "robust"
    min_val: float = 0.0
    max_val: float = 1.0
    mean: float = 0.0
    std: float = 1.0
    median: float = 0.0
    iqr: float = 1.0
    cap_low: float = 0.0    # winsorize lower fence
    cap_high: float = 1.0   # winsorize upper fence
    dropped: bool = False
    drop_reason: str = ""

    def transform(self, value: float) -> float:
        """Apply fitted scaling to a single value."""
        if self.dropped:
            return value
        # Winsorize first
        value = max(self.cap_low, min(self.cap_high, value))
        if self.strategy == "minmax":
            denom = self.max_val - self.min_val
            return (value - self.min_val) / denom if denom else 0.0
        elif self.strategy == "standard":
            return (value - self.mean) / self.std if self.std else 0.0
        elif self.strategy == "robust":
            return (value - self.median) / self.iqr if self.iqr else 0.0
        return value

    def inverse_transform(self, value: float) -> float:
        """Reverse scaling (for interpretability)."""
        if self.strategy == "minmax":
            return value * (self.max_val - self.min_val) + self.min_val
        elif self.strategy == "standard":
            return value * self.std + self.mean
        elif self.strategy == "robust":
            return value * self.iqr + self.median
        return value


# ──────────────────────────────────────────────────────────────────────
# Data Tamer
# ──────────────────────────────────────────────────────────────────────

class DataTamer:
    """
    Full data taming pipeline for IoMT NIDS window/flow datasets.

    Parameters
    ──────────
    strategy  : "minmax" | "standard" | "robust"
    balance   : "none" | "undersample" | "oversample" | "hybrid"
    drop_ids  : drop zero-variance and always-drop columns
    verbose   : print progress
    seed      : random seed for balancing
    """

    def __init__(
        self,
        strategy: str = "robust",
        balance: str = "undersample",
        drop_ids: bool = True,
        verbose: bool = True,
        seed: int = 42,
    ) -> None:
        self.strategy = strategy
        self.balance = balance
        self.drop_ids = drop_ids
        self.verbose = verbose
        self.seed = seed
        random.seed(seed)

        self.scaler_params: Dict[str, FeatureScalerParam] = {}
        self.feature_cols: List[str] = []   # ordered list of kept features
        self.fitted: bool = False
        self._report_lines: List[str] = []
        self._class_dist_before: Dict[str, int] = {}
        self._class_dist_after: Dict[str, int] = {}

    # ── Fit ──────────────────────────────────────────────────────────

    def fit(self, records: List[Dict[str, Any]]) -> "DataTamer":
        """
        Learn scaling parameters from records.
        Only numeric fields (excluding LABEL_COLS) are processed.
        Returns self for chaining.
        """
        if not records:
            raise ValueError("No records provided to fit().")

        self._log("═" * 60)
        self._log("  IoMT Data Taming Pipeline — FIT")
        self._log(f"  Input: {len(records)} records")
        self._log(f"  Strategy: {self.strategy}  |  Balance: {self.balance}")
        self._log("═" * 60)

        # Step 1: Discover numeric columns
        all_cols = set()
        for r in records:
            all_cols.update(r.keys())
        numeric_cols = [
            c for c in sorted(all_cols)
            if c not in LABEL_COLS and self._is_numeric_col(records, c)
        ]

        self._log(f"\n[1] Discovered {len(numeric_cols)} numeric features")
        self._class_dist_before = Counter(
            str(r.get("label", "unknown")) for r in records
        )
        self._log(f"    Class distribution (before): {dict(self._class_dist_before)}")

        # Step 2: Sanitise + collect values
        col_values: Dict[str, List[float]] = defaultdict(list)
        for r in records:
            for c in numeric_cols:
                val = self._to_float(r.get(c, 0))
                col_values[c].append(val)

        # Step 3: Winsorize fences
        self._log("\n[2] Computing winsorize fences (1%–99%)")
        for c in numeric_cols:
            vals = sorted(col_values[c])
            n = len(vals)
            lo_idx = max(0, int(WINSOR_LOW * n))
            hi_idx = min(n - 1, int(WINSOR_HIGH * n))
            param = FeatureScalerParam(
                feature=c,
                strategy=self.strategy,
                cap_low=vals[lo_idx],
                cap_high=vals[hi_idx],
            )
            col_values[c] = [
                max(param.cap_low, min(param.cap_high, v))
                for v in col_values[c]
            ]
            self.scaler_params[c] = param

        # Step 4: Check variance and drop low-variance columns
        self._log("\n[3] Variance filtering")
        dropped_zero_var = []
        for c in numeric_cols:
            vals = col_values[c]
            if len(vals) < 2:
                var = 0.0
            else:
                var = statistics.pvariance(vals)
            if var < MIN_VARIANCE and self.drop_ids:
                self.scaler_params[c].dropped = True
                self.scaler_params[c].drop_reason = f"variance={var:.2e} < {MIN_VARIANCE:.2e}"
                dropped_zero_var.append(c)
        self._log(f"    Dropped {len(dropped_zero_var)} zero-variance features: "
                  f"{dropped_zero_var or 'none'}")

        # Step 5: Fit scalers on capped values
        self._log(f"\n[4] Fitting {self.strategy} scaler on kept features")
        kept = 0
        for c in numeric_cols:
            if self.scaler_params[c].dropped:
                continue
            vals = col_values[c]
            param = self.scaler_params[c]

            if self.strategy == "minmax":
                param.min_val = min(vals)
                param.max_val = max(vals)
            elif self.strategy == "standard":
                param.mean = statistics.mean(vals)
                param.std  = statistics.pstdev(vals) or 1.0
            elif self.strategy == "robust":
                sv = sorted(vals)
                n = len(sv)
                param.median = sv[n // 2]
                q1 = sv[n // 4]
                q3 = sv[3 * n // 4]
                param.iqr = (q3 - q1) or 1.0
            kept += 1

        self._log(f"    Kept {kept} features for scaling")

        # Ordered feature list (deterministic)
        self.feature_cols = [
            c for c in sorted(numeric_cols)
            if not self.scaler_params[c].dropped
        ]
        self.fitted = True
        self._log(f"\n[5] Pipeline fitted. {len(self.feature_cols)} features ready.")
        return self

    # ── Transform ────────────────────────────────────────────────────

    def transform(
        self, records: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Apply the fitted pipeline to a set of records.
        Returns new dicts with only kept features + label columns.
        """
        if not self.fitted:
            raise RuntimeError("Call fit() before transform().")

        self._log(f"\n[TRANSFORM] Applying to {len(records)} records...")
        out = []
        for r in records:
            new_r: Dict[str, Any] = {}
            # Keep label cols unchanged
            for lc in LABEL_COLS - ALWAYS_DROP:
                if lc in r:
                    new_r[lc] = r[lc]
            # Transform numeric features
            for c in self.feature_cols:
                raw = self._to_float(r.get(c, 0))
                new_r[c] = self.scaler_params[c].transform(raw)
            out.append(new_r)

        # Apply balancing
        if self.balance != "none" and out:
            out = self._balance(out)

        self._class_dist_after = Counter(
            str(r.get("label", "unknown")) for r in out
        )
        self._log(f"    Output: {len(out)} records")
        self._log(f"    Class distribution (after): {dict(self._class_dist_after)}")
        return out

    def fit_transform(
        self, records: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Convenience: fit on records and immediately transform them."""
        return self.fit(records).transform(records)

    # ── Balancing ────────────────────────────────────────────────────

    def _balance(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Balance the dataset by under- or over-sampling."""
        benign = [r for r in records if r.get("label") not in ATTACK_LABELS]
        attack = [r for r in records if r.get("label") in ATTACK_LABELS]

        if not attack or not benign:
            return records

        n_attack = len(attack)
        n_benign = len(benign)
        self._log(f"\n[BALANCE] Mode={self.balance}  "
                  f"benign={n_benign}  attack={n_attack}  "
                  f"ratio={n_benign/n_attack:.1f}:1")

        if self.balance == "undersample":
            # Reduce benign to match attack count (1:1)
            target = n_attack
            random.shuffle(benign)
            balanced = benign[:target] + attack

        elif self.balance == "oversample":
            # Duplicate attack samples (with small jitter) to match benign count
            target = n_benign
            oversampled = []
            while len(oversampled) < target:
                sample = deepcopy(random.choice(attack))
                # Add tiny gaussian noise to numeric features (0.5% std)
                for c in self.feature_cols:
                    v = float(sample.get(c, 0))
                    sample[c] = round(v + random.gauss(0, 0.005), 6)
                oversampled.append(sample)
            balanced = benign + oversampled

        elif self.balance == "hybrid":
            # Undersample benign to 2× attack, then oversample attack to match
            target_benign = min(n_benign, n_attack * 2)
            random.shuffle(benign)
            benign_sub = benign[:target_benign]
            # Oversample attack to match
            oversampled = []
            while len(oversampled) < target_benign:
                sample = deepcopy(random.choice(attack))
                for c in self.feature_cols:
                    v = float(sample.get(c, 0))
                    sample[c] = round(v + random.gauss(0, 0.005), 6)
                oversampled.append(sample)
            balanced = benign_sub + oversampled

        else:
            return records

        random.shuffle(balanced)
        self._log(f"    After balancing: {len(balanced)} records total")
        return balanced

    # ── Report ───────────────────────────────────────────────────────

    def print_report(self) -> None:
        """Print the full audit trail collected during fit/transform."""
        print("\n".join(self._report_lines))

    def report_string(self) -> str:
        """Return the full report as a string."""
        return "\n".join(self._report_lines)

    def feature_summary(self) -> str:
        """Print a table of all features with their scaler params."""
        lines = []
        lines.append(f"\n{'Feature':<32} {'Status':<10} {'Strategy':<10} "
                     f"{'Cap_Low':>10} {'Cap_High':>10} {'Scale_A':>10} {'Scale_B':>10}")
        lines.append("─" * 95)
        for c, p in sorted(self.scaler_params.items()):
            if p.dropped:
                lines.append(f"  {c:<30} {'DROPPED':<10} {'':<10}  {p.drop_reason}")
                continue
            if p.strategy == "minmax":
                a, b = p.min_val, p.max_val
                a_lbl, b_lbl = "min", "max"
            elif p.strategy == "standard":
                a, b = p.mean, p.std
                a_lbl, b_lbl = "mean", "std"
            else:  # robust
                a, b = p.median, p.iqr
                a_lbl, b_lbl = "median", "iqr"
            lines.append(
                f"  {c:<30} {'OK':<10} {p.strategy:<10} "
                f"{p.cap_low:>10.2f} {p.cap_high:>10.2f} "
                f"{a:>10.4f} {b:>10.4f}"
            )
        return "\n".join(lines)

    # ── Export ───────────────────────────────────────────────────────

    def to_csv(self, records: List[Dict[str, Any]], path: str) -> None:
        """Write tamed records to CSV."""
        if not records:
            return
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = list(records[0].keys())
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)
        self._log(f"\n[EXPORT] Wrote {len(records)} tamed records → {path}")

    def save_config(self, path: str) -> None:
        """Serialise fitted scaler params to JSON (for inference-time use)."""
        data = {
            "strategy": self.strategy,
            "balance": self.balance,
            "feature_cols": self.feature_cols,
            "params": {
                c: asdict(p) for c, p in self.scaler_params.items()
            },
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        self._log(f"[EXPORT] Tamer config saved → {path}")

    def load_config(self, path: str) -> "DataTamer":
        """Load fitted scaler params from JSON."""
        with open(path) as f:
            data = json.load(f)
        self.strategy = data["strategy"]
        self.balance = data["balance"]
        self.feature_cols = data["feature_cols"]
        self.scaler_params = {
            c: FeatureScalerParam(**pdict)
            for c, pdict in data["params"].items()
        }
        self.fitted = True
        return self

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _to_float(val: Any) -> float:
        try:
            return float(val) if val not in (None, "", "nan", "NaN") else 0.0
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def _is_numeric_col(records: List[Dict], col: str) -> bool:
        """Return True if the column appears to hold numeric values."""
        for r in records[:50]:
            v = r.get(col)
            if v is None or v == "":
                continue
            try:
                float(v)
                return True
            except (ValueError, TypeError):
                return False
        return False

    def _log(self, msg: str) -> None:
        self._report_lines.append(msg)
        if self.verbose:
            print(msg)


# ──────────────────────────────────────────────────────────────────────
# Convenience wrapper: tame a dataset file
# ──────────────────────────────────────────────────────────────────────

def tame_csv_file(
    input_path: str,
    output_path: str,
    strategy: str = "robust",
    balance:  str = "undersample",
    config_path: Optional[str] = None,
    report_path: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], DataTamer]:
    """
    One-shot helper: read a CSV, tame it, write results.

    Parameters
    ──────────
    input_path  : path to raw windows CSV (e.g. output/windows_train.csv)
    output_path : path for cleaned ML-ready CSV
    strategy    : "minmax" | "standard" | "robust"
    balance     : "none" | "undersample" | "oversample" | "hybrid"
    config_path : optional path to save tamer config JSON
    report_path : optional path to save taming report TXT

    Returns
    ───────
    (tamed_records, fitted_DataTamer)
    """
    # Read CSV
    records: List[Dict[str, Any]] = []
    with open(input_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(dict(row))

    if not records:
        raise ValueError(f"No records in {input_path}")

    print(f"\n[DataTamer] Loaded {len(records)} records from {input_path}")

    # Fit + transform
    tamer = DataTamer(strategy=strategy, balance=balance)
    tamed = tamer.fit_transform(records)

    # Write outputs
    tamer.to_csv(tamed, output_path)
    if config_path:
        tamer.save_config(config_path)
    if report_path:
        Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w") as f:
            f.write(tamer.report_string())
            f.write(tamer.feature_summary())
        print(f"[DataTamer] Report saved → {report_path}")

    print(tamer.feature_summary())
    return tamed, tamer


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import os

    print("\n" + "="*64)
    print("  IoMT Data Tamer — Standalone Demo")
    print("="*64)

    # Generate synthetic dummy windows to demo the pipeline
    random.seed(42)

    def _rand_flow(label: str, is_attack: bool = False) -> dict:
        scale = 50 if is_attack else 1
        return {
            "window_start": 0.0, "window_end": 5.0,
            "label": label,
            "attack_id": "A25" if is_attack else "",
            "scenario_id": "A25" if is_attack else "",
            "flow_count":           random.randint(1, 10) * scale,
            "pkt_count":            random.randint(5, 50) * scale,
            "byte_count":           random.randint(500, 5000) * scale,
            "unique_src_ip":        random.randint(1, 3),
            "unique_dst_ip":        random.randint(1, 3) * scale,
            "unique_dst_port":      random.randint(1, 5) * scale,
            "new_external_peers":   random.randint(0, 1) * (5 if is_attack else 0),
            "failed_login_count":   random.randint(0, 2) * (20 if is_attack else 0),
            "successful_login_count": random.randint(0, 2),
            "dicom_query_rate":     round(random.uniform(0, 2), 3),
            "dicom_move_rate":      round(random.uniform(0, 1), 3),
            "dicom_bytes_out":      random.randint(0, 50000),
            "fhir_read_rate":       round(random.uniform(0, 1), 3),
            "hl7_msg_rate":         round(random.uniform(0, 1), 3),
            "hl7_error_rate":       round(random.uniform(0, 0.1) * (10 if is_attack else 1), 4),
            "ble_telemetry_rate":   round(random.uniform(0, 2), 3),
            "replay_alerts":        random.randint(0, 1) * (5 if is_attack else 0),
            "config_write_rate":    0.0,
            "reboot_events":        0,
            "device_update_events": 0,
            "east_west_flow_count": random.randint(0, 3) * scale,
            "enterprise_to_clinical_flows": random.randint(0, 2) * scale,
            "clinical_to_external_bytes":   random.randint(0, 10000) * scale,
            "backup_server_flows":  random.randint(0, 2),
            "retransmission_rate":  round(random.uniform(0, 0.02) * (5 if is_attack else 1), 6),
            "rst_rate":             round(random.uniform(0, 0.01), 6),
            "error_4xx_5xx_rate":   round(random.uniform(0, 0.05), 4),
            "service_unavailable_rate": 0.0,
            "patient_value_jump_score": round(random.uniform(0, 0.5), 3),
            "max_device_anomaly_score": round(random.uniform(0, 0.3), 4),
            "n_anomalous_devices":  0,
            "vendor_remote_sessions": 0,
            "remote_admin_sessions": 0,
        }

    # 900 benign + 100 attack
    dummy_records = (
        [_rand_flow("benign", False) for _ in range(900)] +
        [_rand_flow("attack", True) for _ in range(100)]
    )
    random.shuffle(dummy_records)

    tamer = DataTamer(strategy="robust", balance="undersample", verbose=True)
    tamed = tamer.fit_transform(dummy_records)

    tamer.to_csv(tamed, "/tmp/iomt_tamed_windows.csv")
    tamer.save_config("/tmp/iomt_tamer_config.json")

    print(tamer.feature_summary())
    print(f"\n  ✓ {len(tamed)} tamed records written to /tmp/iomt_tamed_windows.csv")
    print(f"  ✓ Tamer config saved to /tmp/iomt_tamer_config.json")
