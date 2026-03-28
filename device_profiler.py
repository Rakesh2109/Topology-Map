"""
IoMT Medical NIDS Simulator — Device Profiler
═══════════════════════════════════════════════════════════════════════════════

WHAT IS DEVICE PROFILING?
───────────────────────────
Each IoMT device type has a characteristic "normal" behaviour:
  • A CT scanner generates DICOM flows to the PACS server, not SSH to AD.
  • An infusion pump emits small BLE telemetry bursts, not large TCP transfers.
  • A PACS server talks HTTPS/DICOM inbound from radiology workstations.

Device Profiling records these baseline statistics from BENIGN flows and then
scores any new flow or time-window against the expected profile. A large
deviation (z-score or IQR violation) is surfaced as a DEVICE_ANOMALY event.

FEATURES PROFILED (per DeviceRole):
  • Packet size distribution         → pkt_size_mean, pkt_size_std
  • Byte volume per flow             → bytes_fwd, bytes_rev
  • Connection rate                  → flows per window
  • Port diversity                   → unique_dst_port mean
  • Protocol mix                     → protocol frequency dict
  • Auth failure rate                → auth_failures / auth_attempts
  • IoMT-specific metrics            → ble_telemetry_cnt, dicom_*, hl7_*
  • Zone crossing pattern            → allowed src→dst zone pairs

OUTPUT:
  • DeviceProfile dataclass per role  (serialisable to JSON)
  • anomaly_score(flow) → float 0-1
  • enrich_window(window, flows) → adds device_anomaly_score to windows CSV

Usage:
  from device_profiler import DeviceProfiler
  profiler = DeviceProfiler()
  profiler.fit(benign_flows)           # learn baselines
  score = profiler.anomaly_score(flow) # score a flow
  profiler.save("output/profiles.json")
  profiler.load("output/profiles.json")
"""

import json
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────

# How many std deviations away is "anomalous"?
ANOMALY_Z_THRESHOLD = 3.0

# Minimum number of samples required to build a reliable baseline
MIN_SAMPLES = 10

# Feature names extracted from flows for profiling
NUMERIC_FEATURES = [
    "bytes_fwd", "bytes_rev", "pkts_fwd", "pkts_rev",
    "duration_ms", "dst_port",
    "auth_failures", "auth_attempts",
    "dicom_query_cnt", "dicom_move_cnt", "dicom_bytes",
    "fhir_read_cnt", "hl7_msg_cnt", "hl7_error_cnt",
    "ble_telemetry_cnt", "config_write_cnt",
    "retrans_cnt", "rst_cnt", "syn_cnt",
    "patient_value_jump_score",
]

# IoMT device roles that should NEVER have certain features above 0
ROLE_FORBIDDEN: Dict[str, List[str]] = {
    "infusion_pump":     ["dicom_query_cnt", "fhir_read_cnt", "auth_attempts"],
    "patient_monitor":   ["dicom_move_cnt", "config_write_cnt"],
    "ventilator":        ["dicom_query_cnt", "fhir_read_cnt", "hl7_msg_cnt"],
    "ct_scanner":        ["ble_telemetry_cnt", "auth_failures"],
    "mri_scanner":       ["ble_telemetry_cnt", "auth_failures"],
    "ble_gateway":       ["dicom_query_cnt", "dicom_move_cnt", "fhir_read_cnt"],
    "wearable":          ["dicom_query_cnt", "config_write_cnt", "hl7_msg_cnt"],
}

# Allowed zone-crossing pairs: src_zone → [allowed dst_zones]
ROLE_ALLOWED_ZONES: Dict[str, List[Tuple[str, str]]] = {
    "ct_scanner":           [("zone_d", "zone_c"), ("zone_d", "zone_d")],
    "mri_scanner":          [("zone_d", "zone_c"), ("zone_d", "zone_d")],
    "patient_monitor":      [("zone_e", "zone_e"), ("zone_e", "zone_c")],
    "infusion_pump":        [("zone_e", "zone_e"), ("zone_e", "zone_c")],
    "ventilator":           [("zone_e", "zone_e"), ("zone_e", "zone_c")],
    "ble_gateway":          [("zone_e", "zone_e"), ("zone_e", "zone_c")],
    "wearable":             [("zone_e", "zone_e")],
    "telemetry_aggregator": [("zone_e", "zone_c"), ("zone_e", "zone_e")],
    "pacs_server":          [("zone_c", "zone_c"), ("zone_c", "zone_d"), ("zone_c", "zone_b")],
    "hl7_engine":           [("zone_c", "zone_c"), ("zone_c", "zone_b")],
    "fhir_server":          [("zone_c", "zone_b"), ("zone_c", "zone_c"), ("zone_c", "zone_a")],
    "ad_server":            [("zone_b", "zone_b"), ("zone_b", "zone_c")],
    "ehr_frontend":         [("zone_b", "zone_b"), ("zone_b", "zone_c"), ("zone_b", "zone_a")],
    "backup_server":        [("zone_b", "zone_b")],
    "file_share":           [("zone_b", "zone_b"), ("zone_b", "zone_c")],
}


# ──────────────────────────────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────────────────────────────

@dataclass
class FeatureStat:
    """Running statistics for a single numeric feature."""
    mean: float = 0.0
    std: float = 0.0
    p5: float = 0.0    # 5th percentile (lower fence)
    p95: float = 0.0   # 95th percentile (upper fence)
    max_observed: float = 0.0
    n_samples: int = 0

    def is_anomalous(self, value: float) -> Tuple[bool, float]:
        """
        Returns (is_anomalous, z_score).
        Uses z-score if std > 0, otherwise flags anything > mean*2.
        """
        if self.n_samples < MIN_SAMPLES:
            return False, 0.0
        if self.std > 0:
            z = abs(value - self.mean) / self.std
            return z > ANOMALY_Z_THRESHOLD, z
        elif value > self.p95:
            return True, float("inf")
        return False, 0.0


@dataclass
class DeviceProfile:
    """Complete behavioral profile for a device role."""
    role: str
    n_flows_fitted: int = 0
    feature_stats: Dict[str, FeatureStat] = field(default_factory=dict)
    protocol_dist: Dict[str, float] = field(default_factory=dict)   # proto → fraction
    allowed_zones: List[Tuple[str, str]] = field(default_factory=list)
    forbidden_features: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "DeviceProfile":
        p = cls(role=d["role"], n_flows_fitted=d["n_flows_fitted"])
        for fname, fstat_dict in d.get("feature_stats", {}).items():
            p.feature_stats[fname] = FeatureStat(**fstat_dict)
        p.protocol_dist = d.get("protocol_dist", {})
        p.allowed_zones = [tuple(z) for z in d.get("allowed_zones", [])]
        p.forbidden_features = d.get("forbidden_features", [])
        return p


# ──────────────────────────────────────────────────────────────────────
# Device Profiler
# ──────────────────────────────────────────────────────────────────────

class DeviceProfiler:
    """
    Learns behavioral baselines per DeviceRole from benign flows,
    then scores any new flow or window against those baselines.

    Typical workflow
    ────────────────
    profiler = DeviceProfiler()
    profiler.fit(benign_flows)              # train on benign-only flows
    score, reasons = profiler.anomaly_score(flow)
    windows = profiler.enrich_windows(windows, all_flows)
    profiler.save("output/device_profiles.json")
    """

    def __init__(self) -> None:
        self.profiles: Dict[str, DeviceProfile] = {}

    # ── Fitting ──────────────────────────────────────────────────────

    def fit(self, flows: List[Dict[str, Any]]) -> "DeviceProfiler":
        """
        Build per-role profiles from a list of flow records.
        Only BENIGN flows are used (label != 'attack'/'transition').
        Flows without a device_role_src are skipped.
        """
        # Bucket flows by device role of the SOURCE device
        role_flows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for flow in flows:
            if flow.get("label") in ("attack", "transition"):
                continue
            role = str(flow.get("device_role_src", "")).strip()
            if role:
                role_flows[role].append(flow)

        for role, rflows in role_flows.items():
            self.profiles[role] = self._build_profile(role, rflows)

        print(f"[DeviceProfiler] Fitted {len(self.profiles)} device roles "
              f"from {len(flows)} flows.")
        return self

    def _build_profile(self, role: str,
                       flows: List[Dict[str, Any]]) -> DeviceProfile:
        """Compute statistics for all numeric features for one role."""
        profile = DeviceProfile(
            role=role,
            n_flows_fitted=len(flows),
            allowed_zones=ROLE_ALLOWED_ZONES.get(role, []),
            forbidden_features=ROLE_FORBIDDEN.get(role, []),
        )

        # Numeric feature stats
        for feat in NUMERIC_FEATURES:
            values = [
                float(f.get(feat, 0))
                for f in flows
                if f.get(feat) is not None
            ]
            if len(values) >= 2:
                profile.feature_stats[feat] = self._compute_stat(values)
            else:
                profile.feature_stats[feat] = FeatureStat(n_samples=len(values))

        # Protocol distribution
        proto_counts: Dict[str, int] = defaultdict(int)
        for f in flows:
            proto = str(f.get("proto", "unknown"))
            proto_counts[proto] += 1
        total = max(1, len(flows))
        profile.protocol_dist = {
            p: round(c / total, 4) for p, c in proto_counts.items()
        }

        return profile

    @staticmethod
    def _compute_stat(values: List[float]) -> FeatureStat:
        """Compute mean, std, p5, p95, max for a list of values."""
        n = len(values)
        mean = statistics.mean(values)
        std = statistics.pstdev(values) if n > 1 else 0.0
        sorted_v = sorted(values)
        p5_idx = max(0, int(0.05 * n) - 1)
        p95_idx = min(n - 1, int(0.95 * n))
        return FeatureStat(
            mean=round(mean, 4),
            std=round(std, 4),
            p5=round(sorted_v[p5_idx], 4),
            p95=round(sorted_v[p95_idx], 4),
            max_observed=round(max(values), 4),
            n_samples=n,
        )

    # ── Scoring ──────────────────────────────────────────────────────

    def anomaly_score(
        self, flow: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """
        Score a single flow against its device role's baseline.

        Returns
        ───────
        (score, reasons)
          score   : float 0.0–1.0  (0=normal, 1=maximally anomalous)
          reasons : list of human-readable anomaly descriptions
        """
        role = str(flow.get("device_role_src", "")).strip()
        profile = self.profiles.get(role)
        if not profile or profile.n_flows_fitted < MIN_SAMPLES:
            return 0.0, []

        reasons: List[str] = []
        z_scores: List[float] = []

        # 1. Numeric feature z-scores
        for feat in NUMERIC_FEATURES:
            val = float(flow.get(feat, 0))
            stat = profile.feature_stats.get(feat)
            if stat and stat.n_samples >= MIN_SAMPLES:
                is_anom, z = stat.is_anomalous(val)
                if is_anom:
                    z_scores.append(min(z, 10.0))
                    reasons.append(
                        f"{feat}={val:.1f} (expected ≤ {stat.p95:.1f}, "
                        f"z={z:.1f})"
                    )

        # 2. Forbidden-feature violations
        for feat in profile.forbidden_features:
            val = float(flow.get(feat, 0))
            if val > 0:
                reasons.append(
                    f"FORBIDDEN: {feat}={val} on role={role}"
                )
                z_scores.append(5.0)  # hard penalty

        # 3. Zone-crossing violations
        src_zone = str(flow.get("zone_src", ""))
        dst_zone = str(flow.get("zone_dst", ""))
        if src_zone and dst_zone and profile.allowed_zones:
            pair = (src_zone, dst_zone)
            if pair not in profile.allowed_zones:
                reasons.append(
                    f"ZONE_VIOLATION: {src_zone} → {dst_zone} "
                    f"not in profile for {role}"
                )
                z_scores.append(4.0)

        # 4. Protocol mismatch
        proto = str(flow.get("proto", ""))
        if proto and profile.protocol_dist:
            proto_frac = profile.protocol_dist.get(proto, 0.0)
            if proto_frac < 0.01:   # protocol seen in <1% of baseline flows
                reasons.append(
                    f"PROTO_MISMATCH: proto={proto} "
                    f"(baseline_frac={proto_frac:.3f})"
                )
                z_scores.append(3.0)

        # Convert z-scores to a 0-1 score via sigmoid-like mapping
        if not z_scores:
            return 0.0, []

        avg_z = sum(z_scores) / len(z_scores)
        # sigmoid: score = 1 / (1 + e^(-(z-threshold)))
        score = 1.0 / (1.0 + math.exp(-(avg_z - ANOMALY_Z_THRESHOLD)))
        return round(min(1.0, score), 4), reasons

    def enrich_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """Add device_anomaly_score and device_anomaly_reasons to a flow."""
        score, reasons = self.anomaly_score(flow)
        flow["device_anomaly_score"] = score
        flow["device_anomaly_reasons"] = "; ".join(reasons) if reasons else ""
        return flow

    def enrich_flows(
        self, flows: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Enrich all flows with device profiling scores."""
        return [self.enrich_flow(f) for f in flows]

    def enrich_windows(
        self,
        windows: List[Dict[str, Any]],
        flows: List[Dict[str, Any]],
        window_size_s: float = 5.0,
    ) -> List[Dict[str, Any]]:
        """
        Enrich time-window records with per-window device anomaly scores.

        For each window:
          - Finds all flows belonging to that window (by timestamp)
          - Computes individual flow anomaly scores
          - Aggregates: max_device_anomaly_score, n_anomalous_devices
        """
        for window in windows:
            w_start = float(window.get("window_start", 0))
            w_end = float(window.get("window_end", w_start + window_size_s))

            wflows = [
                f for f in flows
                if w_start <= float(f.get("ts_start", 0)) < w_end
            ]

            if not wflows:
                window["max_device_anomaly_score"] = 0.0
                window["n_anomalous_devices"] = 0
                window["device_anomaly_roles"] = ""
                continue

            scored = [self.anomaly_score(f) for f in wflows]
            scores = [s for s, _ in scored]
            anomalous_roles = [
                str(wflows[i].get("device_role_src", ""))
                for i, (s, reasons) in enumerate(scored)
                if s > 0.5
            ]

            window["max_device_anomaly_score"] = round(max(scores) if scores else 0.0, 4)
            window["n_anomalous_devices"] = len(set(anomalous_roles))
            window["device_anomaly_roles"] = "|".join(sorted(set(anomalous_roles)))

        return windows

    # ── Role Summary ─────────────────────────────────────────────────

    def summary(self) -> str:
        """Print a human-readable summary of all fitted profiles."""
        lines = []
        lines.append("╔══════════════════════════════════════════════════════════╗")
        lines.append("║         IoMT Device Profiler — Baseline Summary          ║")
        lines.append("╠══════════════════════════════════════════════════════════╣")
        for role, p in sorted(self.profiles.items()):
            lines.append(f"  ▸ {role:<34s}  {p.n_flows_fitted:>5d} flows")
            for feat in ["bytes_fwd", "pkt_count", "ble_telemetry_cnt",
                         "dicom_query_cnt", "hl7_msg_cnt"]:
                stat = p.feature_stats.get(feat)
                if stat and stat.n_samples > 0:
                    lines.append(
                        f"      {feat:<26s}: mean={stat.mean:>8.2f} "
                        f"std={stat.std:>8.2f}  p95={stat.p95:>8.2f}"
                    )
        lines.append("╚══════════════════════════════════════════════════════════╝")
        return "\n".join(lines)

    def get_role_profile(self, role: str) -> Optional[DeviceProfile]:
        """Return the profile for a specific device role, or None."""
        return self.profiles.get(role)

    def get_all_roles(self) -> List[str]:
        """Return sorted list of all profiled device roles."""
        return sorted(self.profiles.keys())

    # ── Persistence ──────────────────────────────────────────────────

    def save(self, path: str) -> None:
        """Serialize all profiles to a JSON file."""
        data = {role: p.to_dict() for role, p in self.profiles.items()}
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[DeviceProfiler] Saved {len(self.profiles)} profiles → {path}")

    def load(self, path: str) -> "DeviceProfiler":
        """Load profiles from a previously saved JSON file."""
        with open(path) as f:
            data = json.load(f)
        self.profiles = {
            role: DeviceProfile.from_dict(pdict)
            for role, pdict in data.items()
        }
        print(f"[DeviceProfiler] Loaded {len(self.profiles)} profiles ← {path}")
        return self


# ──────────────────────────────────────────────────────────────────────
# Static baseline profiles (no training data required)
# ──────────────────────────────────────────────────────────────────────

def build_static_baseline_profiles() -> DeviceProfiler:
    """
    Build hard-coded reasonable baseline profiles for common IoMT roles.
    Use this when no benign training data is available.

    Values are derived from IoMT literature and the simulator's own
    traffic generator defaults.
    """
    profiler = DeviceProfiler()

    static_defs = [
        # (role, bytes_fwd_mean, bytes_fwd_std, pkts_fwd_mean, pkts_fwd_std, ...extra)
        # extra = dict of {feat: (mean, std)}
        ("patient_monitor",     500,   150,  4,  2, {
            "ble_telemetry_cnt": (8, 2), "duration_ms": (120, 40),
        }),
        ("infusion_pump",       350,   100,  3,  1, {
            "ble_telemetry_cnt": (5, 2), "duration_ms": (80, 30),
        }),
        ("ventilator",          400,   120,  3,  1, {
            "ble_telemetry_cnt": (6, 2), "duration_ms": (100, 30),
        }),
        ("ct_scanner",          80000, 20000, 60, 15, {
            "dicom_query_cnt": (4, 2), "dicom_move_cnt": (2, 1),
            "dicom_bytes": (75000, 18000), "bytes_fwd": (80000, 20000),
        }),
        ("mri_scanner",         90000, 25000, 70, 18, {
            "dicom_query_cnt": (5, 2), "dicom_move_cnt": (3, 1),
            "dicom_bytes": (90000, 22000), "bytes_fwd": (90000, 25000),
        }),
        ("pacs_server",         120000, 30000, 90, 25, {
            "dicom_query_cnt": (10, 4), "dicom_move_cnt": (5, 2),
            "dicom_bytes": (100000, 25000),
        }),
        ("hl7_engine",          800,  200, 6, 2, {
            "hl7_msg_cnt": (5, 2), "hl7_error_cnt": (0.1, 0.2),
        }),
        ("fhir_server",         2000, 500, 8, 3, {
            "fhir_read_cnt": (3, 1),
        }),
        ("ehr_frontend",        3000, 800, 12, 4, {
            "auth_attempts": (1, 0.3), "auth_failures": (0.05, 0.1),
        }),
        ("ad_server",           1200, 300, 8, 2, {
            "auth_attempts": (2, 0.5), "auth_failures": (0.1, 0.2),
        }),
        ("ble_gateway",         200,  60,  2, 1, {
            "ble_telemetry_cnt": (12, 3),
        }),
        ("telemetry_aggregator", 1000, 250, 8, 2, {
            "ble_telemetry_cnt": (20, 5),
        }),
        ("backup_server",       5000, 1500, 15, 5, {}),
        ("file_share",          2000, 600, 10, 3, {}),
        ("wearable",            150,  50,  2, 1, {
            "ble_telemetry_cnt": (4, 1),
        }),
    ]

    for entry in static_defs:
        role = entry[0]
        p = DeviceProfile(
            role=role,
            n_flows_fitted=1000,  # synthetic baseline
            allowed_zones=ROLE_ALLOWED_ZONES.get(role, []),
            forbidden_features=ROLE_FORBIDDEN.get(role, []),
        )

        # bytes_fwd
        p.feature_stats["bytes_fwd"] = FeatureStat(
            mean=entry[1], std=entry[2],
            p5=max(0, entry[1] - 2*entry[2]),
            p95=entry[1] + 2*entry[2],
            max_observed=entry[1] + 4*entry[2],
            n_samples=1000,
        )
        # pkts_fwd
        p.feature_stats["pkts_fwd"] = FeatureStat(
            mean=entry[3], std=entry[4],
            p5=max(0, entry[3] - 2*entry[4]),
            p95=entry[3] + 2*entry[4],
            max_observed=entry[3] + 4*entry[4],
            n_samples=1000,
        )
        # extra features
        for feat, (fm, fs) in entry[5].items():
            p.feature_stats[feat] = FeatureStat(
                mean=fm, std=fs,
                p5=max(0, fm - 2*fs),
                p95=fm + 2*fs,
                max_observed=fm + 4*fs,
                n_samples=1000,
            )
        # fill remaining with benign zeros
        for feat in NUMERIC_FEATURES:
            if feat not in p.feature_stats:
                p.feature_stats[feat] = FeatureStat(
                    mean=0.0, std=0.1, p5=0.0, p95=0.5,
                    max_observed=1.0, n_samples=1000,
                )

        profiler.profiles[role] = p

    print(f"[DeviceProfiler] Built {len(profiler.profiles)} static baseline profiles.")
    return profiler


# ──────────────────────────────────────────────────────────────────────
# CLI demo
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    print("\n" + "="*65)
    print("  IoMT Device Profiler — Quick Demo")
    print("="*65)

    # Build static profiles
    profiler = build_static_baseline_profiles()
    print(profiler.summary())

    # Demo: score a normal infusion pump flow vs an anomalous one
    normal_flow = {
        "device_role_src": "infusion_pump",
        "zone_src": "zone_e",
        "zone_dst": "zone_e",
        "bytes_fwd": 320, "bytes_rev": 120,
        "pkts_fwd": 3, "pkts_rev": 2,
        "ble_telemetry_cnt": 5, "duration_ms": 90,
        "dst_port": 8080, "proto": "TCP", "label": "benign",
    }
    attack_flow = {
        "device_role_src": "infusion_pump",
        "zone_src": "zone_e",
        "zone_dst": "zone_b",           # zone violation
        "bytes_fwd": 98000,             # 280x normal
        "bytes_rev": 55000,
        "pkts_fwd": 800,
        "dicom_query_cnt": 12,          # forbidden feature
        "auth_failures": 8,             # forbidden feature
        "proto": "SMB",                 # unexpected protocol
        "label": "attack",
    }

    s_n, r_n = profiler.anomaly_score(normal_flow)
    s_a, r_a = profiler.anomaly_score(attack_flow)

    print(f"\n  Normal  infusion_pump flow  → score={s_n:.3f}  reasons={r_n or 'none'}")
    print(f"  ATTACK  infusion_pump flow  → score={s_a:.3f}")
    print("  Attack reasons:")
    for r in r_a:
        print(f"    ⚠  {r}")

    # Save static profiles
    profiler.save("/tmp/iomt_device_profiles.json")
    print("\n  Profiles saved to /tmp/iomt_device_profiles.json")
