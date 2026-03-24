"""
IoMT Medical NIDS Simulator — Dataset Builder
Generates raw time-series datasets with:
- All 24 attack types in a single timeline
- Per-flow data (no feature extraction / windowing)
- 80/20 chronological train/test split
- Every attack type appears in both train and test
"""

import csv
import json
import os
import time
import random
from typing import List, Dict, Optional, Callable

from config import SimConfig, ATTACK_SCENARIOS, AttackScenario
from network_model import HospitalNetwork
from traffic_generator import BenignTrafficGenerator
from attack_injector import AttackStateMachine
from labeling_engine import LabelingEngine


# Raw flow columns — no feature extraction
RAW_COLUMNS = [
    "ts_start", "ts_end", "duration",
    "src_ip", "dst_ip", "src_port", "dst_port",
    "proto", "bytes_in", "bytes_out", "packets_in", "packets_out",
    "tcp_flags", "zone_src", "zone_dst",
    "device_role_src", "device_role_dst",
    "label",          # "benign" or "attack"
    "attack_type",    # "" for benign, e.g. "external_recon" for attack
    "scenario_id",    # "" for benign, e.g. "A01" for attack
]


class DatasetBuilder:
    """
    Build a complete raw time-series dataset with all attack types.

    Strategy:
    - Total duration divided into 48 slots (2 per scenario)
    - Each scenario appears TWICE: once in train region (0-80%), once in test (80-100%)
    - Benign traffic runs continuously throughout
    - Output: train.csv + test.csv (chronological split, no shuffle)
    """

    def __init__(
        self,
        total_duration: int = 86400,        # 24 hours simulation
        attack_duration_each: int = 300,     # 5 min per attack slot
        intensity: float = 0.75,
        seed: int = 42,
        output_dir: str = "./dataset",
        scenarios: Optional[Dict[str, AttackScenario]] = None,
        custom_devices: Optional[list] = None,
        train_ratio: float = 0.8,
        window_size_s: int = 5,
    ):
        self.total_duration = total_duration
        self.attack_duration = attack_duration_each
        self.intensity = intensity
        self.seed = seed
        self.output_dir = output_dir
        self.scenarios = scenarios or ATTACK_SCENARIOS
        self.custom_devices = custom_devices
        self.train_ratio = train_ratio
        self.window_size_s = window_size_s

    def _plan_attack_slots(self) -> List[dict]:
        """
        Plan attack placement so every scenario appears in BOTH train and test.

        Returns list of: {scenario_id, attack_start, attack_end, region}
        """
        scenario_ids = sorted(self.scenarios.keys())
        n = len(scenario_ids)

        # Train region: 0 → train_split_t
        # Test region: train_split_t → total_duration
        train_split_t = int(self.total_duration * self.train_ratio)
        train_available = train_split_t
        test_available = self.total_duration - train_split_t

        # Distribute scenarios evenly in each region
        # Gap between attacks to have benign-only periods
        train_gap = max(self.attack_duration, (train_available - n * self.attack_duration) // max(1, n + 1))
        test_gap = max(self.attack_duration // 2, (test_available - n * self.attack_duration) // max(1, n + 1))

        slots = []
        rng = random.Random(self.seed + 999)

        # Shuffle scenario order for variety (but deterministic)
        train_order = list(scenario_ids)
        test_order = list(scenario_ids)
        rng.shuffle(train_order)
        rng.shuffle(test_order)

        # Place in train region
        t = train_gap
        for sid in train_order:
            if t + self.attack_duration > train_split_t:
                break
            slots.append({
                "scenario_id": sid,
                "attack_start": t,
                "attack_end": t + self.attack_duration,
                "region": "train",
            })
            t += self.attack_duration + train_gap

        # Place in test region
        t = train_split_t + test_gap
        for sid in test_order:
            if t + self.attack_duration > self.total_duration:
                break
            slots.append({
                "scenario_id": sid,
                "attack_start": t,
                "attack_end": t + self.attack_duration,
                "region": "test",
            })
            t += self.attack_duration + test_gap

        return sorted(slots, key=lambda s: s["attack_start"])

    def generate(self, progress_callback: Optional[Callable] = None) -> dict:
        """
        Generate the full dataset.

        Returns: {train_path, test_path, stats}
        """
        os.makedirs(self.output_dir, exist_ok=True)

        # Setup network
        config_base = SimConfig(
            seed=self.seed,
            duration_s=self.total_duration,
            window_size_s=self.window_size_s,
            intensity=self.intensity,
            output_dir=self.output_dir,
        )
        network = HospitalNetwork(config_base.environment_profile, self.seed)
        traffic_gen = BenignTrafficGenerator(network, config_base)
        labeling = LabelingEngine(config_base)

        # Plan attack slots
        slots = self._plan_attack_slots()
        train_split_t = int(self.total_duration * self.train_ratio)

        # Build attack machines for each slot
        attack_schedule = []
        for slot in slots:
            scenario = self.scenarios.get(slot["scenario_id"])
            if not scenario:
                continue

            slot_config = SimConfig(
                scenario_id=slot["scenario_id"],
                seed=self.seed + hash(slot["scenario_id"]) % 10000,
                duration_s=self.total_duration,
                attack_start_s=slot["attack_start"],
                attack_duration_s=self.attack_duration,
                intensity=self.intensity,
                window_size_s=self.window_size_s,
                output_dir=self.output_dir,
            )
            sm = AttackStateMachine(scenario, network, slot_config)
            attack_schedule.append({
                "sm": sm,
                "start": slot["attack_start"],
                "end": slot["attack_end"],
                "scenario_id": slot["scenario_id"],
                "label": scenario.label,
            })

        # Generate flows time-step by time-step
        all_flows = []
        step_size = self.window_size_s
        total_steps = self.total_duration // step_size
        start_time = time.time()

        print(f"\n{'='*60}")
        print(f"  IoMT NIDS — Raw Time-Series Dataset Builder")
        print(f"{'='*60}")
        print(f"  Duration:     {self.total_duration}s ({self.total_duration/3600:.1f} hours)")
        print(f"  Scenarios:    {len(self.scenarios)}")
        print(f"  Attack slots: {len(attack_schedule)}")
        print(f"  Train/Test:   {self.train_ratio*100:.0f}% / {(1-self.train_ratio)*100:.0f}%")
        print(f"  Split at:     t={train_split_t}s")
        print(f"  Output:       {self.output_dir}")
        print(f"{'='*60}\n")

        for step in range(total_steps):
            t_start = step * step_size
            t_end = t_start + step_size

            # 1) Benign traffic
            benign = traffic_gen.generate_flows(t_start, t_end, start_hour=0.0)

            # 2) Attack traffic from all active attack machines
            attack = []
            for sched in attack_schedule:
                if t_start >= sched["start"] and t_end <= sched["end"] + step_size:
                    flows = sched["sm"].generate_flows(t_start, t_end)
                    for f in flows:
                        f["attack_type"] = sched["label"]
                        f["scenario_id"] = sched["scenario_id"]
                    attack.extend(flows)

            # 3) Combine and label
            chunk = benign + attack
            chunk = labeling.label_flows(chunk)

            # Ensure benign flows have explicit empty attack fields
            for f in chunk:
                if f.get("label") == "benign":
                    f.setdefault("attack_type", "")
                    f.setdefault("scenario_id", "")
                elif "attack_type" not in f:
                    f["attack_type"] = f.get("label", "")
                    f.setdefault("scenario_id", "")

            all_flows.extend(chunk)

            # Progress
            pct = (step + 1) / total_steps
            if progress_callback:
                progress_callback(pct, step + 1, total_steps, len(all_flows))
            elif step % max(1, total_steps // 20) == 0:
                benign_n = len(benign)
                attack_n = len(attack)
                active = [s["scenario_id"] for s in attack_schedule
                          if s["start"] <= t_start < s["end"]]
                active_str = ",".join(active) if active else "none"
                print(f"  [{pct*100:5.1f}%] t={t_start:6.0f}s | "
                      f"flows: {len(chunk):4d} (B={benign_n}, A={attack_n}) "
                      f"active: {active_str}")

        # Sort all flows by timestamp
        all_flows.sort(key=lambda f: f.get("ts_start", 0))

        # Split chronologically
        train_flows = [f for f in all_flows if f.get("ts_start", 0) < train_split_t]
        test_flows = [f for f in all_flows if f.get("ts_start", 0) >= train_split_t]

        # Write CSVs
        train_path = os.path.join(self.output_dir, "train.csv")
        test_path = os.path.join(self.output_dir, "test.csv")
        full_path = os.path.join(self.output_dir, "full_dataset.csv")

        self._write_csv(train_flows, train_path)
        self._write_csv(test_flows, test_path)
        self._write_csv(all_flows, full_path)

        # Compute stats
        stats = self._compute_stats(all_flows, train_flows, test_flows, slots)
        stats["elapsed_s"] = round(time.time() - start_time, 1)

        # Write dataset info
        info_path = os.path.join(self.output_dir, "dataset_info.json")
        with open(info_path, "w") as f:
            json.dump(stats, f, indent=2, default=str)

        # Print summary
        self._print_summary(stats)

        return {
            "train_path": train_path,
            "test_path": test_path,
            "full_path": full_path,
            "stats": stats,
        }

    def _write_csv(self, flows: List[dict], path: str):
        """Write raw time-series CSV."""
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=RAW_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for flow in flows:
                row = {col: flow.get(col, "") for col in RAW_COLUMNS}
                writer.writerow(row)
        print(f"  ✓ {len(flows):,} flows → {path}")

    def _compute_stats(self, all_flows, train_flows, test_flows, slots):
        """Compute dataset statistics."""
        def _attack_types(flows):
            return sorted(set(f.get("attack_type", "") for f in flows
                            if f.get("label") != "benign" and f.get("attack_type")))

        def _label_counts(flows):
            counts = {"benign": 0}
            for f in flows:
                label = f.get("label", "benign")
                if label == "benign":
                    counts["benign"] += 1
                else:
                    at = f.get("attack_type", label)
                    counts[at] = counts.get(at, 0) + 1
            return counts

        train_types = _attack_types(train_flows)
        test_types = _attack_types(test_flows)

        return {
            "total_flows": len(all_flows),
            "train_flows": len(train_flows),
            "test_flows": len(test_flows),
            "train_ratio": round(len(train_flows) / max(1, len(all_flows)), 4),
            "test_ratio": round(len(test_flows) / max(1, len(all_flows)), 4),
            "train_attack_types": train_types,
            "test_attack_types": test_types,
            "all_attack_types_in_train": len(train_types),
            "all_attack_types_in_test": len(test_types),
            "coverage_complete": set(train_types) == set(test_types),
            "train_label_counts": _label_counts(train_flows),
            "test_label_counts": _label_counts(test_flows),
            "attack_slots": [{k: v for k, v in s.items() if k != "sm"}
                            for s in slots] if isinstance(slots[0], dict) and "sm" not in slots[0] else
                            [{"scenario_id": s["scenario_id"], "start": s.get("attack_start", 0),
                              "end": s.get("attack_end", 0), "region": s.get("region", "")}
                             for s in slots],
            "columns": RAW_COLUMNS,
            "total_duration_s": self.total_duration,
            "seed": self.seed,
        }

    def _print_summary(self, stats):
        """Print dataset summary."""
        print(f"\n{'='*60}")
        print(f"  Dataset Generation Complete ({stats['elapsed_s']}s)")
        print(f"{'='*60}")
        print(f"  Total flows:   {stats['total_flows']:,}")
        print(f"  Train flows:   {stats['train_flows']:,} ({stats['train_ratio']*100:.1f}%)")
        print(f"  Test flows:    {stats['test_flows']:,} ({stats['test_ratio']*100:.1f}%)")
        print(f"  Attack types:  {stats['all_attack_types_in_train']} in train, "
              f"{stats['all_attack_types_in_test']} in test")
        print(f"  Coverage:      {'✓ Complete' if stats['coverage_complete'] else '⚠ Partial'}")

        print(f"\n  Train label distribution:")
        for label, count in sorted(stats["train_label_counts"].items()):
            print(f"    {label:30s}: {count:,}")

        print(f"\n  Test label distribution:")
        for label, count in sorted(stats["test_label_counts"].items()):
            print(f"    {label:30s}: {count:,}")

        print(f"{'='*60}\n")
