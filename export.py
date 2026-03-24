"""
IoMT Medical NIDS Simulator — Export Layer
Exports simulation results to CSV, Parquet, and JSON formats.
"""

import csv
import json
import os
from typing import List, Dict
from config import (
    SimConfig, BASE_FLOW_FIELDS, MEDICAL_METADATA_FIELDS,
    LABEL_FIELDS, WINDOW_FEATURE_FIELDS, WINDOW_LABEL_FIELDS
)


class Exporter:
    """Exports simulation data to multiple file formats."""

    def __init__(self, config: SimConfig):
        self.config = config
        self.output_dir = config.output_dir

    def ensure_output_dir(self):
        os.makedirs(self.output_dir, exist_ok=True)

    def export_all(self, flows: List[dict], windows: List[dict],
                   events: List[dict], assets: List[dict]):
        """Export all data files."""
        self.ensure_output_dir()
        self.export_flows(flows)
        self.export_windows(windows)
        self.export_events(events)
        self.export_assets(assets)
        self.export_manifest()

    def export_flows(self, flows: List[dict]):
        """Export flows.csv with all base + medical + label fields."""
        all_fields = BASE_FLOW_FIELDS + MEDICAL_METADATA_FIELDS + LABEL_FIELDS
        path = os.path.join(self.output_dir, "flows.csv")

        sorted_flows = sorted(flows, key=lambda f: f.get("ts_start", 0))

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=all_fields, extrasaction="ignore")
            writer.writeheader()
            for flow in sorted_flows:
                row = {field: flow.get(field, "") for field in all_fields}
                writer.writerow(row)

        print(f"  ✓ Exported {len(sorted_flows)} flows → {path}")

        # Try Parquet export
        self._try_parquet_export(sorted_flows, all_fields)

    def _try_parquet_export(self, flows: List[dict], fields: List[str]):
        """Attempt Parquet export if pandas/pyarrow are available."""
        try:
            import pandas as pd
            path = os.path.join(self.output_dir, "flows.parquet")
            df = pd.DataFrame(flows)
            # Ensure all fields exist
            for field in fields:
                if field not in df.columns:
                    df[field] = ""
            df = df[fields]
            df.to_parquet(path, index=False)
            print(f"  ✓ Exported flows → {path} (Parquet)")
        except ImportError:
            print("  ℹ Parquet export skipped (install pandas + pyarrow: pip install pandas pyarrow)")
        except Exception as e:
            print(f"  ⚠ Parquet export failed: {e}")

    def export_windows(self, windows: List[dict]):
        """Export windows_5s.csv with aggregate features and labels."""
        all_fields = WINDOW_FEATURE_FIELDS + WINDOW_LABEL_FIELDS
        path = os.path.join(self.output_dir, f"windows_{self.config.window_size_s}s.csv")

        sorted_windows = sorted(windows, key=lambda w: w.get("window_start", 0))

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=all_fields, extrasaction="ignore")
            writer.writeheader()
            for window in sorted_windows:
                row = {field: window.get(field, "") for field in all_fields}
                writer.writerow(row)

        print(f"  ✓ Exported {len(sorted_windows)} windows → {path}")

    def export_events(self, events: List[dict]):
        """Export events.csv with high-level protocol events."""
        fields = [
            "timestamp", "event_type", "src_ip", "dst_ip", "protocol",
            "details", "label", "attack_id", "scenario_id"
        ]
        path = os.path.join(self.output_dir, "events.csv")

        sorted_events = sorted(events, key=lambda e: e.get("timestamp", 0))

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for event in sorted_events:
                row = {field: event.get(field, "") for field in fields}
                writer.writerow(row)

        print(f"  ✓ Exported {len(sorted_events)} events → {path}")

    def export_assets(self, assets: List[dict]):
        """Export assets.csv with device inventory."""
        fields = [
            "name", "zone", "ip", "device_role", "protocols",
            "criticality", "internet_exposed"
        ]
        path = os.path.join(self.output_dir, "assets.csv")

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for asset in assets:
                row = {field: asset.get(field, "") for field in fields}
                writer.writerow(row)

        print(f"  ✓ Exported {len(assets)} assets → {path}")

    def export_manifest(self):
        """Export scenario_manifest.json for reproducibility."""
        path = os.path.join(self.output_dir, "scenario_manifest.json")
        manifest = self.config.to_dict()
        manifest["generator_version"] = "2.0.0"
        manifest["export_files"] = [
            "flows.csv",
            f"windows_{self.config.window_size_s}s.csv",
            "events.csv",
            "assets.csv",
            "scenario_manifest.json",
        ]

        with open(path, "w") as f:
            json.dump(manifest, f, indent=2, default=str)

        print(f"  ✓ Exported manifest → {path}")
