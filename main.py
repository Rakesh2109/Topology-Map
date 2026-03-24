"""
IoMT Medical NIDS Simulator — Main Entry Point (v2)
CLI and GUI launcher with:
- Input validation and auto-clamping
- Multi-scenario concurrent support
- Batch mode for generating diverse datasets
"""

import argparse
import sys
import time
import os
from config import SimConfig, ATTACK_SCENARIOS
from network_model import HospitalNetwork
from traffic_generator import BenignTrafficGenerator
from attack_injector import AttackStateMachine
from labeling_engine import LabelingEngine
from time_window import TimeWindowAggregator
from export import Exporter


def validate_config(config: SimConfig) -> SimConfig:
    """Validate and auto-clamp configuration parameters."""
    warnings = []

    # Clamp attack window to fit within duration
    if config.attack_start_s >= config.duration_s:
        old = config.attack_start_s
        config.attack_start_s = max(0, config.duration_s - config.attack_duration_s - 10)
        warnings.append(f"  ⚠ attack_start_s ({old}) >= duration ({config.duration_s}), "
                       f"clamped to {config.attack_start_s}")

    if config.attack_start_s + config.attack_duration_s > config.duration_s:
        old = config.attack_duration_s
        config.attack_duration_s = config.duration_s - config.attack_start_s
        warnings.append(f"  ⚠ attack window exceeded duration, "
                       f"attack_duration clamped from {old} to {config.attack_duration_s}")

    if config.attack_duration_s < config.window_size_s:
        old = config.attack_duration_s
        config.attack_duration_s = config.window_size_s
        warnings.append(f"  ⚠ attack_duration ({old}) < window_size ({config.window_size_s}), "
                       f"set to {config.attack_duration_s}")

    # Validate scenario
    if config.scenario_id not in ATTACK_SCENARIOS:
        warnings.append(f"  ⚠ Unknown scenario {config.scenario_id}, using A01")
        config.scenario_id = "A01"

    # Clamp intensity
    config.intensity = max(0.1, min(1.0, config.intensity))

    # Ensure duration is a multiple of window size
    if config.duration_s % config.window_size_s != 0:
        config.duration_s = (config.duration_s // config.window_size_s) * config.window_size_s
        warnings.append(f"  ⚠ duration adjusted to {config.duration_s} "
                       f"(multiple of window_size={config.window_size_s})")

    if warnings:
        print("\n".join(warnings))

    return config


class Simulator:
    """Main simulation engine coordinating all modules."""

    def __init__(self, config: SimConfig):
        self.config = validate_config(config)
        self.network = HospitalNetwork(config.environment_profile, config.seed)
        self.traffic_gen = BenignTrafficGenerator(self.network, config)
        self.labeling = LabelingEngine(config)
        self.windower = TimeWindowAggregator(config)
        self.exporter = Exporter(config)

        # Support multiple concurrent attack scenarios
        self.attack_machines: list = []
        if isinstance(config.scenario_id, str) and "," in config.scenario_id:
            # Multi-scenario mode: "A14,A17,A20"
            for sid in config.scenario_id.split(","):
                sid = sid.strip()
                scenario = ATTACK_SCENARIOS.get(sid)
                if scenario:
                    self.attack_machines.append(
                        AttackStateMachine(scenario, self.network, config)
                    )
        else:
            scenario = ATTACK_SCENARIOS.get(config.scenario_id)
            if scenario:
                self.attack_machines.append(
                    AttackStateMachine(scenario, self.network, config)
                )

        self.all_flows = []
        self.all_events = []
        self.progress_callback = None

    def run(self, progress_callback=None):
        """Run the full simulation."""
        self.progress_callback = progress_callback
        self.all_flows = []
        self.all_events = []

        duration = self.config.duration_s
        window = self.config.window_size_s
        total_steps = duration // window

        scenario_ids = ", ".join(sm.scenario.scenario_id for sm in self.attack_machines)
        scenario_labels = ", ".join(sm.scenario.label for sm in self.attack_machines)

        print(f"\n{'='*60}")
        print(f"  IoMT Medical NIDS Simulator v2.0")
        print(f"{'='*60}")
        print(f"  Scenario(s): {scenario_ids} ({scenario_labels})")
        print(f"  Duration:    {duration}s")
        print(f"  Attack:      {self.config.attack_start_s}s → "
              f"{self.config.attack_start_s + self.config.attack_duration_s}s")
        print(f"  Intensity:   {self.config.intensity}")
        print(f"  Stealth:     {self.config.stealth_mode}")
        print(f"  Seed:        {self.config.seed}")
        print(f"  Output:      {self.config.output_dir}")
        print(f"{'='*60}\n")

        start_time = time.time()

        for step in range(total_steps):
            t_start = step * window
            t_end = t_start + window

            # Benign traffic
            benign = self.traffic_gen.generate_flows(t_start, t_end, start_hour=8.0)

            # Attack traffic from ALL active attack machines
            attack = []
            for sm in self.attack_machines:
                attack.extend(sm.generate_flows(t_start, t_end))

            # Combine and label
            chunk_flows = benign + attack
            chunk_flows = self.labeling.label_flows(chunk_flows)

            # Extract events
            chunk_events = self.labeling.get_events(chunk_flows)

            self.all_flows.extend(chunk_flows)
            self.all_events.extend(chunk_events)

            # Progress
            pct = (step + 1) / total_steps
            if progress_callback:
                progress_callback(pct, step + 1, total_steps, len(self.all_flows))
            elif step % max(1, total_steps // 20) == 0:
                benign_n = sum(1 for f in chunk_flows if f.get("label") == "benign")
                attack_n = len(chunk_flows) - benign_n
                print(f"  [{pct*100:5.1f}%] t={t_start:6.0f}-{t_end:6.0f}s | "
                      f"flows: {len(chunk_flows):4d} (benign={benign_n}, attack={attack_n})")

        elapsed = time.time() - start_time

        # Aggregate into windows
        print(f"\n  Aggregating into {self.config.window_size_s}s windows...")
        windows = self.windower.aggregate(self.all_flows, self.labeling)

        # Get asset info
        assets = self.network.get_assets_csv_rows()

        # Export
        print(f"\n  Exporting results...")
        self.exporter.export_all(self.all_flows, windows, self.all_events, assets)

        # Summary
        total_flows = len(self.all_flows)
        benign_total = sum(1 for f in self.all_flows if f.get("label") == "benign")
        attack_total = total_flows - benign_total
        benign_windows = sum(1 for w in windows if w.get("label") == "benign")
        attack_windows = len(windows) - benign_windows

        print(f"\n{'='*60}")
        print(f"  Simulation Complete in {elapsed:.1f}s")
        print(f"{'='*60}")
        print(f"  Total flows:   {total_flows:,}")
        print(f"  Benign flows:  {benign_total:,}")
        print(f"  Attack flows:  {attack_total:,}")
        print(f"  Total windows: {len(windows):,}")
        print(f"  Benign wins:   {benign_windows:,}")
        print(f"  Attack wins:   {attack_windows:,}")
        print(f"  Total events:  {len(self.all_events):,}")
        print(f"{'='*60}\n")

        return {
            "total_flows": total_flows,
            "benign_flows": benign_total,
            "attack_flows": attack_total,
            "total_windows": len(windows),
            "benign_windows": benign_windows,
            "attack_windows": attack_windows,
            "total_events": len(self.all_events),
            "elapsed_s": elapsed,
            "flows": self.all_flows,
            "windows": windows,
            "events": self.all_events,
        }


def run_batch(args):
    """
    Batch mode: run multiple scenarios and concatenate outputs
    into a single diverse dataset.
    """
    scenarios = args.batch_scenarios.split(",") if args.batch_scenarios else list(ATTACK_SCENARIOS.keys())
    all_flows = []
    all_events = []
    all_windows = []

    print(f"\n{'='*60}")
    print(f"  IoMT NIDS Simulator — BATCH MODE")
    print(f"  Scenarios: {len(scenarios)}")
    print(f"  Duration each: {args.duration}s")
    print(f"{'='*60}\n")

    for i, sid in enumerate(scenarios):
        sid = sid.strip()
        if sid not in ATTACK_SCENARIOS:
            print(f"  ⚠ Skipping unknown scenario: {sid}")
            continue

        print(f"\n  ── [{i+1}/{len(scenarios)}] Running {sid}: "
              f"{ATTACK_SCENARIOS[sid].label} ──")

        config = SimConfig(
            scenario_id=sid,
            duration_s=args.duration,
            attack_start_s=args.attack_start,
            attack_duration_s=args.attack_duration,
            intensity=args.intensity,
            stealth_mode=args.stealth,
            seed=args.seed + i,  # Different seed per scenario
            window_size_s=args.window_size,
            output_dir=os.path.join(args.output, sid),
        )

        sim = Simulator(config)
        result = sim.run()

        # Offset timestamps for concatenation
        time_offset = i * args.duration
        for f in result["flows"]:
            f["ts_start"] = round(f.get("ts_start", 0) + time_offset, 6)
            f["ts_end"] = round(f.get("ts_end", 0) + time_offset, 6)
        for w in result["windows"]:
            w["window_start"] = round(w.get("window_start", 0) + time_offset, 6)
            w["window_end"] = round(w.get("window_end", 0) + time_offset, 6)
        for e in result["events"]:
            e["timestamp"] = round(e.get("timestamp", 0) + time_offset, 6)

        all_flows.extend(result["flows"])
        all_events.extend(result["events"])
        all_windows.extend(result["windows"])

    # Export combined dataset
    print(f"\n  Exporting combined dataset ({len(all_flows):,} flows, "
          f"{len(all_windows):,} windows, {len(all_events):,} events)...")

    combined_config = SimConfig(
        scenario_id="BATCH",
        duration_s=args.duration * len(scenarios),
        output_dir=args.output,
        window_size_s=args.window_size,
    )
    exporter = Exporter(combined_config)
    network = HospitalNetwork("medium_hospital_v1", args.seed)
    assets = network.get_assets_csv_rows()
    exporter.export_all(all_flows, all_windows, all_events, assets)

    print(f"\n{'='*60}")
    print(f"  Batch Complete: {len(scenarios)} scenarios")
    print(f"  Combined: {len(all_flows):,} flows, "
          f"{len(all_windows):,} windows, {len(all_events):,} events")
    print(f"  Output: {args.output}")
    print(f"{'='*60}\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="IoMT Medical NIDS Dataset Simulator v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Web dashboard (recommended)
  python main.py --web

  # Generate raw time-series dataset (all 24 attacks, train/test split)
  python main.py --generate-dataset --duration 86400 --output ./dataset

  # Load custom scenario from JSON
  python main.py --load-scenario ./examples/scenarios/A14_dicom_exfiltration.json

  # Export built-in scenarios as JSON examples
  python main.py --export-examples

  # Single scenario (CLI)
  python main.py --scenario A14 --duration 3600 --output ./output

  # Batch mode (all 24 scenarios)
  python main.py --batch --duration 600 --output ./batch_output

  # Tkinter GUI mode
  python main.py --gui
        """
    )
    parser.add_argument("--web", action="store_true", help="Launch web dashboard (recommended)")
    parser.add_argument("--port", type=int, default=8080, help="Web dashboard port (default: 8080)")
    parser.add_argument("--gui", action="store_true", help="Launch Tkinter GUI mode")
    parser.add_argument("--generate-dataset", action="store_true",
                        help="Generate raw time-series dataset with all attacks + train/test split")
    parser.add_argument("--train-ratio", type=float, default=0.8,
                        help="Train/test split ratio (default: 0.8)")
    parser.add_argument("--load-scenario", type=str, default=None,
                        help="Load custom scenario from JSON file")
    parser.add_argument("--load-devices", type=str, default=None,
                        help="Load custom device set from JSON file")
    parser.add_argument("--export-examples", action="store_true",
                        help="Export built-in 24 scenarios and devices as JSON examples")
    parser.add_argument("--batch", action="store_true",
                        help="Batch mode: run multiple scenarios")
    parser.add_argument("--batch-scenarios", type=str, default=None,
                        help="Comma-separated scenario IDs for batch mode (default: all)")
    parser.add_argument("--scenario", type=str, default="A14",
                        help="Attack scenario ID(s), comma-separated for concurrent (A01-A24)")
    parser.add_argument("--duration", type=int, default=3600,
                        help="Simulation duration in seconds")
    parser.add_argument("--attack-start", type=int, default=420,
                        help="Attack start time in seconds")
    parser.add_argument("--attack-duration", type=int, default=180,
                        help="Attack duration in seconds")
    parser.add_argument("--intensity", type=float, default=0.75,
                        help="Attack intensity [0.1-1.0]")
    parser.add_argument("--stealth", action="store_true",
                        help="Enable stealth mode (low-and-slow)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducibility")
    parser.add_argument("--window-size", type=int, default=5,
                        help="Time window size in seconds (1, 5, or 10)")
    parser.add_argument("--output", type=str, default="./output",
                        help="Output directory")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.web:
        from gui_web import launch_web
        launch_web(port=args.port)
        return

    if args.export_examples:
        from scenario_builder import export_builtin_examples
        export_builtin_examples(os.path.join(args.output, "examples"))
        return

    if args.generate_dataset:
        from dataset_builder import DatasetBuilder
        # Load custom scenarios/devices if specified
        scenarios = None
        if args.load_scenario:
            from scenario_builder import load_scenarios
            scenarios = load_scenarios(args.load_scenario)

        builder = DatasetBuilder(
            total_duration=args.duration,
            attack_duration_each=args.attack_duration,
            intensity=args.intensity,
            seed=args.seed,
            output_dir=args.output,
            scenarios=scenarios,
            train_ratio=args.train_ratio,
            window_size_s=args.window_size,
        )
        builder.generate()
        return

    if args.gui:
        try:
            from gui import launch_gui
            launch_gui()
        except ImportError as e:
            print(f"Error: GUI dependencies not available: {e}")
            print("Install tkinter or run in CLI mode.")
            sys.exit(1)
        return

    if args.batch:
        run_batch(args)
        return

    # Load custom scenario if specified
    if args.load_scenario:
        from scenario_builder import load_scenarios
        custom = load_scenarios(args.load_scenario)
        # Register custom scenarios
        for sid, s in custom.items():
            ATTACK_SCENARIOS[sid] = s
        args.scenario = list(custom.keys())[0]
        print(f"  ✓ Loaded custom scenario: {args.scenario}")

    # CLI mode (single or multi-scenario)
    config = SimConfig(
        scenario_id=args.scenario,
        duration_s=args.duration,
        attack_start_s=args.attack_start,
        attack_duration_s=args.attack_duration,
        intensity=args.intensity,
        stealth_mode=args.stealth,
        seed=args.seed,
        window_size_s=args.window_size,
        output_dir=args.output,
    )

    sim = Simulator(config)
    sim.run()


if __name__ == "__main__":
    main()
