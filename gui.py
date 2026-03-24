"""
IoMT Medical NIDS Simulator — GUI
Tkinter-based GUI with scenario editor, parameter controls, live plots,
and export management.
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import threading
import os
import sys

from config import SimConfig, ATTACK_SCENARIOS, MEDIUM_HOSPITAL_ASSETS, Zone, DeviceRole

# Try to import matplotlib for live plots
try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


# ──────────────────────────────────────────────────────────────────────
# Color palette
# ──────────────────────────────────────────────────────────────────────
BG_DARK = "#1a1b2e"
BG_PANEL = "#252640"
BG_INPUT = "#2d2e4a"
FG_TEXT = "#e0e0f0"
FG_DIM = "#8888aa"
ACCENT = "#6c63ff"
ACCENT_HOVER = "#857dff"
SUCCESS = "#4caf50"
DANGER = "#ff5252"
WARNING = "#ffab40"
CYAN = "#26c6da"


class SimulatorGUI:
    """Full-featured simulator GUI with dark theme."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("IoMT Medical NIDS Simulator")
        self.root.geometry("1280x820")
        self.root.minsize(1000, 700)
        self.root.configure(bg=BG_DARK)

        self.sim_thread = None
        self.is_running = False

        # Style
        self._setup_style()

        # Build UI
        self._build_ui()

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=BG_DARK, foreground=FG_TEXT,
                         fieldbackground=BG_INPUT, font=("Helvetica", 10))
        style.configure("TLabel", background=BG_DARK, foreground=FG_TEXT,
                         font=("Helvetica", 10))
        style.configure("TFrame", background=BG_DARK)
        style.configure("TLabelframe", background=BG_PANEL, foreground=ACCENT,
                         font=("Helvetica", 11, "bold"))
        style.configure("TLabelframe.Label", background=BG_PANEL, foreground=ACCENT)
        style.configure("TButton", background=ACCENT, foreground="white",
                         font=("Helvetica", 10, "bold"), padding=(12, 6))
        style.map("TButton",
                  background=[("active", ACCENT_HOVER), ("disabled", FG_DIM)])
        style.configure("TCombobox", fieldbackground=BG_INPUT, background=BG_INPUT,
                         foreground=FG_TEXT, selectbackground=ACCENT)
        style.configure("TScale", background=BG_DARK, troughcolor=BG_INPUT)
        style.configure("TCheckbutton", background=BG_DARK, foreground=FG_TEXT)
        style.configure("Horizontal.TProgressbar", troughcolor=BG_INPUT,
                         background=ACCENT, thickness=18)
        style.configure("Header.TLabel", font=("Helvetica", 16, "bold"),
                         foreground=ACCENT, background=BG_DARK)
        style.configure("SubHeader.TLabel", font=("Helvetica", 11),
                         foreground=FG_DIM, background=BG_DARK)

    def _build_ui(self):
        # Header
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=20, pady=(15, 5))
        ttk.Label(header_frame, text="⚕ IoMT Medical NIDS Simulator",
                  style="Header.TLabel").pack(side=tk.LEFT)
        ttk.Label(header_frame, text="Healthcare Network Intrusion Dataset Generator",
                  style="SubHeader.TLabel").pack(side=tk.LEFT, padx=(15, 0))

        # Main content: left panel + right panel
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)

        # Left panel — Controls
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        self._build_scenario_panel(left_frame)
        self._build_params_panel(left_frame)
        self._build_control_panel(left_frame)

        # Right panel — Output + Plot
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self._build_plot_panel(right_frame)
        self._build_log_panel(right_frame)

    # ── Scenario Panel ────────────────────────────────────────────────
    def _build_scenario_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="  Attack Scenario  ", padding=10)
        frame.pack(fill=tk.X, pady=(0, 8))

        # Scenario ID
        ttk.Label(frame, text="Scenario:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.scenario_var = tk.StringVar(value="A14")
        scenarios = [f"{sid} — {s.label}" for sid, s in ATTACK_SCENARIOS.items()]
        self.scenario_combo = ttk.Combobox(frame, textvariable=self.scenario_var,
                                            values=scenarios, width=35, state="readonly")
        self.scenario_combo.set("A14 — dicom_exfiltration")
        self.scenario_combo.grid(row=0, column=1, sticky=tk.EW, pady=3, padx=(5, 0))
        self.scenario_combo.bind("<<ComboboxSelected>>", self._on_scenario_change)

        # Description
        self.desc_label = ttk.Label(frame, text="", wraplength=320, foreground=FG_DIM)
        self.desc_label.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=3)

        # Environment profile
        ttk.Label(frame, text="Environment:").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.env_var = tk.StringVar(value="medium_hospital_v1")
        ttk.Combobox(frame, textvariable=self.env_var,
                     values=["medium_hospital_v1"], width=35,
                     state="readonly").grid(row=2, column=1, sticky=tk.EW, pady=3, padx=(5, 0))

        frame.columnconfigure(1, weight=1)
        self._update_description()

    def _on_scenario_change(self, event=None):
        self._update_description()

    def _update_description(self):
        sid = self.scenario_var.get().split(" — ")[0].strip()
        scenario = ATTACK_SCENARIOS.get(sid)
        if scenario:
            desc = f"Target: {scenario.primary_target}\n{scenario.signature_description}"
            self.desc_label.configure(text=desc)

    # ── Parameters Panel ──────────────────────────────────────────────
    def _build_params_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="  Simulation Parameters  ", padding=10)
        frame.pack(fill=tk.X, pady=(0, 8))

        row = 0

        # Duration
        ttk.Label(frame, text="Duration (s):").grid(row=row, column=0, sticky=tk.W, pady=3)
        self.duration_var = tk.IntVar(value=3600)
        self.duration_spin = ttk.Spinbox(frame, from_=60, to=86400,
                                          textvariable=self.duration_var, width=10)
        self.duration_spin.grid(row=row, column=1, sticky=tk.W, pady=3, padx=(5, 0))
        row += 1

        # Attack start
        ttk.Label(frame, text="Attack start (s):").grid(row=row, column=0, sticky=tk.W, pady=3)
        self.atk_start_var = tk.IntVar(value=420)
        ttk.Spinbox(frame, from_=0, to=86400, textvariable=self.atk_start_var,
                     width=10).grid(row=row, column=1, sticky=tk.W, pady=3, padx=(5, 0))
        row += 1

        # Attack duration
        ttk.Label(frame, text="Attack duration (s):").grid(row=row, column=0, sticky=tk.W, pady=3)
        self.atk_dur_var = tk.IntVar(value=180)
        ttk.Spinbox(frame, from_=10, to=86400, textvariable=self.atk_dur_var,
                     width=10).grid(row=row, column=1, sticky=tk.W, pady=3, padx=(5, 0))
        row += 1

        # Intensity
        ttk.Label(frame, text="Intensity:").grid(row=row, column=0, sticky=tk.W, pady=3)
        self.intensity_var = tk.DoubleVar(value=0.75)
        intensity_frame = ttk.Frame(frame)
        intensity_frame.grid(row=row, column=1, sticky=tk.EW, pady=3, padx=(5, 0))
        self.intensity_scale = ttk.Scale(intensity_frame, from_=0.1, to=1.0,
                                          variable=self.intensity_var, orient=tk.HORIZONTAL,
                                          command=self._update_intensity_label)
        self.intensity_scale.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.intensity_label = ttk.Label(intensity_frame, text="0.75", width=5)
        self.intensity_label.pack(side=tk.RIGHT)
        row += 1

        # Stealth
        self.stealth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Stealth mode (low-and-slow)",
                        variable=self.stealth_var).grid(row=row, column=0,
                                                         columnspan=2, sticky=tk.W, pady=3)
        row += 1

        # Seed
        ttk.Label(frame, text="Seed:").grid(row=row, column=0, sticky=tk.W, pady=3)
        self.seed_var = tk.IntVar(value=42)
        ttk.Spinbox(frame, from_=0, to=999999, textvariable=self.seed_var,
                     width=10).grid(row=row, column=1, sticky=tk.W, pady=3, padx=(5, 0))
        row += 1

        # Window size
        ttk.Label(frame, text="Window (s):").grid(row=row, column=0, sticky=tk.W, pady=3)
        self.window_var = tk.IntVar(value=5)
        ttk.Combobox(frame, textvariable=self.window_var,
                     values=[1, 5, 10], width=5,
                     state="readonly").grid(row=row, column=1, sticky=tk.W, pady=3, padx=(5, 0))
        row += 1

        # Output directory
        ttk.Label(frame, text="Output:").grid(row=row, column=0, sticky=tk.W, pady=3)
        out_frame = ttk.Frame(frame)
        out_frame.grid(row=row, column=1, sticky=tk.EW, pady=3, padx=(5, 0))
        self.output_var = tk.StringVar(value="./output")
        ttk.Entry(out_frame, textvariable=self.output_var, width=20).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(out_frame, text="...", command=self._browse_output,
                   width=3).pack(side=tk.RIGHT, padx=(3, 0))

        frame.columnconfigure(1, weight=1)

    def _update_intensity_label(self, val=None):
        self.intensity_label.configure(text=f"{self.intensity_var.get():.2f}")

    def _browse_output(self):
        d = filedialog.askdirectory(title="Select output directory")
        if d:
            self.output_var.set(d)

    # ── Control Panel ─────────────────────────────────────────────────
    def _build_control_panel(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=(0, 8))

        self.run_btn = ttk.Button(frame, text="▶  Run Simulation",
                                   command=self._start_simulation)
        self.run_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.stop_btn = ttk.Button(frame, text="■  Stop",
                                    command=self._stop_simulation, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.progress = ttk.Progressbar(frame, style="Horizontal.TProgressbar",
                                         mode="determinate")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))

    # ── Plot Panel ────────────────────────────────────────────────────
    def _build_plot_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="  Live Traffic Monitor  ", padding=5)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        if HAS_MATPLOTLIB:
            self.fig = Figure(figsize=(7, 3), dpi=90, facecolor=BG_DARK)
            self.ax1 = self.fig.add_subplot(121)
            self.ax2 = self.fig.add_subplot(122)
            for ax in (self.ax1, self.ax2):
                ax.set_facecolor(BG_PANEL)
                ax.tick_params(colors=FG_DIM, labelsize=8)
                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
                for spine in ax.spines.values():
                    spine.set_color(FG_DIM)

            self.ax1.set_title("Traffic Rate (flows/window)", color=FG_TEXT, fontsize=10)
            self.ax2.set_title("Attack Phase Transitions", color=FG_TEXT, fontsize=10)

            self.canvas = FigureCanvasTkAgg(self.fig, master=frame)
            self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Data buffers for plotting
            self.plot_times = []
            self.plot_benign = []
            self.plot_attack = []
            self.plot_phases = []
        else:
            ttk.Label(frame, text="Install matplotlib for live traffic plots",
                      foreground=WARNING).pack(expand=True)

    # ── Log Panel ─────────────────────────────────────────────────────
    def _build_log_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="  Simulation Log  ", padding=5)
        frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(
            frame, height=10, bg=BG_INPUT, fg=FG_TEXT,
            insertbackground=FG_TEXT, font=("Menlo", 9),
            wrap=tk.WORD, borderwidth=0
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _log(self, msg: str):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    # ── Simulation Control ────────────────────────────────────────────
    def _start_simulation(self):
        if self.is_running:
            return

        sid = self.scenario_var.get().split(" — ")[0].strip()

        config = SimConfig(
            scenario_id=sid,
            environment_profile=self.env_var.get(),
            seed=self.seed_var.get(),
            duration_s=self.duration_var.get(),
            window_size_s=self.window_var.get(),
            attack_start_s=self.atk_start_var.get(),
            attack_duration_s=self.atk_dur_var.get(),
            intensity=self.intensity_var.get(),
            stealth_mode=self.stealth_var.get(),
            output_dir=self.output_var.get(),
        )

        self.is_running = True
        self.run_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.progress["value"] = 0

        # Reset plot data
        if HAS_MATPLOTLIB:
            self.plot_times = []
            self.plot_benign = []
            self.plot_attack = []

        self._log(f"Starting simulation: {sid}")
        self._log(f"  Duration: {config.duration_s}s, Attack: {config.attack_start_s}s-"
                  f"{config.attack_start_s + config.attack_duration_s}s")

        self.sim_thread = threading.Thread(
            target=self._run_simulation_thread, args=(config,), daemon=True
        )
        self.sim_thread.start()

    def _run_simulation_thread(self, config: SimConfig):
        try:
            from main import Simulator
            sim = Simulator(config)

            # Override progress callback for GUI
            all_flows_buffer = []
            duration = config.duration_s
            window = config.window_size_s
            total_steps = duration // window

            from network_model import HospitalNetwork
            from traffic_generator import BenignTrafficGenerator
            from attack_injector import AttackStateMachine
            from labeling_engine import LabelingEngine
            from time_window import TimeWindowAggregator
            from export import Exporter

            network = HospitalNetwork(config.environment_profile, config.seed)
            traffic_gen = BenignTrafficGenerator(network, config)
            attack_sm = None
            scenario = ATTACK_SCENARIOS.get(config.scenario_id)
            if scenario:
                attack_sm = AttackStateMachine(scenario, network, config)
            labeling = LabelingEngine(config)
            windower = TimeWindowAggregator(config)
            exporter = Exporter(config)

            all_flows = []
            all_events = []

            for step in range(total_steps):
                if not self.is_running:
                    self.root.after(0, lambda: self._log("Simulation stopped by user."))
                    break

                t_start = step * window
                t_end = t_start + window

                benign = traffic_gen.generate_flows(t_start, t_end, start_hour=8.0)
                attack = attack_sm.generate_flows(t_start, t_end) if attack_sm else []

                chunk = benign + attack
                chunk = labeling.label_flows(chunk)
                events = labeling.get_events(chunk)

                all_flows.extend(chunk)
                all_events.extend(events)

                # Update GUI
                pct = (step + 1) / total_steps * 100
                benign_n = len(benign)
                attack_n = len(attack)

                self.root.after(0, lambda p=pct, s=step, b=benign_n, a=attack_n, t=t_start:
                                self._update_progress(p, s, b, a, t))

            if self.is_running:
                # Aggregate and export
                self.root.after(0, lambda: self._log("Aggregating windows..."))
                windows = windower.aggregate(all_flows, labeling)
                assets = network.get_assets_csv_rows()

                self.root.after(0, lambda: self._log("Exporting results..."))
                exporter.export_all(all_flows, windows, all_events, assets)

                total = len(all_flows)
                benign_total = sum(1 for f in all_flows if f.get("label") == "benign")
                attack_total = total - benign_total

                self.root.after(0, lambda: self._log(
                    f"\n✓ Simulation Complete!\n"
                    f"  Total flows: {total:,}\n"
                    f"  Benign: {benign_total:,} | Attack: {attack_total:,}\n"
                    f"  Windows: {len(windows):,} | Events: {len(all_events):,}\n"
                    f"  Output: {config.output_dir}"
                ))

        except Exception as e:
            self.root.after(0, lambda: self._log(f"ERROR: {e}"))
            import traceback
            self.root.after(0, lambda: self._log(traceback.format_exc()))
        finally:
            self.root.after(0, self._simulation_done)

    def _update_progress(self, pct, step, benign_n, attack_n, t):
        self.progress["value"] = pct

        if step % 10 == 0:
            self._log(f"  t={t:6.0f}s | benign={benign_n:4d}, attack={attack_n:3d}")

        # Update plot
        if HAS_MATPLOTLIB:
            self.plot_times.append(t)
            self.plot_benign.append(benign_n)
            self.plot_attack.append(attack_n)

            if step % 20 == 0:
                self._update_plots()

    def _update_plots(self):
        if not HAS_MATPLOTLIB:
            return

        self.ax1.clear()
        self.ax1.set_facecolor(BG_PANEL)
        self.ax1.fill_between(self.plot_times, self.plot_benign,
                               alpha=0.6, color=CYAN, label="Benign")
        self.ax1.fill_between(self.plot_times, self.plot_attack,
                               alpha=0.7, color=DANGER, label="Attack")
        self.ax1.set_title("Traffic Rate (flows/window)", color=FG_TEXT, fontsize=10)
        self.ax1.legend(fontsize=8, loc="upper right",
                        facecolor=BG_PANEL, edgecolor=FG_DIM, labelcolor=FG_TEXT)
        self.ax1.tick_params(colors=FG_DIM, labelsize=8)

        # Attack phase display
        self.ax2.clear()
        self.ax2.set_facecolor(BG_PANEL)
        atk_start = self.atk_start_var.get()
        atk_end = atk_start + self.atk_dur_var.get()
        if self.plot_times:
            max_t = max(self.plot_times)
            # Draw phases
            self.ax2.axvspan(0, atk_start, alpha=0.3, color=SUCCESS, label="Pre-attack")
            self.ax2.axvspan(atk_start, min(atk_end, max_t),
                              alpha=0.3, color=DANGER, label="Attack Phase")
            if atk_end < max_t:
                self.ax2.axvspan(atk_end, max_t, alpha=0.3, color=SUCCESS, label="Post-attack")
            self.ax2.set_title("Attack Phase Transitions", color=FG_TEXT, fontsize=10)
            self.ax2.legend(fontsize=8, loc="upper right",
                            facecolor=BG_PANEL, edgecolor=FG_DIM, labelcolor=FG_TEXT)
            self.ax2.tick_params(colors=FG_DIM, labelsize=8)

        self.fig.tight_layout()
        self.canvas.draw_idle()

    def _simulation_done(self):
        self.is_running = False
        self.run_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.progress["value"] = 100

        if HAS_MATPLOTLIB:
            self._update_plots()

    def _stop_simulation(self):
        self.is_running = False
        self._log("Stopping simulation...")


def launch_gui():
    """Entry point for GUI mode."""
    root = tk.Tk()
    app = SimulatorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
