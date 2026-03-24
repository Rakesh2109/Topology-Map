"""
IoMT Medical NIDS Simulator — Web Dashboard Server (v3)
Pure Python HTTP server with:
- REST API for simulation control
- Server-Sent Events (SSE) for real-time streaming
- Static file serving for the dashboard
- No external dependencies (uses built-in http.server)
"""

import http.server
import json
import os
import threading
import time
import queue
import socketserver
from urllib.parse import urlparse, parse_qs
from config import SimConfig, ATTACK_SCENARIOS, MEDIUM_HOSPITAL_ASSETS, Zone
from network_model import HospitalNetwork
from traffic_generator import BenignTrafficGenerator
from attack_injector import AttackStateMachine
from labeling_engine import LabelingEngine
from time_window import TimeWindowAggregator
from export import Exporter
from dataset_builder import DatasetBuilder
from scenario_builder import (
    export_builtin_examples, list_custom_scenarios,
    scenario_to_dict, dict_to_scenario, save_scenario,
    load_scenarios, asset_to_dict, dict_to_asset, save_devices,
)

# Dataset generation state
_dataset_state = {
    "running": False,
    "progress": 0,
    "total_flows": 0,
    "done": False,
    "error": None,
    "result": None,
}

# Global state
_sim_state = {
    "running": False,
    "progress": 0,
    "total_flows": 0,
    "benign_flows": 0,
    "attack_flows": 0,
    "total_events": 0,
    "total_windows": 0,
    "current_stage": "",
    "elapsed": 0,
    "recent_events": [],
    "flow_rates": [],          # [{t, benign, attack}, ...]
    "protocol_counts": {},
    "zone_traffic": {},
    "done": False,
    "error": None,
}
_event_queues = []  # SSE subscriber queues
_sim_lock = threading.Lock()


def _broadcast(event_type: str, data: dict):
    msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    dead = []
    for q in _event_queues:
        try:
            q.put_nowait(msg)
        except queue.Full:
            dead.append(q)
    for d in dead:
        _event_queues.remove(d)


def _run_simulation(config: SimConfig):
    global _sim_state
    try:
        with _sim_lock:
            _sim_state = {
                "running": True, "progress": 0, "total_flows": 0,
                "benign_flows": 0, "attack_flows": 0, "total_events": 0,
                "total_windows": 0, "current_stage": "initializing",
                "elapsed": 0, "recent_events": [], "flow_rates": [],
                "protocol_counts": {}, "zone_traffic": {}, "done": False, "error": None,
            }

        network = HospitalNetwork(config.environment_profile, config.seed)
        traffic_gen = BenignTrafficGenerator(network, config)

        # Support multi-scenario
        attack_machines = []
        if "," in config.scenario_id:
            for sid in config.scenario_id.split(","):
                sid = sid.strip()
                scenario = ATTACK_SCENARIOS.get(sid)
                if scenario:
                    attack_machines.append(AttackStateMachine(scenario, network, config))
        else:
            scenario = ATTACK_SCENARIOS.get(config.scenario_id)
            if scenario:
                attack_machines.append(AttackStateMachine(scenario, network, config))

        labeling = LabelingEngine(config)
        windower = TimeWindowAggregator(config)
        exporter = Exporter(config)

        all_flows = []
        all_events = []
        start_time = time.time()

        duration = config.duration_s
        window = config.window_size_s
        total_steps = duration // window

        for step in range(total_steps):
            if not _sim_state["running"]:
                break

            t_start = step * window
            t_end = t_start + window

            benign = traffic_gen.generate_flows(t_start, t_end, start_hour=8.0)
            attack = []
            for sm in attack_machines:
                attack.extend(sm.generate_flows(t_start, t_end))

            chunk = benign + attack
            chunk = labeling.label_flows(chunk)
            events = labeling.get_events(chunk)

            all_flows.extend(chunk)
            all_events.extend(events)

            # Compute stats
            benign_n = len(benign)
            attack_n = len(attack)
            pct = (step + 1) / total_steps * 100

            # Protocol distribution
            for f in chunk:
                p = f.get("proto", "TCP")
                _sim_state["protocol_counts"][p] = _sim_state["protocol_counts"].get(p, 0) + 1

            # Zone traffic
            for f in chunk:
                zs = f.get("zone_src", "")
                zd = f.get("zone_dst", "")
                key = f"{zs}→{zd}"
                _sim_state["zone_traffic"][key] = _sim_state["zone_traffic"].get(key, 0) + 1

            # Current stage
            stage = ""
            for sm in attack_machines:
                s = sm.get_current_stage((t_start + t_end) / 2.0)
                if s:
                    stage = f"{sm.scenario.scenario_id}:{s}"

            with _sim_lock:
                _sim_state["progress"] = pct
                _sim_state["total_flows"] = len(all_flows)
                _sim_state["benign_flows"] = sum(1 for f in all_flows if f.get("label") == "benign")
                _sim_state["attack_flows"] = _sim_state["total_flows"] - _sim_state["benign_flows"]
                _sim_state["total_events"] = len(all_events)
                _sim_state["current_stage"] = stage
                _sim_state["elapsed"] = round(time.time() - start_time, 1)
                _sim_state["flow_rates"].append({
                    "t": t_start,
                    "benign": benign_n,
                    "attack": attack_n,
                })
                # Keep recent events (last 50)
                for ev in events[-10:]:
                    _sim_state["recent_events"].append({
                        "ts": round(ev.get("timestamp", 0), 1),
                        "type": ev.get("event_type", ""),
                        "src": ev.get("src_ip", ""),
                        "dst": ev.get("dst_ip", ""),
                        "label": ev.get("label", ""),
                        "details": ev.get("details", ""),
                    })
                _sim_state["recent_events"] = _sim_state["recent_events"][-100:]

            _broadcast("progress", {
                "pct": round(pct, 1),
                "t": t_start,
                "benign": benign_n,
                "attack": attack_n,
                "stage": stage,
                "total_flows": len(all_flows),
                "events": len(events),
            })

        # Aggregate and export
        with _sim_lock:
            _sim_state["current_stage"] = "aggregating"
        _broadcast("status", {"msg": "Aggregating windows..."})

        windows = windower.aggregate(all_flows, labeling)
        assets = network.get_assets_csv_rows()

        with _sim_lock:
            _sim_state["current_stage"] = "exporting"
        _broadcast("status", {"msg": "Exporting results..."})

        exporter.export_all(all_flows, windows, all_events, assets)

        with _sim_lock:
            _sim_state["running"] = False
            _sim_state["done"] = True
            _sim_state["progress"] = 100
            _sim_state["total_windows"] = len(windows)
            _sim_state["elapsed"] = round(time.time() - start_time, 1)
            _sim_state["current_stage"] = "complete"

        _broadcast("complete", {
            "total_flows": len(all_flows),
            "benign_flows": _sim_state["benign_flows"],
            "attack_flows": _sim_state["attack_flows"],
            "total_windows": len(windows),
            "total_events": len(all_events),
            "elapsed": _sim_state["elapsed"],
        })

    except Exception as e:
        with _sim_lock:
            _sim_state["running"] = False
            _sim_state["error"] = str(e)
        _broadcast("error", {"msg": str(e)})


class SimHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler for the simulator dashboard."""

    def __init__(self, *args, **kwargs):
        static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
        super().__init__(*args, directory=static_dir, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/scenarios":
            self._json_response({
                sid: {
                    "label": s.label,
                    "target": s.primary_target,
                    "protocols": s.affected_protocols,
                    "entry_point": s.entry_point,
                    "stages": [{"name": st.name, "frac": st.duration_frac, "desc": st.description}
                               for st in s.stages],
                    "signature": s.signature_description,
                    "stealth": s.default_stealth,
                }
                for sid, s in ATTACK_SCENARIOS.items()
            })

        elif path == "/api/network":
            self._json_response({
                "assets": [
                    {
                        "name": a.name, "zone": a.zone.value, "ip": a.ip,
                        "role": a.device_role.value, "protocols": a.protocols,
                        "criticality": a.criticality, "internet_exposed": a.internet_exposed,
                    }
                    for a in MEDIUM_HOSPITAL_ASSETS
                ],
                "zones": {z.value: z.name for z in Zone},
            })

        elif path == "/api/status":
            with _sim_lock:
                self._json_response(dict(_sim_state))

        elif path == "/api/dataset-status":
            self._json_response(dict(_dataset_state))

        elif path == "/api/custom-scenarios":
            # We look in configs/scenarios/ instead of output/examples/scenarios/
            base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "configs", "scenarios")
            custom = os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom_scenarios")
            results = list_custom_scenarios(base) + list_custom_scenarios(custom)
            self._json_response(results)

        elif path == "/api/device-roles":
            from config import DeviceRole
            self._json_response([r.value for r in DeviceRole])

        elif path == "/api/zones":
            self._json_response([{"value": z.value, "name": z.name} for z in Zone])

        elif path == "/api/events":
            self._sse_stream()

        else:
            # Serve static files
            if path == "/":
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/start":
            content_len = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_len)) if content_len else {}

            if _sim_state["running"]:
                self._json_response({"error": "Simulation already running"}, 400)
                return

            # Validate and clamp
            duration = max(30, min(86400, body.get("duration", 3600)))
            attack_start = max(0, body.get("attack_start", 420))
            attack_duration = max(10, body.get("attack_duration", 180))

            if attack_start >= duration:
                attack_start = max(0, duration - attack_duration - 10)
            if attack_start + attack_duration > duration:
                attack_duration = duration - attack_start

            config = SimConfig(
                scenario_id=body.get("scenario", "A14"),
                duration_s=duration,
                attack_start_s=attack_start,
                attack_duration_s=attack_duration,
                intensity=max(0.1, min(1.0, body.get("intensity", 0.75))),
                stealth_mode=body.get("stealth", False),
                seed=body.get("seed", 42),
                window_size_s=body.get("window_size", 5),
                output_dir=body.get("output_dir", "./output"),
            )

            thread = threading.Thread(target=_run_simulation, args=(config,), daemon=True)
            thread.start()

            self._json_response({"status": "started", "config": config.to_dict()})

        elif path == "/api/stop":
            with _sim_lock:
                _sim_state["running"] = False
            self._json_response({"status": "stopped"})

        elif path == "/api/generate-dataset":
            content_len = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_len)) if content_len else {}

            if _dataset_state["running"] or _sim_state["running"]:
                self._json_response({"error": "A simulation is already running"}, 400)
                return

            def _run_dataset(body):
                global _dataset_state
                try:
                    _dataset_state = {"running": True, "progress": 0, "total_flows": 0,
                                      "done": False, "error": None, "result": None}

                    def _progress(pct, step, total, nflows):
                        _dataset_state["progress"] = round(pct * 100, 1)
                        _dataset_state["total_flows"] = nflows
                        _broadcast("dataset-progress", {"pct": round(pct * 100, 1), "flows": nflows})

                    builder = DatasetBuilder(
                        total_duration=body.get("duration", 86400),
                        attack_duration_each=body.get("attack_duration", 300),
                        intensity=body.get("intensity", 0.75),
                        seed=body.get("seed", 42),
                        output_dir=body.get("output_dir", "./dataset"),
                        train_ratio=body.get("train_ratio", 0.8),
                        window_size_s=body.get("window_size", 5),
                    )
                    result = builder.generate(progress_callback=_progress)
                    _dataset_state["done"] = True
                    _dataset_state["running"] = False
                    _dataset_state["progress"] = 100
                    _dataset_state["result"] = result["stats"]
                    _broadcast("dataset-complete", result["stats"])
                except Exception as e:
                    _dataset_state["running"] = False
                    _dataset_state["error"] = str(e)
                    _broadcast("error", {"msg": str(e)})

            thread = threading.Thread(target=_run_dataset, args=(body,), daemon=True)
            thread.start()
            self._json_response({"status": "started"})

        elif path == "/api/save-scenario":
            content_len = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_len)) if content_len else {}

            try:
                scenario = dict_to_scenario(body)
                custom_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom_scenarios")
                os.makedirs(custom_dir, exist_ok=True)
                path = os.path.join(custom_dir, f"{scenario.scenario_id}_{scenario.label}.json")
                save_scenario(scenario, path)
                # Also register it
                ATTACK_SCENARIOS[scenario.scenario_id] = scenario
                self._json_response({"status": "saved", "path": path})
            except Exception as e:
                self._json_response({"error": str(e)}, 400)

        elif path == "/api/export-examples":
            try:
                base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "configs")
                result = export_builtin_examples(base)
                self._json_response({"status": "exported", **result})
            except Exception as e:
                self._json_response({"error": str(e)}, 500)

        else:
            self._json_response({"error": "Not found"}, 404)

    def _json_response(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def _sse_stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        q = queue.Queue(maxsize=500)
        _event_queues.append(q)

        try:
            while True:
                try:
                    msg = q.get(timeout=30)
                    self.wfile.write(msg.encode())
                    self.wfile.flush()
                except queue.Empty:
                    # Send keepalive
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            if q in _event_queues:
                _event_queues.remove(q)

    def log_message(self, format, *args):
        # Suppress default logging for SSE
        if "/api/events" not in str(args):
            super().log_message(format, *args)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def launch_web(port=8080):
    """Launch the web dashboard server."""
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    os.makedirs(static_dir, exist_ok=True)

    server = ThreadedHTTPServer(("0.0.0.0", port), SimHandler)
    print(f"\n{'='*60}")
    print(f"  IoMT Medical NIDS Simulator v3.0 — Web Dashboard")
    print(f"{'='*60}")
    print(f"  Dashboard: http://localhost:{port}")
    print(f"  API:       http://localhost:{port}/api/scenarios")
    print(f"{'='*60}\n")

    import webbrowser
    webbrowser.open(f"http://localhost:{port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    launch_web()
