"""
IoMT Medical NIDS Simulator — Scenario & Device Builder
JSON-based save/load for custom scenarios and device definitions.
Built-in 24 scenarios exported as loadable example JSON files.
"""

import json
import os
from typing import List, Dict, Optional
from config import (
    AttackScenario, AttackStage, AssetDef,
    Zone, DeviceRole, ATTACK_SCENARIOS, MEDIUM_HOSPITAL_ASSETS,
    NORMAL_COMM_MAP,
)


# ──────────────────────────────────────────────────────────────────────
# Scenario JSON ↔ AttackScenario
# ──────────────────────────────────────────────────────────────────────

def scenario_to_dict(s: AttackScenario) -> dict:
    """Convert AttackScenario to a JSON-serializable dict."""
    return {
        "scenario_id": s.scenario_id,
        "label": s.label,
        "attack_path": s.attack_path,
        "primary_target": s.primary_target,
        "target_roles": [r.value for r in s.target_roles],
        "affected_protocols": s.affected_protocols,
        "entry_point": s.entry_point,
        "target_asset": s.target_asset,
        "default_intensity": s.default_intensity,
        "default_stealth": s.default_stealth,
        "stages": [
            {"name": st.name, "duration_frac": st.duration_frac, "description": st.description}
            for st in s.stages
        ],
        "signature_description": s.signature_description,
    }


def dict_to_scenario(d: dict) -> AttackScenario:
    """Convert dict (from JSON) to AttackScenario."""
    return AttackScenario(
        scenario_id=d["scenario_id"],
        label=d["label"],
        attack_path=d.get("attack_path", ""),
        primary_target=d.get("primary_target", ""),
        target_roles=[DeviceRole(r) for r in d.get("target_roles", [])],
        affected_protocols=d.get("affected_protocols", []),
        entry_point=d.get("entry_point", ""),
        target_asset=d.get("target_asset", ""),
        default_intensity=d.get("default_intensity", 0.75),
        default_stealth=d.get("default_stealth", False),
        stages=[
            AttackStage(
                name=st["name"],
                duration_frac=st["duration_frac"],
                description=st.get("description", "")
            )
            for st in d.get("stages", [])
        ],
        signature_description=d.get("signature_description", ""),
    )


def save_scenario(scenario: AttackScenario, path: str):
    """Save a single scenario to JSON."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(scenario_to_dict(scenario), f, indent=2)


def load_scenario(path: str) -> AttackScenario:
    """Load a single scenario from JSON."""
    with open(path, "r") as f:
        return dict_to_scenario(json.load(f))


def save_scenarios(scenarios: Dict[str, AttackScenario], path: str):
    """Save multiple scenarios to a single JSON file."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    data = {sid: scenario_to_dict(s) for sid, s in scenarios.items()}
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_scenarios(path: str) -> Dict[str, AttackScenario]:
    """Load multiple scenarios from JSON file."""
    with open(path, "r") as f:
        data = json.load(f)

    # Handle both single scenario and multi-scenario format
    if "scenario_id" in data:
        # Single scenario
        s = dict_to_scenario(data)
        return {s.scenario_id: s}
    else:
        # Multi-scenario dict
        return {sid: dict_to_scenario(d) for sid, d in data.items()}


# ──────────────────────────────────────────────────────────────────────
# Device/Asset JSON ↔ AssetDef
# ──────────────────────────────────────────────────────────────────────

def asset_to_dict(a: AssetDef) -> dict:
    """Convert AssetDef to JSON dict."""
    return {
        "name": a.name,
        "zone": a.zone.value,
        "ip": a.ip,
        "device_role": a.device_role.value,
        "protocols": a.protocols,
        "criticality": a.criticality,
        "internet_exposed": a.internet_exposed,
    }


def dict_to_asset(d: dict) -> AssetDef:
    """Convert dict to AssetDef."""
    return AssetDef(
        name=d["name"],
        zone=Zone(d["zone"]),
        ip=d["ip"],
        device_role=DeviceRole(d["device_role"]),
        protocols=d.get("protocols", []),
        criticality=d.get("criticality", 5),
        internet_exposed=d.get("internet_exposed", False),
    )


def save_devices(devices: List[AssetDef], path: str):
    """Save device list to JSON."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump([asset_to_dict(a) for a in devices], f, indent=2)


def load_devices(path: str) -> List[AssetDef]:
    """Load device list from JSON."""
    with open(path, "r") as f:
        return [dict_to_asset(d) for d in json.load(f)]


# ──────────────────────────────────────────────────────────────────────
# Communication Map JSON
# ──────────────────────────────────────────────────────────────────────

def save_comm_map(comm_map: list, path: str):
    """Save communication map to JSON."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    data = [
        {
            "src_role": src.value,
            "dst_role": dst.value,
            "protocols": protos,
            "flows_per_hour": fph,
        }
        for src, dst, protos, fph in comm_map
    ]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_comm_map(path: str) -> list:
    """Load communication map from JSON."""
    with open(path, "r") as f:
        data = json.load(f)
    return [
        (DeviceRole(d["src_role"]), DeviceRole(d["dst_role"]),
         d["protocols"], d["flows_per_hour"])
        for d in data
    ]


# ──────────────────────────────────────────────────────────────────────
# Export Built-in Examples
# ──────────────────────────────────────────────────────────────────────

def export_builtin_examples(output_dir: str = "configs"):
    """
    Exports the predefined attack scenarios and hospital device lists
    as JSON files so users can modify them or build their own.r use as templates.
    """
    scenarios_dir = os.path.join(output_dir, "scenarios")
    devices_dir = os.path.join(output_dir, "devices")
    os.makedirs(scenarios_dir, exist_ok=True)
    os.makedirs(devices_dir, exist_ok=True)

    # Export each scenario individually
    for sid, scenario in ATTACK_SCENARIOS.items():
        path = os.path.join(scenarios_dir, f"{sid}_{scenario.label}.json")
        save_scenario(scenario, path)

    # Export all scenarios in one file
    save_scenarios(ATTACK_SCENARIOS, os.path.join(scenarios_dir, "all_scenarios.json"))

    # Export devices
    save_devices(MEDIUM_HOSPITAL_ASSETS, os.path.join(devices_dir, "medium_hospital.json"))

    # Export communication map
    save_comm_map(NORMAL_COMM_MAP, os.path.join(devices_dir, "comm_map.json"))

    print(f"  ✓ Exported {len(ATTACK_SCENARIOS)} scenario examples → {scenarios_dir}")
    print(f"  ✓ Exported {len(MEDIUM_HOSPITAL_ASSETS)} devices → {devices_dir}")
    print(f"  ✓ Exported communication map → {devices_dir}/comm_map.json")

    return {
        "scenarios_dir": scenarios_dir,
        "devices_dir": devices_dir,
        "scenario_count": len(ATTACK_SCENARIOS),
        "device_count": len(MEDIUM_HOSPITAL_ASSETS),
    }


# ──────────────────────────────────────────────────────────────────────
# List Custom Scenarios
# ──────────────────────────────────────────────────────────────────────

def list_custom_scenarios(directory: str) -> List[dict]:
    """List all JSON scenario files in a directory."""
    results = []
    if not os.path.isdir(directory):
        return results

    for fname in sorted(os.listdir(directory)):
        if fname.endswith(".json") and fname != "all_scenarios.json":
            path = os.path.join(directory, fname)
            try:
                scenario = load_scenario(path)
                results.append({
                    "file": fname,
                    "path": path,
                    "scenario_id": scenario.scenario_id,
                    "label": scenario.label,
                    "target": scenario.primary_target,
                    "stages": len(scenario.stages),
                    "protocols": scenario.affected_protocols,
                })
            except Exception:
                pass
    return results


if __name__ == "__main__":
    # Quick test
    export_builtin_examples()
    print("\nListing exported scenarios:")
    
    for s in list_custom_scenarios("configs/scenarios"):
        print(f"Loaded scenario: {s['label']} ({s['stages']} stages)")
