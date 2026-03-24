"""
IoMT Medical NIDS Simulator — Attack Injector (v2)
Implements all 24 attack scenarios (A01-A24) with:
- Attacker IP rotation and multiple source IPs
- Organic variability (bursts, pauses, jitter)
- Inter-flow correlation / session state for multi-stage attacks
- Multi-scenario concurrent support
"""

import random
import math
from typing import List, Dict, Optional
from config import (
    Zone, DeviceRole, SimConfig, ATTACK_SCENARIOS, AttackScenario,
    BASE_FLOW_FIELDS, MEDICAL_METADATA_FIELDS, LABEL_FIELDS
)
from network_model import HospitalNetwork, Asset


def _empty_flow() -> dict:
    flow = {}
    for f in BASE_FLOW_FIELDS:
        flow[f] = 0
    for f in MEDICAL_METADATA_FIELDS:
        flow[f] = 0
    for f in LABEL_FIELDS:
        flow[f] = ""
    return flow


class AttackStateMachine:
    """
    Attack scenario execution engine with session state tracking,
    IP rotation, and organic traffic variability.
    """

    def __init__(self, scenario: AttackScenario, network: HospitalNetwork,
                 config: SimConfig):
        self.scenario = scenario
        self.network = network
        self.config = config
        self.rng = random.Random(config.seed + hash(scenario.scenario_id))
        self.attack_start = config.attack_start_s
        self.attack_end = config.attack_start_s + config.attack_duration_s
        self.intensity = config.intensity
        self.stealth = config.stealth_mode or scenario.default_stealth

        # === IP rotation pool ===
        self._attacker_ips = self._generate_attacker_ips()
        self._current_ip_idx = 0
        self._ip_rotate_interval = self.rng.uniform(15, 60)  # seconds between rotations
        self._last_ip_rotate = 0.0

        # === Session state for inter-flow correlation ===
        self._session_id = self.rng.randint(100000, 999999)
        self._compromised_hosts = []  # IPs that have been "taken over"
        self._discovered_data = 0  # bytes of data found
        self._stage_progress = {}  # track per-stage progress
        self._flows_generated = 0

        # Resolve targets
        self.targets = self._resolve_targets()

    def _generate_attacker_ips(self) -> List[str]:
        """Generate a pool of attacker IPs for rotation."""
        ips = []
        if self.scenario.entry_point in ("internet", "Internet"):
            # External attackers use multiple IPs (botnet/proxies)
            n = 3 if self.stealth else self.rng.randint(2, 6)
            for _ in range(n):
                ips.append(f"198.51.100.{self.rng.randint(1, 254)}")
        elif self.scenario.entry_point in ("vendor_vpn",):
            vendor = self.network.get_assets_by_role(DeviceRole.VENDOR_JUMPHOST)
            if vendor:
                ips = [v.ip for v in vendor]
            else:
                ips = [f"10.5.0.{self.rng.randint(30, 50)}"]
        else:
            # Internal attacker — use compromised workstation IP
            zone_map = {
                "clinical_subnet": Zone.C,
                "imaging_subnet": Zone.D,
                "iomt_subnet": Zone.E,
                "enterprise_it": Zone.B,
                "internal_subnet": Zone.B,
            }
            zone = zone_map.get(self.scenario.entry_point, Zone.B)
            assets = self.network.get_assets_by_zone(zone)
            if assets:
                chosen = self.rng.sample(assets, min(3, len(assets)))
                ips = [a.ip for a in chosen]
            else:
                ips = [self.network.generate_external_ip()]

        return ips if ips else [self.network.generate_external_ip()]

    def _get_attacker_ip(self, t: float) -> str:
        """Get current attacker IP with rotation logic."""
        if t - self._last_ip_rotate > self._ip_rotate_interval:
            self._current_ip_idx = (self._current_ip_idx + 1) % len(self._attacker_ips)
            self._last_ip_rotate = t
            self._ip_rotate_interval = self.rng.uniform(15, 60)
        return self._attacker_ips[self._current_ip_idx]

    def _get_attacker_role(self) -> str:
        """Infer the attacker's device role based on entry point."""
        if self.scenario.entry_point in ("internet", "Internet"):
            return DeviceRole.EXTERNAL_ATTACKER.value
        if self.scenario.entry_point == "vendor_vpn":
            return DeviceRole.VENDOR_JUMPHOST.value
        # Internal compromise — use the compromised asset's actual role
        for asset in self.network.assets:
            if asset.ip == self._attacker_ips[0]:
                return asset.device_role.value
        return DeviceRole.EXTERNAL_ATTACKER.value

    def _resolve_targets(self) -> List[Asset]:
        targets = []
        for role in self.scenario.target_roles:
            targets.extend(self.network.get_assets_by_role(role))
        return targets if targets else [self.network.assets[0]]

    def get_current_stage(self, t: float) -> Optional[str]:
        """Return the current attack stage name for time t."""
        if t < self.attack_start or t >= self.attack_end:
            return None
        elapsed_frac = (t - self.attack_start) / max(1, self.attack_end - self.attack_start)
        cumulative = 0.0
        for stage in self.scenario.stages:
            cumulative += stage.duration_frac
            if elapsed_frac <= cumulative:
                return stage.name
        return self.scenario.stages[-1].name if self.scenario.stages else None

    def _organic_flow_count(self, base_n: int, t: float) -> int:
        """
        Apply organic variability to the base flow count.
        Creates bursts and pauses instead of constant rates.
        """
        # Multi-frequency modulation
        mod1 = 0.7 + 0.4 * math.sin(t * 0.1 + self.rng.random() * 3.14)
        mod2 = 0.85 + 0.2 * math.sin(t * 0.37 + 1.5)

        # Random burst/pause (more natural)
        if self.rng.random() < 0.08:
            burst = self.rng.uniform(1.8, 3.0)  # occasional burst
        elif self.rng.random() < 0.05:
            burst = self.rng.uniform(0.1, 0.4)  # occasional pause
        else:
            burst = 1.0

        n = int(base_n * mod1 * mod2 * burst)
        # Add Gaussian noise
        n = max(1, int(self.rng.gauss(n, max(1, n * 0.15))))
        return n

    def generate_flows(self, t_start: float, t_end: float) -> List[dict]:
        """Generate attack flows for time interval [t_start, t_end]."""
        flows = []
        if t_end <= self.attack_start or t_start >= self.attack_end:
            return flows

        t0 = max(t_start, self.attack_start)
        t1 = min(t_end, self.attack_end)
        stage = self.get_current_stage((t0 + t1) / 2.0)
        if not stage:
            return flows

        generator = SCENARIO_GENERATORS.get(self.scenario.scenario_id,
                                            self._generic_attack_flows)
        flows = generator(self, t0, t1, stage)

        # Label all flows
        for flow in flows:
            flow["label"] = self.scenario.label
            flow["attack_id"] = self.scenario.scenario_id
            flow["scenario_id"] = self.config.scenario_id
            flow["attack_stage"] = stage
            self._flows_generated += 1

        return flows

    def _make_base_flow(self, src_ip: str, dst: Asset, proto: str,
                        ts: float, **overrides) -> dict:
        """Create a base flow with common attack properties."""
        flow = _empty_flow()

        port_map = {
            "HTTPS": 443, "HTTP": 80, "DICOM": 11112, "HL7": 2575,
            "SSH": 22, "RDP": 3389, "SMB": 445, "SNMP": 161,
            "BLE": 0, "TCP": 8080, "FHIR": 443, "VPN": 1194,
        }

        flow["ts_start"] = round(ts, 6)
        flow["src_ip"] = src_ip
        flow["dst_ip"] = dst.ip
        flow["src_port"] = self.rng.randint(49152, 65535)
        flow["dst_port"] = port_map.get(proto, self.rng.randint(1024, 65535))
        flow["proto"] = proto
        flow["direction"] = "fwd"
        flow["zone_src"] = self._infer_zone(src_ip)
        flow["zone_dst"] = dst.zone.value
        flow["device_role_src"] = overrides.pop("src_role", self._get_attacker_role())
        flow["device_role_dst"] = dst.device_role.value
        flow["app_service"] = proto

        for k, v in overrides.items():
            if k in flow:
                flow[k] = v

        return flow

    def _infer_zone(self, ip: str) -> str:
        if ip.startswith("203.0.113.") or ip.startswith("198.51.100."):
            return Zone.A.value
        if ip.startswith("10.1."):
            return Zone.B.value
        if ip.startswith("10.2."):
            return Zone.C.value
        if ip.startswith("10.3."):
            return Zone.D.value
        if ip.startswith("10.4."):
            return Zone.E.value
        if ip.startswith("10.5."):
            return Zone.F.value
        return Zone.A.value

    def _generic_attack_flows(self, t0, t1, stage):
        flows = []
        base_n = max(1, int(5 * self.intensity * (t1 - t0)))
        if self.stealth:
            base_n = max(1, base_n // 3)
        n = self._organic_flow_count(base_n, (t0 + t1) / 2.0)
        for _ in range(n):
            dst = self.rng.choice(self.targets)
            proto = self.rng.choice(self.scenario.affected_protocols)
            ts = self.rng.uniform(t0, t1)
            ip = self._get_attacker_ip(ts)
            flow = self._make_base_flow(ip, dst, proto, ts)
            flow["duration_ms"] = self.rng.randint(50, 2000)
            flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
            flow["pkts_fwd"] = self.rng.randint(2, 20)
            flow["pkts_rev"] = self.rng.randint(1, 10)
            flow["bytes_fwd"] = flow["pkts_fwd"] * self.rng.randint(40, 500)
            flow["bytes_rev"] = flow["pkts_rev"] * self.rng.randint(40, 500)
            flow["syn_cnt"] = 1
            flows.append(flow)
        return flows


# ──────────────────────────────────────────────────────────────────────
# Scenario-specific attack flow generators (v2 — with IP rotation,
# organic variability, and inter-flow correlation)
# ──────────────────────────────────────────────────────────────────────

def _a01_recon(sm, t0, t1, stage):
    """A01: External recon — short flows to many hosts/ports."""
    flows = []
    base_n = max(5, int(30 * sm.intensity * (t1 - t0)))
    if sm.stealth:
        base_n = max(2, base_n // 4)
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    all_assets = sm.network.assets
    for _ in range(n):
        dst = sm.rng.choice(all_assets)
        ts = sm.rng.uniform(t0, t1)
        ip = sm._get_attacker_ip(ts)
        proto = sm.rng.choice(["TCP", "HTTPS"])
        flow = sm._make_base_flow(ip, dst, proto, ts)
        flow["duration_ms"] = sm.rng.randint(5, 100)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(1, 3)
        flow["pkts_rev"] = sm.rng.randint(0, 2)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(40, 80)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(40, 60)
        flow["syn_cnt"] = 1
        flow["rst_cnt"] = 1 if sm.rng.random() < 0.6 else 0
        flow["dst_port"] = sm.rng.randint(1, 65535)
        flows.append(flow)
    return flows


def _a02_enum(sm, t0, t1, stage):
    """A02: Service enumeration."""
    flows = []
    base_n = max(3, int(15 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets) if sm.targets else sm.network.assets[0]
        ts = sm.rng.uniform(t0, t1)
        ip = sm._get_attacker_ip(ts)
        flow = sm._make_base_flow(ip, dst, "HTTPS", ts)
        flow["duration_ms"] = sm.rng.randint(50, 500)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(2, 8)
        flow["pkts_rev"] = sm.rng.randint(1, 4)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 400)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(50, 200)
        flow["http_status"] = sm.rng.choice([200, 301, 403, 404, 404, 404])
        flow["tls_session"] = 1
        flow["syn_cnt"] = 1
        flows.append(flow)
    return flows


def _a03_spray(sm, t0, t1, stage):
    """A03: Password spraying — low-rate login attempts, many usernames."""
    flows = []
    base_n = max(2, int(5 * sm.intensity * (t1 - t0)))
    if sm.stealth:
        base_n = max(1, base_n // 3)
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        ip = sm._get_attacker_ip(ts)
        flow = sm._make_base_flow(ip, dst, "HTTPS", ts)
        flow["duration_ms"] = sm.rng.randint(200, 800)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(3, 8)
        flow["pkts_rev"] = sm.rng.randint(2, 5)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 300)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(80, 200)
        flow["auth_attempts"] = 1
        flow["auth_failures"] = 1 if sm.rng.random() < 0.92 else 0
        flow["http_status"] = 401 if flow["auth_failures"] else 200
        flow["tls_session"] = 1
        # Correlate: track total attempts
        sm._stage_progress["total_spray_attempts"] = sm._stage_progress.get("total_spray_attempts", 0) + 1
        flows.append(flow)
    return flows


def _a04_bruteforce(sm, t0, t1, stage):
    """A04: Brute force — high rate auth failures with IP rotation."""
    flows = []
    base_n = max(5, int(40 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        ip = sm._get_attacker_ip(ts)
        flow = sm._make_base_flow(ip, dst, "HTTPS", ts)
        flow["duration_ms"] = sm.rng.randint(50, 300)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(3, 6)
        flow["pkts_rev"] = sm.rng.randint(2, 4)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(80, 200)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(60, 150)
        flow["auth_attempts"] = sm.rng.randint(1, 3)
        # Success rate increases over time (simulates cracking progress)
        attempts_so_far = sm._stage_progress.get("brute_attempts", 0)
        success_prob = min(0.15, 0.01 + attempts_so_far * 0.0001)
        flow["auth_failures"] = flow["auth_attempts"] if sm.rng.random() > success_prob else 0
        flow["http_status"] = 401 if flow["auth_failures"] else 200
        flow["tls_session"] = 1
        sm._stage_progress["brute_attempts"] = attempts_so_far + 1
        flows.append(flow)
    return flows


def _a05_vendor_abuse(sm, t0, t1, stage):
    """A05: Vendor support abuse with progressive internal pivot."""
    flows = []
    vendor = sm.network.get_random_asset(role=DeviceRole.VENDOR_JUMPHOST)
    if not vendor:
        return sm._generic_attack_flows(t0, t1, stage)

    base_n = max(2, int(8 * sm.intensity * (t1 - t0)))
    if sm.stealth:
        base_n = max(1, base_n // 2)
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)

    for _ in range(n):
        if stage == "vendor_access":
            dst = sm.rng.choice(sm.targets)
            proto = sm.rng.choice(["SSH", "RDP"])
        elif stage == "internal_pivot":
            # Progressively discover more clinical assets
            clinical = (sm.network.get_assets_by_zone(Zone.C) +
                       sm.network.get_assets_by_zone(Zone.E))
            dst = sm.rng.choice(clinical) if clinical else sm.rng.choice(sm.targets)
            proto = sm.rng.choice(["SMB", "RDP", "HTTPS"])
            # Track compromised hosts
            if dst.ip not in sm._compromised_hosts:
                sm._compromised_hosts.append(dst.ip)
        else:
            dst = sm.rng.choice(sm.targets)
            proto = "HTTPS"

        ts = sm.rng.uniform(t0, t1)
        flow = sm._make_base_flow(vendor.ip, dst, proto, ts,
                                  src_role=vendor.device_role.value)
        flow["duration_ms"] = sm.rng.randint(500, 5000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(10, 50)
        flow["pkts_rev"] = sm.rng.randint(5, 30)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 800)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(100, 500)
        flow["remote_admin_flag"] = 1
        flow["zone_src"] = Zone.F.value
        flows.append(flow)
    return flows


def _a06_default_cred(sm, t0, t1, stage):
    """A06: Default credential login to patient monitor."""
    flows = []
    monitors = sm.network.get_assets_by_role(DeviceRole.PATIENT_MONITOR)
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    base_n = max(1, int(3 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(monitors) if monitors else sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        flow = sm._make_base_flow(src_ip, dst, "TCP", ts)
        flow["duration_ms"] = sm.rng.randint(200, 3000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(5, 15)
        flow["pkts_rev"] = sm.rng.randint(3, 10)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 400)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(100, 600)
        if stage == "login_attempt":
            flow["auth_attempts"] = 1
            flow["auth_failures"] = 0
        elif stage == "admin_session":
            flow["remote_admin_flag"] = 1
        elif stage == "device_query":
            flow["config_write_cnt"] = sm.rng.randint(1, 5)
            flow["remote_admin_flag"] = 1
        flows.append(flow)
    return flows


def _a07_hardcoded(sm, t0, t1, stage):
    """A07: Hard-coded credential abuse on ventilator."""
    flows = []
    vents = sm.network.get_assets_by_role(DeviceRole.VENTILATOR)
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    base_n = max(1, int(4 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(vents) if vents else sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        proto = sm.rng.choice(["SSH", "TCP"])
        flow = sm._make_base_flow(src_ip, dst, proto, ts)
        flow["duration_ms"] = sm.rng.randint(500, 5000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(5, 25)
        flow["pkts_rev"] = sm.rng.randint(3, 15)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 500)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(100, 400)
        flow["auth_attempts"] = 1
        flow["auth_failures"] = 0
        if stage == "config_rw":
            flow["config_write_cnt"] = sm.rng.randint(2, 10)
            flow["remote_admin_flag"] = 1
        flows.append(flow)
    return flows


def _a08_auth_bypass(sm, t0, t1, stage):
    """A08: Authentication bypass on imaging application."""
    flows = []
    base_n = max(2, int(8 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        ip = sm._get_attacker_ip(ts)
        flow = sm._make_base_flow(ip, dst, "HTTPS", ts)
        flow["duration_ms"] = sm.rng.randint(100, 2000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(5, 20)
        flow["pkts_rev"] = sm.rng.randint(3, 15)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 500)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(200, 1500)
        flow["tls_session"] = 1
        flow["http_status"] = 200
        flow["auth_attempts"] = 0
        if stage == "data_access":
            flow["dicom_query_cnt"] = sm.rng.randint(2, 10)
            flow["dicom_bytes"] = sm.rng.randint(50000, 500000)
        flows.append(flow)
    return flows


def _a09_replay(sm, t0, t1, stage):
    """A09: Replay-token attack on cardiology platform."""
    flows = []
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    base_n = max(2, int(6 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        flow = sm._make_base_flow(src_ip, dst, "HTTPS", ts)
        flow["duration_ms"] = sm.rng.randint(100, 1500)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(5, 15)
        flow["pkts_rev"] = sm.rng.randint(3, 12)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(200, 600)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(200, 800)
        flow["tls_session"] = 1
        flow["http_status"] = 200
        flow["auth_attempts"] = 0
        if stage == "token_replay":
            flow["fhir_read_cnt"] = sm.rng.randint(3, 15)
        flows.append(flow)
    return flows


def _a10_cleartext(sm, t0, t1, stage):
    """A10: Cleartext credential capture and reuse."""
    flows = []
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    base_n = max(1, int(4 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        proto = "HTTP" if stage == "sniff" else "HTTPS"
        flow = sm._make_base_flow(src_ip, dst, proto, ts)
        flow["duration_ms"] = sm.rng.randint(200, 2000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(4, 12)
        flow["pkts_rev"] = sm.rng.randint(3, 10)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 500)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(100, 400)
        flow["tls_session"] = 0 if stage == "sniff" else 1
        flow["auth_attempts"] = 1
        flow["auth_failures"] = 0
        flows.append(flow)
    return flows


def _a11_ble_replay(sm, t0, t1, stage):
    """A11: BLE telemetry sniff-and-replay."""
    flows = []
    ble_devices = (sm.network.get_assets_by_role(DeviceRole.WEARABLE) +
                   sm.network.get_assets_by_role(DeviceRole.BLE_GATEWAY))
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    base_n = max(2, int(10 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(ble_devices) if ble_devices else sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        flow = sm._make_base_flow(src_ip, dst, "BLE", ts)
        flow["duration_ms"] = sm.rng.randint(10, 500)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(2, 8)
        flow["pkts_rev"] = sm.rng.randint(0, 3)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(20, 100)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(20, 80)
        flow["ble_telemetry_cnt"] = sm.rng.randint(5, 30)
        flow["ble_replay_flag"] = 1 if stage == "ble_replay" else 0
        flows.append(flow)
    return flows


def _a12_firmware(sm, t0, t1, stage):
    """A12: Unauthorized firmware push / update tampering."""
    flows = []
    mgmt = sm.network.get_assets_by_role(DeviceRole.DEVICE_MGMT)
    src = mgmt[0] if mgmt else sm.network.assets[0]
    iomt_devices = (sm.network.get_assets_by_role(DeviceRole.PATIENT_MONITOR) +
                    sm.network.get_assets_by_role(DeviceRole.INFUSION_PUMP) +
                    sm.network.get_assets_by_role(DeviceRole.VENTILATOR))
    base_n = max(2, int(6 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(iomt_devices) if iomt_devices else sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        flow = sm._make_base_flow(src.ip, dst, "HTTPS", ts,
                                  src_role=src.device_role.value)
        flow["duration_ms"] = sm.rng.randint(2000, 15000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(50, 200)
        flow["pkts_rev"] = sm.rng.randint(10, 50)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(500, 1500)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(40, 200)
        flow["device_update_flag"] = 1
        flow["remote_admin_flag"] = 1
        if stage == "device_reboot":
            flow["reboot_flag"] = 1
        flows.append(flow)
    return flows


def _a13_dicom_discovery(sm, t0, t1, stage):
    """A13: DICOM study discovery / patient lookup abuse."""
    flows = []
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    base_n = max(3, int(15 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        flow = sm._make_base_flow(src_ip, dst, "DICOM", ts)
        flow["duration_ms"] = sm.rng.randint(100, 2000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(5, 20)
        flow["pkts_rev"] = sm.rng.randint(3, 15)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 400)
        flow["dicom_query_cnt"] = sm.rng.randint(3, 20)
        if stage == "data_fetch":
            flow["dicom_move_cnt"] = sm.rng.randint(1, 5)
            flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(500, 5000)
            flow["dicom_bytes"] = flow["bytes_rev"]
        else:
            flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(40, 200)
            flow["dicom_bytes"] = flow["bytes_fwd"] + flow["bytes_rev"]
        # Track discovered data
        sm._discovered_data += flow.get("dicom_bytes", 0)
        flows.append(flow)
    return flows


def _a14_dicom_exfil(sm, t0, t1, stage):
    """A14: Bulk DICOM/PACS image exfiltration with progressive data theft."""
    flows = []
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    base_n = max(3, int(12 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        ts = sm.rng.uniform(t0, t1)
        if stage == "exfil_external":
            dst = sm.rng.choice(sm.targets)
            flow = sm._make_base_flow(src_ip, dst, "HTTPS", ts)
            flow["bytes_fwd"] = sm.rng.randint(100000, 2000000)
            flow["bytes_rev"] = sm.rng.randint(500, 5000)
            flow["pkts_fwd"] = max(10, flow["bytes_fwd"] // 1400)
            flow["pkts_rev"] = sm.rng.randint(5, 20)
            flow["tls_session"] = 1
        else:
            dst = sm.rng.choice(sm.targets)
            flow = sm._make_base_flow(src_ip, dst, "DICOM", ts)
            flow["pkts_fwd"] = sm.rng.randint(10, 40)
            flow["pkts_rev"] = sm.rng.randint(20, 100)
            flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 400)
            flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(1000, 5000)
            flow["dicom_move_cnt"] = sm.rng.randint(3, 15)
            flow["dicom_store_cnt"] = sm.rng.randint(1, 5)
            flow["dicom_bytes"] = flow["bytes_rev"]
            flow["dicom_query_cnt"] = sm.rng.randint(1, 5)
        flow["duration_ms"] = sm.rng.randint(1000, 10000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        sm._discovered_data += flow.get("bytes_fwd", 0) + flow.get("bytes_rev", 0)
        flows.append(flow)
    return flows


def _a15_fhir_pull(sm, t0, t1, stage):
    """A15: FHIR / API bulk record pull."""
    flows = []
    base_n = max(3, int(20 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        ip = sm._get_attacker_ip(ts)
        flow = sm._make_base_flow(ip, dst, "HTTPS", ts)
        flow["duration_ms"] = sm.rng.randint(100, 1000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(3, 10)
        flow["pkts_rev"] = sm.rng.randint(5, 30)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 400)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(500, 5000)
        flow["fhir_read_cnt"] = sm.rng.randint(5, 50)
        flow["tls_session"] = 1
        flow["http_status"] = 200
        flows.append(flow)
    return flows


def _a16_hl7_flood(sm, t0, t1, stage):
    """A16: HL7 interface abuse / message flood."""
    flows = []
    base_n = max(5, int(25 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        flow = sm._make_base_flow(src_ip, dst, "HL7", ts)
        flow["duration_ms"] = sm.rng.randint(10, 500)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(5, 30)
        flow["pkts_rev"] = sm.rng.randint(2, 10)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(200, 1000)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(50, 200)
        flow["hl7_msg_cnt"] = sm.rng.randint(10, 100)
        flow["hl7_error_cnt"] = sm.rng.randint(2, 20) if stage == "error_gen" else 0
        flows.append(flow)
    return flows


def _a17_lateral(sm, t0, t1, stage):
    """A17: East-west pivot into clinical subnet with progressive compromise."""
    flows = []
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    clinical = (sm.network.get_assets_by_zone(Zone.C) +
                sm.network.get_assets_by_zone(Zone.D) +
                sm.network.get_assets_by_zone(Zone.E))
    base_n = max(2, int(8 * sm.intensity * (t1 - t0)))
    if sm.stealth:
        base_n = max(1, base_n // 2)
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)

    # Use compromised hosts as additional sources in later stages
    src_options = [src_ip] + sm._compromised_hosts[-3:]

    for _ in range(n):
        dst = sm.rng.choice(clinical) if clinical else sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        src = sm.rng.choice(src_options)
        proto = sm.rng.choice(["SMB", "RDP", "HTTPS"])
        flow = sm._make_base_flow(src, dst, proto, ts)
        flow["duration_ms"] = sm.rng.randint(200, 5000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(5, 30)
        flow["pkts_rev"] = sm.rng.randint(3, 20)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 800)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(100, 600)
        # Track compromised hosts
        if dst.ip not in sm._compromised_hosts and sm.rng.random() < 0.3:
            sm._compromised_hosts.append(dst.ip)
        flows.append(flow)
    return flows


def _a18_ransomware(sm, t0, t1, stage):
    """A18: Ransomware staging via SMB/RDP with progressive spread."""
    flows = []
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    base_n = max(3, int(15 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)

    # Spread from multiple compromised hosts
    src_options = [src_ip] + sm._compromised_hosts[-5:]

    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        src = sm.rng.choice(src_options)
        proto = "SMB" if stage in ("smb_enum", "admin_share") else sm.rng.choice(["SMB", "RDP"])
        flow = sm._make_base_flow(src, dst, proto, ts)
        flow["duration_ms"] = sm.rng.randint(200, 8000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(10, 60)
        flow["pkts_rev"] = sm.rng.randint(5, 30)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(200, 1500)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(100, 800)
        if stage == "admin_share":
            flow["remote_admin_flag"] = 1
        # Track spread
        if dst.ip not in sm._compromised_hosts:
            sm._compromised_hosts.append(dst.ip)
        flows.append(flow)
    return flows


def _a19_backup_delete(sm, t0, t1, stage):
    """A19: Backup discovery and deletion."""
    flows = []
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    backup = sm.network.get_assets_by_role(DeviceRole.BACKUP_SERVER)
    base_n = max(2, int(6 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(backup) if backup else sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        proto = sm.rng.choice(["SMB", "HTTPS"])
        flow = sm._make_base_flow(src_ip, dst, proto, ts)
        flow["duration_ms"] = sm.rng.randint(500, 5000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(5, 25)
        flow["pkts_rev"] = sm.rng.randint(3, 15)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 500)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(50, 300)
        if stage == "backup_delete":
            flow["backup_delete_flag"] = 1
            flow["remote_admin_flag"] = 1
        flows.append(flow)
    return flows


def _a20_phi_exfil(sm, t0, t1, stage):
    """A20: PHI exfiltration before extortion with progressive data staging."""
    flows = []
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    base_n = max(2, int(8 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        ts = sm.rng.uniform(t0, t1)
        if stage == "exfiltrate":
            dst = sm.rng.choice(sm.targets)
            flow = sm._make_base_flow(src_ip, dst, "HTTPS", ts)
            flow["bytes_fwd"] = sm.rng.randint(200000, 5000000)
            flow["pkts_fwd"] = max(20, flow["bytes_fwd"] // 1400)
            flow["bytes_rev"] = sm.rng.randint(500, 3000)
            flow["pkts_rev"] = sm.rng.randint(5, 15)
        else:
            dst = sm.rng.choice(sm.targets)
            proto = sm.rng.choice(["SMB", "HTTPS"])
            flow = sm._make_base_flow(src_ip, dst, proto, ts)
            flow["pkts_fwd"] = sm.rng.randint(10, 40)
            flow["pkts_rev"] = sm.rng.randint(10, 50)
            flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(200, 800)
            flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(500, 3000)
        flow["duration_ms"] = sm.rng.randint(1000, 15000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["tls_session"] = 1
        sm._discovered_data += flow.get("bytes_fwd", 0)
        flows.append(flow)
    return flows


def _a21_pacs_dos(sm, t0, t1, stage):
    """A21: Protocol-aware DoS on PACS with multiple attacker IPs."""
    flows = []
    base_n = max(10, int(50 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        ip = sm._get_attacker_ip(ts)
        proto = sm.rng.choice(["DICOM", "HTTPS"])
        flow = sm._make_base_flow(ip, dst, proto, ts)
        flow["duration_ms"] = sm.rng.randint(10, 500)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(20, 100)
        flow["pkts_rev"] = sm.rng.randint(1, 10)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(500, 1500)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(40, 100)
        flow["retrans_cnt"] = sm.rng.randint(2, 20)
        flow["rst_cnt"] = sm.rng.randint(1, 5)
        flow["syn_cnt"] = sm.rng.randint(3, 20)
        if proto == "DICOM":
            flow["dicom_query_cnt"] = sm.rng.randint(10, 50)
            flow["dicom_bytes"] = flow["bytes_fwd"]
        flows.append(flow)
    return flows


def _a22_app_flood(sm, t0, t1, stage):
    """A22: Application-layer flood on clinical portal."""
    flows = []
    base_n = max(10, int(60 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        ip = sm._get_attacker_ip(ts)
        flow = sm._make_base_flow(ip, dst, "HTTPS", ts)
        flow["duration_ms"] = sm.rng.randint(10, 300)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(3, 15)
        flow["pkts_rev"] = sm.rng.randint(1, 5)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(100, 800)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(40, 200)
        flow["tls_session"] = 1
        flow["http_status"] = sm.rng.choice([200, 429, 500, 502, 503, 503, 503])
        flow["syn_cnt"] = 1
        # Track total load for event generation
        sm._stage_progress["flood_requests"] = sm._stage_progress.get("flood_requests", 0) + 1
        flows.append(flow)
    return flows


def _a23_telemetry_spoof(sm, t0, t1, stage):
    """A23: Telemetry spoofing / manipulated patient data."""
    flows = []
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    base_n = max(3, int(12 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        proto = sm.rng.choice(["TCP", "BLE"])
        flow = sm._make_base_flow(src_ip, dst, proto, ts)
        flow["duration_ms"] = sm.rng.randint(50, 1000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(3, 15)
        flow["pkts_rev"] = sm.rng.randint(1, 5)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(50, 300)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(50, 200)
        flow["patient_value_jump_score"] = round(sm.rng.uniform(0.6, 1.0), 3)
        if proto == "BLE":
            flow["ble_telemetry_cnt"] = sm.rng.randint(5, 20)
        flows.append(flow)
    return flows


def _a24_unauth_config(sm, t0, t1, stage):
    """A24: Unauthorized config change on device management plane."""
    flows = []
    src_ip = sm._get_attacker_ip((t0 + t1) / 2.0)
    base_n = max(2, int(8 * sm.intensity * (t1 - t0)))
    n = sm._organic_flow_count(base_n, (t0 + t1) / 2.0)
    for _ in range(n):
        dst = sm.rng.choice(sm.targets)
        ts = sm.rng.uniform(t0, t1)
        proto = sm.rng.choice(["HTTPS", "SSH", "SNMP"])
        flow = sm._make_base_flow(src_ip, dst, proto, ts)
        flow["duration_ms"] = sm.rng.randint(100, 3000)
        flow["ts_end"] = round(ts + flow["duration_ms"] / 1000.0, 6)
        flow["pkts_fwd"] = sm.rng.randint(5, 20)
        flow["pkts_rev"] = sm.rng.randint(3, 10)
        flow["bytes_fwd"] = flow["pkts_fwd"] * sm.rng.randint(80, 300)
        flow["bytes_rev"] = flow["pkts_rev"] * sm.rng.randint(50, 200)
        flow["config_write_cnt"] = sm.rng.randint(3, 20)
        flow["remote_admin_flag"] = 1
        if stage == "behavior_drift":
            flow["patient_value_jump_score"] = round(sm.rng.uniform(0.3, 0.7), 3)
        flows.append(flow)
    return flows


# ──────────────────────────────────────────────────────────────────────
# Registry
# ──────────────────────────────────────────────────────────────────────
SCENARIO_GENERATORS = {
    "A01": _a01_recon, "A02": _a02_enum, "A03": _a03_spray,
    "A04": _a04_bruteforce, "A05": _a05_vendor_abuse, "A06": _a06_default_cred,
    "A07": _a07_hardcoded, "A08": _a08_auth_bypass, "A09": _a09_replay,
    "A10": _a10_cleartext, "A11": _a11_ble_replay, "A12": _a12_firmware,
    "A13": _a13_dicom_discovery, "A14": _a14_dicom_exfil, "A15": _a15_fhir_pull,
    "A16": _a16_hl7_flood, "A17": _a17_lateral, "A18": _a18_ransomware,
    "A19": _a19_backup_delete, "A20": _a20_phi_exfil, "A21": _a21_pacs_dos,
    "A22": _a22_app_flood, "A23": _a23_telemetry_spoof, "A24": _a24_unauth_config,
}
