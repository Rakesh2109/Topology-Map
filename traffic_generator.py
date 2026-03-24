"""
IoMT Medical NIDS Simulator — Traffic Generator (v2)
Generates realistic benign hospital network flows with:
- High-volume traffic (~100-300 flows per 5s window)
- DNS, ARP, SNMP, NTP background noise
- Diurnal patterns per device role
- Maintenance noise (patches, updates, logins)
- Organic variability with burst/pause cycles
"""

import math
import random
from typing import List, Dict, Optional, Tuple
from config import (
    Zone, DeviceRole, SimConfig, BASE_FLOW_FIELDS,
    MEDICAL_METADATA_FIELDS, LABEL_FIELDS
)
from network_model import HospitalNetwork, Asset


def _empty_flow() -> dict:
    """Return a flow record with all fields initialized to defaults."""
    flow = {}
    for f in BASE_FLOW_FIELDS:
        flow[f] = 0
    for f in MEDICAL_METADATA_FIELDS:
        flow[f] = 0
    for f in LABEL_FIELDS:
        flow[f] = "benign" if f == "label" else ""
    return flow


def _diurnal_factor(sim_time_s: float, role: DeviceRole) -> float:
    """
    Return a multiplier [0.1, 1.5] for traffic volume based on time-of-day
    and the device role. Simulates hospital business hours.
    """
    hour = (sim_time_s / 3600.0) % 24.0

    if role in (DeviceRole.CT_SCANNER, DeviceRole.MRI_SCANNER,
                DeviceRole.ULTRASOUND, DeviceRole.RAD_WORKSTATION,
                DeviceRole.DICOM_VIEWER):
        # Imaging peaks 8am-6pm
        if 8 <= hour <= 18:
            return 1.0 + 0.5 * math.sin(math.pi * (hour - 8) / 10)
        return 0.2

    if role in (DeviceRole.PATIENT_MONITOR, DeviceRole.VENTILATOR,
                DeviceRole.INFUSION_PUMP, DeviceRole.WEARABLE,
                DeviceRole.BLE_GATEWAY, DeviceRole.TELEMETRY_AGGREGATOR):
        # Telemetry: 24/7 with slight dip at 3am
        return 0.85 + 0.15 * math.sin(math.pi * (hour - 3) / 12)

    if role == DeviceRole.BACKUP_SERVER:
        # Backups cluster 1am-4am
        if 1 <= hour <= 4:
            return 1.5
        return 0.15

    if role in (DeviceRole.VENDOR_JUMPHOST, DeviceRole.VENDOR_VPN):
        # Vendor maintenance: sparse, business hours
        if 9 <= hour <= 17:
            return 0.4
        return 0.03

    if role in (DeviceRole.NURSE_STATION, DeviceRole.EHR_FRONTEND):
        # Clinical staff: peaks during day shifts
        if 7 <= hour <= 19:
            return 1.0 + 0.4 * math.sin(math.pi * (hour - 7) / 12)
        # Night shift — reduced but not zero
        return 0.35

    if role in (DeviceRole.AD_SERVER, DeviceRole.DNS_SERVER,
                DeviceRole.DHCP_SERVER, DeviceRole.SOC_COLLECTOR):
        # Infrastructure: always active
        return 0.8 + 0.2 * math.sin(math.pi * (hour - 6) / 12)

    # Default: moderate diurnal
    if 8 <= hour <= 18:
        return 0.9
    return 0.35


def _pick_proto(protocols: List[str], rng: random.Random) -> str:
    return rng.choice(protocols) if protocols else "TCP"


def _pick_port(proto: str, rng: random.Random) -> Tuple[int, int]:
    """Return (src_port, dst_port) based on protocol."""
    common_ports = {
        "HTTPS": 443, "HTTP": 80, "DICOM": 11112, "HL7": 2575,
        "FHIR": 443, "SSH": 22, "RDP": 3389, "SMB": 445,
        "LDAP": 389, "Kerberos": 88, "DNS": 53, "DHCP": 67,
        "Syslog": 514, "SNMP": 161, "VPN": 1194, "BLE": 0,
        "TCP": 8080, "CIFS": 445, "NTP": 123, "ARP": 0,
    }
    dst_port = common_ports.get(proto, rng.randint(1024, 65535))
    src_port = rng.randint(49152, 65535)
    return src_port, dst_port


class BenignTrafficGenerator:
    """Generates realistic benign hospital network traffic flows."""

    def __init__(self, network: HospitalNetwork, config: SimConfig):
        self.network = network
        self.config = config
        self.rng = random.Random(config.seed)
        self.start_hour = 8.0
        # Burst state for organic variability
        self._burst_phase = 0.0
        self._burst_rng = random.Random(config.seed + 7)

    def _burst_factor(self, t: float) -> float:
        """
        Generate organic burst/pause variability.
        Uses overlapping sine waves to create natural-looking traffic spikes.
        """
        f1 = 0.8 + 0.3 * math.sin(t * 0.05 + self._burst_phase)
        f2 = 0.9 + 0.15 * math.sin(t * 0.17 + 1.3)
        f3 = 0.95 + 0.1 * math.sin(t * 0.41 + 2.7)
        # Occasional random spike
        spike = 1.0
        if self._burst_rng.random() < 0.03:
            spike = self._burst_rng.uniform(1.5, 2.5)
        return f1 * f2 * f3 * spike

    def generate_flows(self, t_start: float, t_end: float,
                       start_hour: float = 8.0) -> List[dict]:
        """
        Generate all benign flows for the time interval [t_start, t_end].
        """
        flows = []
        dt = t_end - t_start

        # 1. Communication-map based traffic (clinical workflows)
        for src, dst, protocols, base_fph in self.network.get_comm_pairs():
            sim_time_s = start_hour * 3600 + (t_start + t_end) / 2.0
            diurnal = _diurnal_factor(sim_time_s, src.device_role)
            burst = self._burst_factor((t_start + t_end) / 2.0)

            # Flows per hour scaled by diurnal and burst
            expected = (base_fph / 3600.0) * dt * diurnal * burst
            n_flows = max(0, int(self.rng.gauss(expected, max(1, expected * 0.25))))

            for _ in range(n_flows):
                flow = self._make_flow(src, dst, protocols, t_start, t_end, sim_time_s)
                flows.append(flow)

        # 2. Infrastructure noise (DNS, NTP, SNMP, ARP)
        flows.extend(self._infrastructure_noise(t_start, t_end, start_hour))

        # 3. Maintenance events
        flows.extend(self._maintenance_noise(t_start, t_end, start_hour))

        # 4. Random clinical browsing / web traffic
        flows.extend(self._web_browsing_noise(t_start, t_end, start_hour))

        return flows

    def _make_flow(self, src: Asset, dst: Asset, protocols: List[str],
                   t_start: float, t_end: float, sim_time_s: float) -> dict:
        flow = _empty_flow()

        proto = _pick_proto(protocols, self.rng)
        src_port, dst_port = _pick_port(proto, self.rng)

        ts = self.rng.uniform(t_start, t_end)
        dur_ms = max(1, int(self.rng.expovariate(1.0 / 500.0)))
        if dur_ms > 30000:
            dur_ms = 30000

        pkts_fwd = max(1, int(self.rng.expovariate(1.0 / 8.0)))
        pkts_rev = max(1, int(self.rng.expovariate(1.0 / 6.0)))
        bytes_fwd = pkts_fwd * self.rng.randint(64, 1500)
        bytes_rev = pkts_rev * self.rng.randint(64, 1500)

        flow["ts_start"] = round(ts, 6)
        flow["ts_end"] = round(ts + dur_ms / 1000.0, 6)
        flow["src_ip"] = src.ip
        flow["dst_ip"] = dst.ip
        flow["src_port"] = src_port
        flow["dst_port"] = dst_port
        flow["proto"] = proto
        flow["direction"] = "fwd"
        flow["duration_ms"] = dur_ms
        flow["pkts_fwd"] = pkts_fwd
        flow["pkts_rev"] = pkts_rev
        flow["bytes_fwd"] = bytes_fwd
        flow["bytes_rev"] = bytes_rev
        flow["syn_cnt"] = 1 if proto not in ("BLE", "UDP", "DNS", "NTP", "ARP") else 0
        flow["rst_cnt"] = 0
        flow["psh_cnt"] = max(0, pkts_fwd - 1)
        flow["retrans_cnt"] = 0 if self.rng.random() > 0.02 else self.rng.randint(1, 3)
        flow["tls_session"] = 1 if proto in ("HTTPS", "VPN") else 0
        flow["http_status"] = self._gen_http_status(proto)
        flow["auth_attempts"] = 1 if proto in ("HTTPS", "SSH", "RDP", "LDAP") and self.rng.random() < 0.3 else 0
        flow["auth_failures"] = 0
        flow["app_service"] = proto
        flow["zone_src"] = src.zone.value
        flow["zone_dst"] = dst.zone.value
        flow["device_role_src"] = src.device_role.value
        flow["device_role_dst"] = dst.device_role.value

        # Medical metadata
        self._fill_medical_metadata(flow, proto, src, dst)

        return flow

    def _gen_http_status(self, proto: str) -> int:
        if proto not in ("HTTPS", "HTTP", "FHIR"):
            return 0
        r = self.rng.random()
        if r < 0.85:
            return 200
        elif r < 0.92:
            return 304
        elif r < 0.97:
            return 302
        else:
            return self.rng.choice([400, 401, 403, 404, 500])

    def _fill_medical_metadata(self, flow: dict, proto: str,
                               src: Asset, dst: Asset):
        """Fill protocol-specific medical metadata fields."""
        if proto == "DICOM":
            flow["dicom_query_cnt"] = self.rng.randint(0, 3)
            flow["dicom_store_cnt"] = self.rng.randint(0, 2)
            flow["dicom_move_cnt"] = self.rng.randint(0, 1)
            flow["dicom_bytes"] = flow["bytes_fwd"] + flow["bytes_rev"]

        elif proto == "HL7":
            flow["hl7_msg_cnt"] = self.rng.randint(1, 5)
            flow["hl7_error_cnt"] = 0 if self.rng.random() > 0.03 else 1

        elif proto in ("FHIR", "HTTPS") and dst.device_role == DeviceRole.FHIR_SERVER:
            flow["fhir_read_cnt"] = self.rng.randint(1, 4)
            flow["fhir_write_cnt"] = self.rng.randint(0, 1)

        elif proto == "BLE":
            flow["ble_telemetry_cnt"] = self.rng.randint(5, 30)
            flow["ble_replay_flag"] = 0

        if dst.device_role == DeviceRole.DEVICE_MGMT or src.device_role == DeviceRole.DEVICE_MGMT:
            flow["remote_admin_flag"] = 1
            flow["config_write_cnt"] = 0

        if src.device_role in (DeviceRole.VENDOR_JUMPHOST, DeviceRole.VENDOR_VPN):
            flow["remote_admin_flag"] = 1

    def _infrastructure_noise(self, t_start: float, t_end: float,
                              start_hour: float) -> List[dict]:
        """Generate DNS, NTP, SNMP, and ARP background traffic."""
        flows = []
        dt = t_end - t_start
        sim_time_s = start_hour * 3600 + (t_start + t_end) / 2.0

        # DNS queries — every device does ~2-6 DNS lookups per minute
        dns_server = self.network.get_assets_by_role(DeviceRole.DNS_SERVER)
        if dns_server:
            dns = dns_server[0]
            all_clients = [a for a in self.network.assets
                          if a.device_role != DeviceRole.DNS_SERVER]
            # Randomly pick clients that make DNS queries in this window
            n_dns = max(1, int(len(all_clients) * 0.3 * dt / 5.0
                               * _diurnal_factor(sim_time_s, DeviceRole.DNS_SERVER)))
            for _ in range(n_dns):
                client = self.rng.choice(all_clients)
                flow = _empty_flow()
                ts = self.rng.uniform(t_start, t_end)
                flow["ts_start"] = round(ts, 6)
                flow["ts_end"] = round(ts + self.rng.uniform(0.01, 0.1), 6)
                flow["src_ip"] = client.ip
                flow["dst_ip"] = dns.ip
                flow["src_port"] = self.rng.randint(49152, 65535)
                flow["dst_port"] = 53
                flow["proto"] = "DNS"
                flow["direction"] = "fwd"
                flow["duration_ms"] = self.rng.randint(5, 80)
                flow["pkts_fwd"] = 1
                flow["pkts_rev"] = 1
                flow["bytes_fwd"] = self.rng.randint(40, 120)
                flow["bytes_rev"] = self.rng.randint(60, 300)
                flow["zone_src"] = client.zone.value
                flow["zone_dst"] = dns.zone.value
                flow["device_role_src"] = client.device_role.value
                flow["device_role_dst"] = dns.device_role.value
                flow["app_service"] = "DNS"
                flows.append(flow)

        # SNMP polling — device management polls IoMT devices
        mgmt_list = self.network.get_assets_by_role(DeviceRole.DEVICE_MGMT)
        if mgmt_list:
            mgmt = mgmt_list[0]
            managed = (self.network.get_assets_by_role(DeviceRole.PATIENT_MONITOR) +
                      self.network.get_assets_by_role(DeviceRole.INFUSION_PUMP) +
                      self.network.get_assets_by_role(DeviceRole.VENTILATOR))
            # SNMP poll ~ every 30s per device
            n_snmp = max(0, int(len(managed) * dt / 30.0))
            for _ in range(n_snmp):
                dev = self.rng.choice(managed)
                flow = _empty_flow()
                ts = self.rng.uniform(t_start, t_end)
                flow["ts_start"] = round(ts, 6)
                flow["ts_end"] = round(ts + self.rng.uniform(0.05, 0.3), 6)
                flow["src_ip"] = mgmt.ip
                flow["dst_ip"] = dev.ip
                flow["src_port"] = self.rng.randint(49152, 65535)
                flow["dst_port"] = 161
                flow["proto"] = "SNMP"
                flow["direction"] = "fwd"
                flow["duration_ms"] = self.rng.randint(20, 200)
                flow["pkts_fwd"] = self.rng.randint(1, 3)
                flow["pkts_rev"] = self.rng.randint(1, 3)
                flow["bytes_fwd"] = self.rng.randint(50, 150)
                flow["bytes_rev"] = self.rng.randint(80, 400)
                flow["zone_src"] = mgmt.zone.value
                flow["zone_dst"] = dev.zone.value
                flow["device_role_src"] = mgmt.device_role.value
                flow["device_role_dst"] = dev.device_role.value
                flow["app_service"] = "SNMP"
                flow["remote_admin_flag"] = 1
                flows.append(flow)

        # NTP sync — periodic, every few minutes per device
        n_ntp = max(0, int(len(self.network.assets) * 0.05 * dt / 5.0))
        for _ in range(n_ntp):
            dev = self.rng.choice(self.network.assets)
            flow = _empty_flow()
            ts = self.rng.uniform(t_start, t_end)
            flow["ts_start"] = round(ts, 6)
            flow["ts_end"] = round(ts + 0.05, 6)
            flow["src_ip"] = dev.ip
            flow["dst_ip"] = "10.1.1.11"  # DNS server doubles as NTP
            flow["src_port"] = self.rng.randint(49152, 65535)
            flow["dst_port"] = 123
            flow["proto"] = "NTP"
            flow["direction"] = "fwd"
            flow["duration_ms"] = self.rng.randint(10, 60)
            flow["pkts_fwd"] = 1
            flow["pkts_rev"] = 1
            flow["bytes_fwd"] = 48
            flow["bytes_rev"] = 48
            flow["zone_src"] = dev.zone.value
            flow["zone_dst"] = Zone.B.value
            flow["device_role_src"] = dev.device_role.value
            flow["device_role_dst"] = DeviceRole.DNS_SERVER.value
            flow["app_service"] = "NTP"
            flows.append(flow)

        # Syslog from critical devices to SOC
        soc_list = self.network.get_assets_by_role(DeviceRole.SOC_COLLECTOR)
        if soc_list:
            soc = soc_list[0]
            critical = [a for a in self.network.assets if a.criticality >= 8]
            n_syslog = max(0, int(len(critical) * 0.2 * dt / 5.0))
            for _ in range(n_syslog):
                dev = self.rng.choice(critical)
                flow = _empty_flow()
                ts = self.rng.uniform(t_start, t_end)
                flow["ts_start"] = round(ts, 6)
                flow["ts_end"] = round(ts + self.rng.uniform(0.01, 0.1), 6)
                flow["src_ip"] = dev.ip
                flow["dst_ip"] = soc.ip
                flow["src_port"] = self.rng.randint(49152, 65535)
                flow["dst_port"] = 514
                flow["proto"] = "Syslog"
                flow["direction"] = "fwd"
                flow["duration_ms"] = self.rng.randint(5, 50)
                flow["pkts_fwd"] = 1
                flow["pkts_rev"] = 0
                flow["bytes_fwd"] = self.rng.randint(100, 600)
                flow["bytes_rev"] = 0
                flow["zone_src"] = dev.zone.value
                flow["zone_dst"] = soc.zone.value
                flow["device_role_src"] = dev.device_role.value
                flow["device_role_dst"] = soc.device_role.value
                flow["app_service"] = "Syslog"
                flows.append(flow)

        return flows

    def _web_browsing_noise(self, t_start: float, t_end: float,
                            start_hour: float) -> List[dict]:
        """Nurse stations and workstations browsing clinical portals, EHR lookups."""
        flows = []
        dt = t_end - t_start
        sim_time_s = start_hour * 3600 + (t_start + t_end) / 2.0
        hour = (sim_time_s / 3600.0) % 24.0

        if hour < 6 or hour > 22:
            return flows  # Minimal at night

        browsers = (self.network.get_assets_by_role(DeviceRole.NURSE_STATION) +
                   self.network.get_assets_by_role(DeviceRole.RAD_WORKSTATION))
        web_targets = (self.network.get_assets_by_role(DeviceRole.WEB_PORTAL) +
                      self.network.get_assets_by_role(DeviceRole.EHR_FRONTEND) +
                      self.network.get_assets_by_role(DeviceRole.FHIR_SERVER))

        if not browsers or not web_targets:
            return flows

        diurnal = _diurnal_factor(sim_time_s, DeviceRole.NURSE_STATION)
        n_browse = max(0, int(len(browsers) * 0.5 * dt / 5.0 * diurnal))

        for _ in range(n_browse):
            src = self.rng.choice(browsers)
            dst = self.rng.choice(web_targets)
            flow = _empty_flow()
            ts = self.rng.uniform(t_start, t_end)
            flow["ts_start"] = round(ts, 6)
            flow["ts_end"] = round(ts + self.rng.uniform(0.1, 3.0), 6)
            flow["src_ip"] = src.ip
            flow["dst_ip"] = dst.ip
            flow["src_port"] = self.rng.randint(49152, 65535)
            flow["dst_port"] = 443
            flow["proto"] = "HTTPS"
            flow["direction"] = "fwd"
            flow["duration_ms"] = self.rng.randint(100, 3000)
            flow["pkts_fwd"] = self.rng.randint(3, 15)
            flow["pkts_rev"] = self.rng.randint(3, 20)
            flow["bytes_fwd"] = flow["pkts_fwd"] * self.rng.randint(100, 500)
            flow["bytes_rev"] = flow["pkts_rev"] * self.rng.randint(200, 3000)
            flow["tls_session"] = 1
            flow["http_status"] = self._gen_http_status("HTTPS")
            flow["syn_cnt"] = 1
            flow["zone_src"] = src.zone.value
            flow["zone_dst"] = dst.zone.value
            flow["device_role_src"] = src.device_role.value
            flow["device_role_dst"] = dst.device_role.value
            flow["app_service"] = "HTTPS"
            if dst.device_role == DeviceRole.FHIR_SERVER:
                flow["fhir_read_cnt"] = self.rng.randint(1, 3)
            flows.append(flow)

        return flows

    def _maintenance_noise(self, t_start: float, t_end: float,
                           start_hour: float) -> List[dict]:
        """Inject benign maintenance events: patches, updates, logins, backup sync."""
        noise_flows = []
        dt = t_end - t_start
        sim_time_s = start_hour * 3600 + (t_start + t_end) / 2.0
        hour = (sim_time_s / 3600.0) % 24.0

        # Software update checks (device mgmt -> internet)
        if self.rng.random() < 0.15 * (dt / 5.0):
            gw = self.network.get_assets_by_role(DeviceRole.GATEWAY)
            mgmt = self.network.get_assets_by_role(DeviceRole.DEVICE_MGMT)
            if gw and mgmt:
                flow = _empty_flow()
                flow["ts_start"] = round(self.rng.uniform(t_start, t_end), 6)
                flow["ts_end"] = round(flow["ts_start"] + self.rng.uniform(1, 5), 6)
                flow["src_ip"] = mgmt[0].ip
                flow["dst_ip"] = gw[0].ip
                flow["src_port"] = self.rng.randint(49152, 65535)
                flow["dst_port"] = 443
                flow["proto"] = "HTTPS"
                flow["direction"] = "fwd"
                flow["duration_ms"] = self.rng.randint(1000, 5000)
                flow["pkts_fwd"] = self.rng.randint(5, 20)
                flow["pkts_rev"] = self.rng.randint(5, 20)
                flow["bytes_fwd"] = flow["pkts_fwd"] * self.rng.randint(200, 800)
                flow["bytes_rev"] = flow["pkts_rev"] * self.rng.randint(200, 1200)
                flow["tls_session"] = 1
                flow["http_status"] = 200
                flow["zone_src"] = Zone.C.value
                flow["zone_dst"] = Zone.A.value
                flow["device_role_src"] = DeviceRole.DEVICE_MGMT.value
                flow["device_role_dst"] = DeviceRole.GATEWAY.value
                flow["device_update_flag"] = 1
                flow["app_service"] = "HTTPS"
                noise_flows.append(flow)

        # Backup sync (night hours)
        if 1 <= hour <= 5 and self.rng.random() < 0.3 * (dt / 5.0):
            backup = self.network.get_assets_by_role(DeviceRole.BACKUP_SERVER)
            fshare = self.network.get_assets_by_role(DeviceRole.FILE_SHARE)
            if backup and fshare:
                flow = _empty_flow()
                flow["ts_start"] = round(self.rng.uniform(t_start, t_end), 6)
                flow["ts_end"] = round(flow["ts_start"] + self.rng.uniform(2, 10), 6)
                flow["src_ip"] = backup[0].ip
                flow["dst_ip"] = fshare[0].ip
                flow["src_port"] = self.rng.randint(49152, 65535)
                flow["dst_port"] = 445
                flow["proto"] = "SMB"
                flow["direction"] = "fwd"
                flow["duration_ms"] = self.rng.randint(2000, 15000)
                flow["pkts_fwd"] = self.rng.randint(20, 80)
                flow["pkts_rev"] = self.rng.randint(20, 80)
                flow["bytes_fwd"] = flow["pkts_fwd"] * self.rng.randint(500, 1500)
                flow["bytes_rev"] = flow["pkts_rev"] * self.rng.randint(500, 1500)
                flow["syn_cnt"] = 1
                flow["zone_src"] = Zone.B.value
                flow["zone_dst"] = Zone.B.value
                flow["device_role_src"] = DeviceRole.BACKUP_SERVER.value
                flow["device_role_dst"] = DeviceRole.FILE_SHARE.value
                flow["app_service"] = "SMB"
                noise_flows.append(flow)

        # Clinician logins
        if self.rng.random() < 0.25 * (dt / 5.0) and 7 <= hour <= 20:
            ns = self.network.get_random_asset(role=DeviceRole.NURSE_STATION)
            ad = self.network.get_random_asset(role=DeviceRole.AD_SERVER)
            if ns and ad:
                flow = _empty_flow()
                flow["ts_start"] = round(self.rng.uniform(t_start, t_end), 6)
                flow["ts_end"] = round(flow["ts_start"] + self.rng.uniform(0.2, 1.0), 6)
                flow["src_ip"] = ns.ip
                flow["dst_ip"] = ad.ip
                flow["src_port"] = self.rng.randint(49152, 65535)
                flow["dst_port"] = 389
                flow["proto"] = "LDAP"
                flow["direction"] = "fwd"
                flow["duration_ms"] = self.rng.randint(100, 800)
                flow["pkts_fwd"] = self.rng.randint(3, 8)
                flow["pkts_rev"] = self.rng.randint(2, 6)
                flow["bytes_fwd"] = flow["pkts_fwd"] * self.rng.randint(100, 300)
                flow["bytes_rev"] = flow["pkts_rev"] * self.rng.randint(100, 500)
                flow["auth_attempts"] = 1
                flow["auth_failures"] = 0
                flow["syn_cnt"] = 1
                flow["zone_src"] = ns.zone.value
                flow["zone_dst"] = ad.zone.value
                flow["device_role_src"] = ns.device_role.value
                flow["device_role_dst"] = ad.device_role.value
                flow["app_service"] = "LDAP"
                noise_flows.append(flow)

        # Vendor scheduled maintenance (rare, business hours)
        if 10 <= hour <= 16 and self.rng.random() < 0.02 * (dt / 5.0):
            vjh = self.network.get_random_asset(role=DeviceRole.VENDOR_JUMPHOST)
            mgmt = self.network.get_random_asset(role=DeviceRole.DEVICE_MGMT)
            if vjh and mgmt:
                flow = _empty_flow()
                flow["ts_start"] = round(self.rng.uniform(t_start, t_end), 6)
                flow["ts_end"] = round(flow["ts_start"] + self.rng.uniform(5, 30), 6)
                flow["src_ip"] = vjh.ip
                flow["dst_ip"] = mgmt.ip
                flow["src_port"] = self.rng.randint(49152, 65535)
                flow["dst_port"] = 22
                flow["proto"] = "SSH"
                flow["direction"] = "fwd"
                flow["duration_ms"] = self.rng.randint(5000, 30000)
                flow["pkts_fwd"] = self.rng.randint(20, 80)
                flow["pkts_rev"] = self.rng.randint(15, 60)
                flow["bytes_fwd"] = flow["pkts_fwd"] * self.rng.randint(100, 400)
                flow["bytes_rev"] = flow["pkts_rev"] * self.rng.randint(100, 500)
                flow["syn_cnt"] = 1
                flow["remote_admin_flag"] = 1
                flow["zone_src"] = Zone.F.value
                flow["zone_dst"] = Zone.C.value
                flow["device_role_src"] = DeviceRole.VENDOR_JUMPHOST.value
                flow["device_role_dst"] = DeviceRole.DEVICE_MGMT.value
                flow["app_service"] = "SSH"
                noise_flows.append(flow)

        return noise_flows
