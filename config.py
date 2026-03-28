"""
IoMT Medical NIDS Simulator — Configuration & Data Models
Defines environment profiles, attack scenario registry (A01-A24),
field schemas, and simulation parameters.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum
import json


# ──────────────────────────────────────────────────────────────────────
# Zone Definitions
# ──────────────────────────────────────────────────────────────────────
class Zone(str, Enum):
    A = "zone_a"  # Internet / vendor cloud / telehealth / remote access
    B = "zone_b"  # Enterprise IT: AD, DNS, DHCP, EHR, file shares, backup
    C = "zone_c"  # Clinical core: PACS, VNA, RIS, LIS, FHIR, HL7, nurse stations
    D = "zone_d"  # Imaging subnet: CT, MRI, US, radiology WS, DICOM viewer
    E = "zone_e"  # IoMT subnet: monitors, infusion, ventilators, BLE/Wi-Fi GW
    F = "zone_f"  # Third-party support: vendor VPN / jump host


ZONE_SUBNETS = {
    Zone.A: "203.0.113.0/24",
    Zone.B: "10.1.0.0/16",
    Zone.C: "10.2.0.0/16",
    Zone.D: "10.3.0.0/16",
    Zone.E: "10.4.0.0/16",
    Zone.F: "10.5.0.0/24",
}


# ──────────────────────────────────────────────────────────────────────
# Device Roles
# ──────────────────────────────────────────────────────────────────────
class DeviceRole(str, Enum):
    GATEWAY = "gateway"
    FIREWALL = "firewall"
    AD_SERVER = "ad_server"
    DNS_SERVER = "dns_server"
    DHCP_SERVER = "dhcp_server"
    EHR_FRONTEND = "ehr_frontend"
    FILE_SHARE = "file_share"
    BACKUP_SERVER = "backup_server"
    SOC_COLLECTOR = "soc_collector"
    PACS_SERVER = "pacs_server"
    VNA = "vna"
    RIS = "ris"
    LIS = "lis"
    FHIR_SERVER = "fhir_server"
    HL7_ENGINE = "hl7_engine"
    NURSE_STATION = "nurse_station"
    DEVICE_MGMT = "device_mgmt_server"
    CT_SCANNER = "ct_scanner"
    MRI_SCANNER = "mri_scanner"
    ULTRASOUND = "ultrasound"
    RAD_WORKSTATION = "rad_workstation"
    DICOM_VIEWER = "dicom_viewer"
    IMAGING_ARCHIVE_GW = "imaging_archive_gw"
    PATIENT_MONITOR = "patient_monitor"
    INFUSION_PUMP = "infusion_pump"
    VENTILATOR = "ventilator"
    MOBILE_MEDICAL_APP = "mobile_medical_app"
    BLE_GATEWAY = "ble_gateway"
    WIFI_GATEWAY = "wifi_gateway"
    TELEMETRY_AGGREGATOR = "telemetry_aggregator"
    VENDOR_VPN = "vendor_vpn"
    VENDOR_JUMPHOST = "vendor_jumphost"
    WEB_PORTAL = "web_portal"
    EXTERNAL_ATTACKER = "external_attacker"
    WEARABLE = "wearable"


# ──────────────────────────────────────────────────────────────────────
# Asset Definition
# ──────────────────────────────────────────────────────────────────────
@dataclass
class AssetDef:
    name: str
    zone: Zone
    ip: str
    device_role: DeviceRole
    protocols: List[str]
    criticality: int  # 1-10
    internet_exposed: bool = False


# ──────────────────────────────────────────────────────────────────────
# Medium Hospital Environment Profile
# ──────────────────────────────────────────────────────────────────────
MEDIUM_HOSPITAL_ASSETS: List[AssetDef] = [
    # Zone A — Internet / Edge
    AssetDef("gw-edge-01", Zone.A, "203.0.113.1", DeviceRole.GATEWAY, ["HTTPS", "VPN"], 9, True),
    AssetDef("fw-perimeter-01", Zone.A, "203.0.113.2", DeviceRole.FIREWALL, ["HTTPS"], 10, True),
    AssetDef("web-portal-01", Zone.A, "203.0.113.10", DeviceRole.WEB_PORTAL, ["HTTPS", "HTTP"], 7, True),

    # Zone B — Enterprise IT
    AssetDef("ad-server-01", Zone.B, "10.1.1.10", DeviceRole.AD_SERVER, ["LDAP", "Kerberos", "SMB"], 10, False),
    AssetDef("dns-server-01", Zone.B, "10.1.1.11", DeviceRole.DNS_SERVER, ["DNS"], 8, False),
    AssetDef("dhcp-server-01", Zone.B, "10.1.1.12", DeviceRole.DHCP_SERVER, ["DHCP"], 6, False),
    AssetDef("ehr-frontend-01", Zone.B, "10.1.2.10", DeviceRole.EHR_FRONTEND, ["HTTPS", "HL7"], 9, False),
    AssetDef("file-share-01", Zone.B, "10.1.3.10", DeviceRole.FILE_SHARE, ["SMB", "CIFS"], 7, False),
    AssetDef("backup-server-01", Zone.B, "10.1.3.20", DeviceRole.BACKUP_SERVER, ["SMB", "HTTPS"], 9, False),
    AssetDef("soc-collector-01", Zone.B, "10.1.4.10", DeviceRole.SOC_COLLECTOR, ["Syslog", "HTTPS"], 8, False),

    # Zone C — Clinical Core
    AssetDef("pacs-server-01", Zone.C, "10.2.1.10", DeviceRole.PACS_SERVER, ["DICOM", "HTTPS"], 10, False),
    AssetDef("vna-01", Zone.C, "10.2.1.20", DeviceRole.VNA, ["DICOM", "HTTPS"], 9, False),
    AssetDef("ris-01", Zone.C, "10.2.1.30", DeviceRole.RIS, ["HL7", "HTTPS"], 8, False),
    AssetDef("lis-01", Zone.C, "10.2.1.40", DeviceRole.LIS, ["HL7", "HTTPS"], 8, False),
    AssetDef("fhir-server-01", Zone.C, "10.2.2.10", DeviceRole.FHIR_SERVER, ["HTTPS", "FHIR"], 9, True),
    AssetDef("hl7-engine-01", Zone.C, "10.2.2.20", DeviceRole.HL7_ENGINE, ["HL7", "TCP"], 9, False),
    AssetDef("nurse-station-01", Zone.C, "10.2.3.10", DeviceRole.NURSE_STATION, ["HTTPS", "RDP"], 6, False),
    AssetDef("nurse-station-02", Zone.C, "10.2.3.11", DeviceRole.NURSE_STATION, ["HTTPS", "RDP"], 6, False),
    AssetDef("device-mgmt-01", Zone.C, "10.2.4.10", DeviceRole.DEVICE_MGMT, ["HTTPS", "SSH", "SNMP"], 9, False),

    # Zone D — Imaging Subnet
    AssetDef("ct-scanner-01", Zone.D, "10.3.1.10", DeviceRole.CT_SCANNER, ["DICOM"], 10, False),
    AssetDef("mri-scanner-01", Zone.D, "10.3.1.20", DeviceRole.MRI_SCANNER, ["DICOM"], 10, False),
    AssetDef("ultrasound-01", Zone.D, "10.3.1.30", DeviceRole.ULTRASOUND, ["DICOM"], 8, False),
    AssetDef("rad-ws-01", Zone.D, "10.3.2.10", DeviceRole.RAD_WORKSTATION, ["DICOM", "HTTPS", "RDP"], 7, False),
    AssetDef("rad-ws-02", Zone.D, "10.3.2.11", DeviceRole.RAD_WORKSTATION, ["DICOM", "HTTPS", "RDP"], 7, False),
    AssetDef("dicom-viewer-01", Zone.D, "10.3.3.10", DeviceRole.DICOM_VIEWER, ["DICOM", "HTTPS"], 7, False),
    AssetDef("img-archive-gw-01", Zone.D, "10.3.3.20", DeviceRole.IMAGING_ARCHIVE_GW, ["DICOM", "HTTPS"], 8, False),

    # Zone E — IoMT Subnet
    AssetDef("patient-mon-01", Zone.E, "10.4.1.10", DeviceRole.PATIENT_MONITOR, ["BLE", "TCP"], 9, False),
    AssetDef("patient-mon-02", Zone.E, "10.4.1.11", DeviceRole.PATIENT_MONITOR, ["BLE", "TCP"], 9, False),
    AssetDef("patient-mon-03", Zone.E, "10.4.1.12", DeviceRole.PATIENT_MONITOR, ["BLE", "TCP"], 9, False),
    AssetDef("infusion-pump-01", Zone.E, "10.4.2.10", DeviceRole.INFUSION_PUMP, ["TCP", "HTTPS"], 10, False),
    AssetDef("infusion-pump-02", Zone.E, "10.4.2.11", DeviceRole.INFUSION_PUMP, ["TCP", "HTTPS"], 10, False),
    AssetDef("ventilator-01", Zone.E, "10.4.3.10", DeviceRole.VENTILATOR, ["TCP", "SSH"], 10, False),
    AssetDef("ventilator-02", Zone.E, "10.4.3.11", DeviceRole.VENTILATOR, ["TCP", "SSH"], 10, False),
    AssetDef("mobile-med-app-01", Zone.E, "10.4.4.10", DeviceRole.MOBILE_MEDICAL_APP, ["HTTPS", "BLE"], 6, False),
    AssetDef("ble-gw-01", Zone.E, "10.4.5.10", DeviceRole.BLE_GATEWAY, ["BLE", "TCP"], 7, False),
    AssetDef("wifi-gw-01", Zone.E, "10.4.5.20", DeviceRole.WIFI_GATEWAY, ["TCP", "HTTPS"], 7, False),
    AssetDef("telemetry-agg-01", Zone.E, "10.4.6.10", DeviceRole.TELEMETRY_AGGREGATOR, ["TCP", "HTTPS", "BLE"], 8, False),
    AssetDef("wearable-01", Zone.E, "10.4.7.10", DeviceRole.WEARABLE, ["BLE"], 6, False),
    AssetDef("wearable-02", Zone.E, "10.4.7.11", DeviceRole.WEARABLE, ["BLE"], 6, False),

    # Zone F — Third-Party Support
    AssetDef("vendor-vpn-01", Zone.F, "10.5.0.10", DeviceRole.VENDOR_VPN, ["VPN", "HTTPS"], 7, False),
    AssetDef("vendor-jumphost-01", Zone.F, "10.5.0.20", DeviceRole.VENDOR_JUMPHOST, ["SSH", "RDP", "HTTPS"], 7, False),
]


# ──────────────────────────────────────────────────────────────────────
# Attack Scenario Definitions (A01-A24)
# ──────────────────────────────────────────────────────────────────────
@dataclass
class AttackStage:
    name: str
    duration_frac: float  # fraction of total attack_duration
    description: str


@dataclass
class AttackScenario:
    scenario_id: str
    label: str
    attack_path: str
    primary_target: str
    target_roles: List[DeviceRole]
    affected_protocols: List[str]
    entry_point: str
    target_asset: str
    default_intensity: float
    default_stealth: bool
    stages: List[AttackStage]
    signature_description: str


ATTACK_SCENARIOS: Dict[str, AttackScenario] = {}

def _register(s: AttackScenario):
    ATTACK_SCENARIOS[s.scenario_id] = s

# A01 — External recon on hospital edge
_register(AttackScenario(
    "A01", "external_recon", "Internet", "Gateway, PACS web, FHIR, VPN",
    [DeviceRole.GATEWAY, DeviceRole.WEB_PORTAL, DeviceRole.FHIR_SERVER, DeviceRole.VENDOR_VPN],
    ["HTTPS", "TCP"],
    "internet",
    "pacs_server_01",
    0.5, False,
    [AttackStage("port_scan", 0.6, "Short flows to many hosts/ports"),
     AttackStage("service_probe", 0.4, "Service identification probes")],
    "Short flows to many hosts/ports, high unique_dst_ip and unique_dst_port, low bytes/flow"
))

# A02 — Service enumeration of clinical web apps
_register(AttackScenario(
    "A02", "service_enumeration", "Internet", "PACS, Synapse, web portals",
    [DeviceRole.PACS_SERVER, DeviceRole.WEB_PORTAL],
    ["HTTPS", "HTTP"],
    "internet",
    "web_portal_01",
    0.6, False,
    [AttackStage("path_discovery", 0.5, "HTTP requests across admin paths"),
     AttackStage("service_fingerprint", 0.5, "Moderate request bursts to identified services")],
    "Repeated HTTP(S) hits across admin paths, moderate request bursts, small responses"
))

# A03 — Password spraying against VPN/portal
_register(AttackScenario(
    "A03", "password_spraying", "Internet", "Remote access gateway",
    [DeviceRole.GATEWAY, DeviceRole.VENDOR_VPN],
    ["HTTPS", "VPN"],
    "internet",
    "gw_edge_01",
    0.4, True,
    [AttackStage("spray_attempt", 0.8, "Low-rate repeated login attempts across usernames"),
     AttackStage("cooldown", 0.2, "Brief pause before next round")],
    "Low-rate repeated login attempts across many usernames, failures dominate, source IP reuse"
))

# A04 — Brute force against PACS / imaging portal
_register(AttackScenario(
    "A04", "brute_force_pacs", "Internet", "Imaging portal",
    [DeviceRole.PACS_SERVER, DeviceRole.WEB_PORTAL],
    ["HTTPS", "DICOM"],
    "internet",
    "pacs_server_01",
    0.8, False,
    [AttackStage("bruteforce", 0.9, "High rate repeated auth failures"),
     AttackStage("success_check", 0.1, "Check for successful login")],
    "Higher request rate, repeated auth failures, one or two usernames targeted"
))

# A05 — Third-party remote support abuse
_register(AttackScenario(
    "A05", "vendor_support_abuse", "Compromised vendor path", "Vendor jump host -> clinical zone",
    [DeviceRole.VENDOR_JUMPHOST, DeviceRole.NURSE_STATION, DeviceRole.DEVICE_MGMT],
    ["SSH", "RDP", "HTTPS"],
    "vendor_vpn",
    "vendor_jumphost_01",
    0.6, True,
    [AttackStage("vendor_access", 0.3, "New remote-admin session from vendor IP"),
     AttackStage("internal_pivot", 0.5, "Pivot from jump host into clinical zone"),
     AttackStage("data_access", 0.2, "Access clinical systems")],
    "New remote-admin sessions, off-hours access, unusual vendor IP, sudden internal pivot"
))

# A06 — Default credential login to patient monitor
_register(AttackScenario(
    "A06", "default_cred_monitor", "Internal / physical foothold", "Patient monitor / bedside device",
    [DeviceRole.PATIENT_MONITOR],
    ["TCP", "HTTPS"],
    "iomt_subnet",
    "patient_mon_01",
    0.5, True,
    [AttackStage("login_attempt", 0.2, "Minimal login attempts with default credentials"),
     AttackStage("admin_session", 0.5, "Successful admin session established"),
     AttackStage("device_query", 0.3, "Device management queries follow")],
    "Immediate successful admin session after minimal attempts; device management queries follow"
))

# A07 — Hard-coded credential abuse on ventilator
_register(AttackScenario(
    "A07", "hardcoded_cred_abuse", "Internal / mobile foothold",
    "Ventilator, mobile logic app, service interface",
    [DeviceRole.VENTILATOR, DeviceRole.MOBILE_MEDICAL_APP],
    ["TCP", "SSH", "HTTPS"],
    "iomt_subnet",
    "ventilator_01",
    0.5, True,
    [AttackStage("priv_access", 0.3, "Privileged access without normal auth pattern"),
     AttackStage("config_rw", 0.7, "Config reads/writes follow")],
    "Successful privileged access without normal auth pattern, config reads/writes follow"
))

# A08 — Authentication bypass on imaging application
_register(AttackScenario(
    "A08", "auth_bypass_imaging", "Internet or internal", "Synapse/medical imaging app",
    [DeviceRole.PACS_SERVER, DeviceRole.DICOM_VIEWER],
    ["HTTPS", "DICOM"],
    "internet",
    "pacs_server_01",
    0.6, False,
    [AttackStage("bypass_exploit", 0.4, "Privileged resource access without prior login"),
     AttackStage("role_escalation", 0.3, "Abnormal role escalation"),
     AttackStage("data_access", 0.3, "Access restricted imaging data")],
    "Privileged resource access without prior login sequence, abnormal role escalation"
))

# A09 — Replay-token attack on cardiology platform
_register(AttackScenario(
    "A09", "replay_token_attack", "Internal / compromised endpoint", "Clinical application",
    [DeviceRole.EHR_FRONTEND, DeviceRole.FHIR_SERVER],
    ["HTTPS"],
    "clinical_subnet",
    "ehr_frontend_01",
    0.5, True,
    [AttackStage("token_capture", 0.3, "Capture auth token/session identifier"),
     AttackStage("token_replay", 0.7, "Reused token from different client context")],
    "Reused auth token/session identifier, repeated access from shifted client context"
))

# A10 — Cleartext credential capture and reuse
_register(AttackScenario(
    "A10", "cleartext_cred_capture", "Internal same subnet", "Web portal / mobile app",
    [DeviceRole.WEB_PORTAL, DeviceRole.MOBILE_MEDICAL_APP],
    ["HTTP", "TCP"],
    "internal_subnet",
    "web_portal_01",
    0.5, True,
    [AttackStage("sniff", 0.4, "Cleartext auth exchange captured"),
     AttackStage("reuse", 0.6, "Successful reuse from another source")],
    "First cleartext auth exchange, then successful reuse from another source; low crypto indicators"
))

# A11 — BLE telemetry sniff-and-replay
_register(AttackScenario(
    "A11", "ble_replay", "Near-device attacker", "Wearable / BLE medical device",
    [DeviceRole.WEARABLE, DeviceRole.BLE_GATEWAY, DeviceRole.PATIENT_MONITOR],
    ["BLE"],
    "iomt_subnet",
    "wearable_01",
    0.5, True,
    [AttackStage("ble_sniff", 0.4, "BLE packet capture"),
     AttackStage("ble_replay", 0.6, "Duplicate message timings, repeated sequence behavior")],
    "Duplicate message timings, repeated sequence behavior, telemetry integrity anomaly"
))

# A12 — Unauthorized firmware push / update tampering
_register(AttackScenario(
    "A12", "firmware_tampering", "Internal privileged access", "IoMT device fleet",
    [DeviceRole.DEVICE_MGMT, DeviceRole.PATIENT_MONITOR, DeviceRole.INFUSION_PUMP, DeviceRole.VENTILATOR],
    ["HTTPS", "TCP", "SSH"],
    "clinical_subnet",
    "device_mgmt_01",
    0.7, False,
    [AttackStage("update_push", 0.5, "Large management transfers to devices"),
     AttackStage("device_reboot", 0.3, "Device reboot and reconnect wave"),
     AttackStage("verify", 0.2, "Verify firmware applied")],
    "Large management transfers, update endpoint traffic, device reboot silence or reconnect wave"
))

# A13 — DICOM study discovery / patient lookup abuse
_register(AttackScenario(
    "A13", "dicom_discovery", "Compromised workstation", "PACS / archive",
    [DeviceRole.PACS_SERVER, DeviceRole.IMAGING_ARCHIVE_GW],
    ["DICOM"],
    "imaging_subnet",
    "pacs_server_01",
    0.6, True,
    [AttackStage("cfind_queries", 0.6, "Spike in DICOM C-FIND queries"),
     AttackStage("data_fetch", 0.4, "Low initial bytes then larger fetches")],
    "Spike in DICOM query/retrieve, many C-FIND-like queries, low initial bytes then larger fetches"
))

# A14 — Bulk DICOM/PACS image exfiltration
_register(AttackScenario(
    "A14", "dicom_exfiltration", "Compromised radiology host", "PACS / viewer / archive",
    [DeviceRole.PACS_SERVER, DeviceRole.DICOM_VIEWER, DeviceRole.IMAGING_ARCHIVE_GW],
    ["DICOM", "HTTPS"],
    "imaging_subnet",
    "pacs_server_01",
    0.7, False,
    [AttackStage("study_enum", 0.2, "Enumerate available studies"),
     AttackStage("bulk_transfer", 0.6, "Sustained large DICOM transfers"),
     AttackStage("exfil_external", 0.2, "Outbound bytes surge to unusual peer")],
    "Sustained large DICOM bytes to unusual peer, many study moves, outbound bytes surge"
))

# A15 — FHIR / API bulk record pull
_register(AttackScenario(
    "A15", "fhir_bulk_pull", "Compromised app token", "FHIR server / cloud API",
    [DeviceRole.FHIR_SERVER],
    ["HTTPS", "FHIR"],
    "internet",
    "fhir_server_01",
    0.6, True,
    [AttackStage("api_enum", 0.2, "Enumerate API endpoints"),
     AttackStage("bulk_read", 0.8, "High GET rate, anomalous volume and pagination")],
    "High GET rate, high object count, mostly read-only but anomalous volume and pagination"
))

# A16 — HL7 interface abuse / message flood
_register(AttackScenario(
    "A16", "hl7_flood", "Compromised clinical app", "HL7 engine / LIS / EHR adapter",
    [DeviceRole.HL7_ENGINE, DeviceRole.LIS, DeviceRole.EHR_FRONTEND],
    ["HL7", "TCP"],
    "clinical_subnet",
    "hl7_engine_01",
    0.8, False,
    [AttackStage("msg_burst", 0.7, "Abnormal HL7 message count bursts"),
     AttackStage("error_gen", 0.3, "Parser errors and retries from non-standard sender")],
    "Abnormal HL7 message count, bursts from non-standard sender, retries and parser errors"
))

# A17 — East-west pivot into clinical subnet
_register(AttackScenario(
    "A17", "lateral_movement", "Compromised IT endpoint", "Enterprise -> PACS / nurse station / IoMT",
    [DeviceRole.PACS_SERVER, DeviceRole.NURSE_STATION, DeviceRole.PATIENT_MONITOR],
    ["SMB", "RDP", "HTTPS"],
    "enterprise_it",
    "nurse_station_01",
    0.6, True,
    [AttackStage("path_probe", 0.3, "Rare path activation, scan clinical assets"),
     AttackStage("smb_rdp_connect", 0.5, "SMB/RDP/HTTPS to clinical assets"),
     AttackStage("establish_presence", 0.2, "Establish persistent access")],
    "Rare path activation, sudden SMB/RDP/HTTPS to clinical assets, unique_dst_ip rises"
))

# A18 — Ransomware staging via SMB/RDP
_register(AttackScenario(
    "A18", "ransomware_staging", "Compromised workstation",
    "File shares, AD, backup, EHR support systems",
    [DeviceRole.FILE_SHARE, DeviceRole.AD_SERVER, DeviceRole.BACKUP_SERVER, DeviceRole.EHR_FRONTEND],
    ["SMB", "RDP", "HTTPS"],
    "enterprise_it",
    "file_share_01",
    0.8, False,
    [AttackStage("smb_enum", 0.3, "SMB session spike, file-share enumeration"),
     AttackStage("admin_share", 0.3, "Admin share access, RDP spread"),
     AttackStage("staging", 0.4, "Ransomware payload staging")],
    "SMB session spike, admin share access, RDP spread, file-share enumeration"
))

# A19 — Backup discovery and deletion
_register(AttackScenario(
    "A19", "backup_deletion", "Compromised admin host", "Backup server",
    [DeviceRole.BACKUP_SERVER],
    ["SMB", "HTTPS"],
    "enterprise_it",
    "backup_server_01",
    0.7, True,
    [AttackStage("backup_discover", 0.3, "Backup share flows appear"),
     AttackStage("backup_delete", 0.5, "Admin/API deletion calls"),
     AttackStage("verify_delete", 0.2, "Drop in routine backup traffic")],
    "Backup share flows appear, admin/API deletion calls, drop in routine backup traffic"
))

# A20 — PHI exfiltration before extortion
_register(AttackScenario(
    "A20", "phi_exfiltration", "Compromised server", "Database / file share / cloud sink",
    [DeviceRole.FILE_SHARE, DeviceRole.EHR_FRONTEND],
    ["HTTPS", "SMB"],
    "enterprise_it",
    "file_share_01",
    0.7, False,
    [AttackStage("data_collect", 0.3, "Identify and stage high-value data"),
     AttackStage("compress", 0.2, "Compression-like byte pattern"),
     AttackStage("exfiltrate", 0.5, "Large outbound transfer to external destination")],
    "Large outbound transfer to unusual external destination, sustained compression-like byte pattern"
))

# A21 — Protocol-aware DoS on PACS
_register(AttackScenario(
    "A21", "pacs_dos", "External or internal", "PACS / imaging server",
    [DeviceRole.PACS_SERVER],
    ["DICOM", "HTTPS"],
    "internet",
    "pacs_server_01",
    0.9, False,
    [AttackStage("flood", 0.8, "Many requests / large payloads causing resource exhaustion"),
     AttackStage("sustained", 0.2, "Retransmissions rise, service latency spikes")],
    "Many requests/large payloads causing resource exhaustion, retransmissions rise, latency spikes"
))

# A22 — Application-layer flood on clinical portal
_register(AttackScenario(
    "A22", "app_layer_flood", "Internet bot / single source", "Clinical web application",
    [DeviceRole.WEB_PORTAL, DeviceRole.EHR_FRONTEND],
    ["HTTPS", "HTTP"],
    "internet",
    "web_portal_01",
    0.9, False,
    [AttackStage("http_flood", 0.7, "High request rate, session churn"),
     AttackStage("error_storm", 0.3, "Many 4xx/5xx responses, CPU/latency spikes")],
    "High request rate, session churn, many 4xx/5xx responses, CPU/latency proxies"
))

# A23 — Telemetry spoofing / manipulated patient data
_register(AttackScenario(
    "A23", "telemetry_spoofing", "Internal MITM or device compromise",
    "Telemetry aggregator / monitor",
    [DeviceRole.TELEMETRY_AGGREGATOR, DeviceRole.PATIENT_MONITOR],
    ["TCP", "BLE"],
    "iomt_subnet",
    "telemetry_agg_01",
    0.6, True,
    [AttackStage("intercept", 0.3, "Intercept telemetry stream"),
     AttackStage("inject_values", 0.7, "Implausible value jumps, inconsistent sender identity")],
    "Normal packet rate but implausible value jumps, inconsistent sender identity, repeat values"
))

# A24 — Unauthorized config change on device management plane
_register(AttackScenario(
    "A24", "unauthorized_config", "Compromised service tool", "IoMT management server",
    [DeviceRole.DEVICE_MGMT, DeviceRole.PATIENT_MONITOR, DeviceRole.INFUSION_PUMP],
    ["HTTPS", "SSH", "SNMP"],
    "clinical_subnet",
    "device_mgmt_01",
    0.6, True,
    [AttackStage("access_mgmt", 0.2, "Access management plane"),
     AttackStage("config_write", 0.5, "Bursts of write/config operations"),
     AttackStage("behavior_drift", 0.3, "Device behavior drift after config change")],
    "Bursts of write/config operations, small request payloads, subsequent device behavior drift"
))

# ─── CVE-Informed 2024-2025 Real-World Attack Scenarios ───────────────────────

# A25 — ALPHV/BlackCat-style Healthcare Ransomware (inspired by Change Healthcare Feb 2024)
# CVE ref: Exploits stolen Citrix creds (CVE-2019-19781 family), no MFA
_register(AttackScenario(
    "A25", "alphv_healthcare_ransomware",
    "Compromised Citrix/VPN endpoint (no MFA)",
    "EHR, file shares, backup, AD — full domain compromise prior to encryption",
    [DeviceRole.GATEWAY, DeviceRole.AD_SERVER, DeviceRole.FILE_SHARE,
     DeviceRole.BACKUP_SERVER, DeviceRole.EHR_FRONTEND],
    ["HTTPS", "SMB", "RDP", "VPN"],
    "internet",
    "gw_edge_01",
    0.9, False,
    [AttackStage("vpn_initial_access", 0.1,
                 "Stolen Citrix credential used; no MFA check; new VPN session off-hours"),
     AttackStage("domain_recon", 0.15,
                 "Rapid LDAP/AD enumeration; BloodHound-style query pattern; high unique_dst_ip"),
     AttackStage("lateral_rdp_smb", 0.2,
                 "RDP/SMB lateral movement to backup, file-share, EHR servers"),
     AttackStage("backup_deletion", 0.15,
                 "Backup server API calls; shadow copy deletion; backup traffic drops to zero"),
     AttackStage("data_exfiltration", 0.2,
                 "Large outbound data to external C2; sustained compression-like byte stream"),
     AttackStage("ransomware_deploy", 0.2,
                 "SMB write volume spikes; file-share flows saturate; services go silent")],
    "CVE-2019-19781 / stolen Citrix creds → AD takeover → backup wipe → PHI exfil → encryption. "
    "Indicators: off-hours VPN, rapid AD LDAP enum, RDP spread, backup silence, large outbound burst."
))

# A26 — Log4Shell Exploitation in Clinical Middleware (CVE-2021-44228)
# Still present in unpatched Java-based FHIR/HL7 gateways as of 2024
_register(AttackScenario(
    "A26", "log4shell_clinical_rce",
    "Internet → FHIR / HL7 Java middleware (unpatched Log4j)",
    "FHIR server, HL7 engine, clinical middleware",
    [DeviceRole.FHIR_SERVER, DeviceRole.HL7_ENGINE, DeviceRole.EHR_FRONTEND],
    ["HTTPS", "FHIR", "HL7", "TCP"],
    "internet",
    "fhir_server_01",
    0.7, True,
    [AttackStage("jndi_probe", 0.15,
                 "Single crafted HTTPS request with JNDI payload in User-Agent/X-Api-Version header"),
     AttackStage("ldap_callback", 0.1,
                 "Outbound LDAP/RMI connection from server to attacker C2 (new external peer)"),
     AttackStage("rce_establish", 0.2,
                 "Reverse shell established; low-volume persistent TCP session to external IP"),
     AttackStage("internal_recon", 0.25,
                 "Internal subnet scanning from FHIR host; rare source IP for east-west flows"),
     AttackStage("ehr_data_access", 0.3,
                 "Bulk FHIR API reads; patient record enumeration; high GET rate anomaly")],
    "CVE-2021-44228 Log4Shell → RCE on Java-based FHIR/HL7 server → internal pivot → bulk PHI read. "
    "Indicators: single external HTTP probe, outbound LDAP callback, new reverse-TCP session, bulk FHIR GET."
))

# A27 — MQTT Telemetry Hijack on IoMT Subnet (2024/2025 IoT CVE pattern)
# Targets unencrypted MQTT brokers on patient monitors + infusion pumps
# Related: CVE-2023-28369 (Eclipse Mosquitto), unauth MQTT brokers in medical subnets
_register(AttackScenario(
    "A27", "mqtt_iomt_hijack",
    "Internal foothold or rogue Wi-Fi device",
    "MQTT broker / telemetry aggregator / patient monitors / infusion pumps",
    [DeviceRole.TELEMETRY_AGGREGATOR, DeviceRole.PATIENT_MONITOR,
     DeviceRole.INFUSION_PUMP, DeviceRole.BLE_GATEWAY],
    ["TCP", "BLE", "HTTPS"],
    "iomt_subnet",
    "telemetry_agg_01",
    0.65, True,
    [AttackStage("broker_discovery", 0.1,
                 "Port 1883/8883 scan across IoMT subnet; unauthenticated MQTT connect attempt"),
     AttackStage("topic_subscribe", 0.2,
                 "Wildcard MQTT subscribe (#) to harvest all vitals and device commands"),
     AttackStage("telemetry_intercept", 0.3,
                 "Passive data capture; low packet volume; repeated telemetry seen on new source"),
     AttackStage("command_inject", 0.25,
                 "MQTT PUBLISH to device control topics; infusion pump/alarm config tampering"),
     AttackStage("persistence", 0.15,
                 "Retain flag set on malicious topic; persists across broker restarts")],
    "Unauth MQTT (CVE-2023-28369 class) → wildcard subscribe → vital intercept → command inject to pumps/monitors. "
    "Indicators: port-1883 scan, new subscriber on all topics, implausible vitals, device command anomalies."
))


# ──────────────────────────────────────────────────────────────────────
# Field Schemas
# ──────────────────────────────────────────────────────────────────────
BASE_FLOW_FIELDS = [
    "ts_start", "ts_end", "src_ip", "dst_ip", "src_port", "dst_port",
    "proto", "direction", "duration_ms", "pkts_fwd", "pkts_rev",
    "bytes_fwd", "bytes_rev", "syn_cnt", "rst_cnt", "psh_cnt",
    "retrans_cnt", "tls_session", "http_status", "auth_attempts",
    "auth_failures", "app_service", "zone_src", "zone_dst",
    "device_role_src", "device_role_dst"
]

MEDICAL_METADATA_FIELDS = [
    "dicom_query_cnt", "dicom_move_cnt", "dicom_store_cnt", "dicom_bytes",
    "hl7_msg_cnt", "hl7_error_cnt", "fhir_read_cnt", "fhir_write_cnt",
    "ble_telemetry_cnt", "ble_replay_flag", "device_update_flag",
    "reboot_flag", "remote_admin_flag", "config_write_cnt",
    "patient_value_jump_score", "backup_delete_flag"
]

LABEL_FIELDS = [
    "label", "attack_id", "scenario_id", "attack_stage"
]

WINDOW_FEATURE_FIELDS = [
    "window_start", "window_end",
    "flow_count", "pkt_count", "byte_count",
    "unique_src_ip", "unique_dst_ip", "unique_dst_port",
    "new_external_peers", "failed_login_count", "successful_login_count",
    "vendor_remote_sessions", "remote_admin_sessions",
    "dicom_query_rate", "dicom_move_rate", "dicom_bytes_out",
    "fhir_read_rate", "hl7_msg_rate", "hl7_error_rate",
    "ble_telemetry_rate", "replay_alerts", "config_write_rate",
    "device_update_events", "reboot_events",
    "east_west_flow_count", "enterprise_to_clinical_flows",
    "clinical_to_external_bytes", "backup_server_flows",
    "retransmission_rate", "rst_rate", "error_4xx_5xx_rate",
    "service_unavailable_rate", "patient_value_jump_score",
]

WINDOW_LABEL_FIELDS = [
    "label", "attack_id", "scenario_id"
]


# ──────────────────────────────────────────────────────────────────────
# Simulation Configuration
# ──────────────────────────────────────────────────────────────────────
@dataclass
class SimConfig:
    scenario_id: str = "A01"
    environment_profile: str = "medium_hospital_v1"
    seed: int = 42
    duration_s: int = 3600
    window_size_s: int = 5
    attack_start_s: int = 420
    attack_duration_s: int = 180
    intensity: float = 0.75
    stealth_mode: bool = False
    entry_point: str = "internet"
    target_asset: str = "pacs_server_01"
    affected_protocols: List[str] = field(default_factory=lambda: ["DICOM", "HTTPS"])
    label_granularity: str = "window"  # window | flow | event
    output_dir: str = "./output"

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "environment_profile": self.environment_profile,
            "seed": self.seed,
            "duration_s": self.duration_s,
            "window_size_s": self.window_size_s,
            "attack_start_s": self.attack_start_s,
            "attack_duration_s": self.attack_duration_s,
            "intensity": self.intensity,
            "stealth_mode": self.stealth_mode,
            "entry_point": self.entry_point,
            "target_asset": self.target_asset,
            "affected_protocols": self.affected_protocols,
            "label_granularity": self.label_granularity,
            "output_dir": self.output_dir,
        }


# ──────────────────────────────────────────────────────────────────────
# Communication maps — who normally talks to whom
# ──────────────────────────────────────────────────────────────────────
# (src_role, dst_role, protocols, flows_per_hour_baseline)
NORMAL_COMM_MAP: List[Tuple[DeviceRole, DeviceRole, List[str], float]] = [
    # Imaging workflow
    (DeviceRole.CT_SCANNER, DeviceRole.PACS_SERVER, ["DICOM"], 30),
    (DeviceRole.MRI_SCANNER, DeviceRole.PACS_SERVER, ["DICOM"], 20),
    (DeviceRole.ULTRASOUND, DeviceRole.PACS_SERVER, ["DICOM"], 25),
    (DeviceRole.RAD_WORKSTATION, DeviceRole.PACS_SERVER, ["DICOM", "HTTPS"], 60),
    (DeviceRole.RAD_WORKSTATION, DeviceRole.DICOM_VIEWER, ["DICOM"], 40),
    (DeviceRole.DICOM_VIEWER, DeviceRole.IMAGING_ARCHIVE_GW, ["DICOM"], 20),
    (DeviceRole.PACS_SERVER, DeviceRole.IMAGING_ARCHIVE_GW, ["DICOM"], 15),

    # Clinical workflow
    (DeviceRole.NURSE_STATION, DeviceRole.EHR_FRONTEND, ["HTTPS"], 120),
    (DeviceRole.NURSE_STATION, DeviceRole.PACS_SERVER, ["HTTPS"], 20),
    (DeviceRole.EHR_FRONTEND, DeviceRole.FHIR_SERVER, ["HTTPS", "FHIR"], 80),
    (DeviceRole.EHR_FRONTEND, DeviceRole.HL7_ENGINE, ["HL7"], 60),
    (DeviceRole.HL7_ENGINE, DeviceRole.LIS, ["HL7"], 40),
    (DeviceRole.HL7_ENGINE, DeviceRole.RIS, ["HL7"], 30),
    (DeviceRole.FHIR_SERVER, DeviceRole.EHR_FRONTEND, ["HTTPS"], 50),

    # IoMT telemetry
    (DeviceRole.PATIENT_MONITOR, DeviceRole.TELEMETRY_AGGREGATOR, ["TCP", "BLE"], 300),
    (DeviceRole.WEARABLE, DeviceRole.BLE_GATEWAY, ["BLE"], 200),
    (DeviceRole.BLE_GATEWAY, DeviceRole.TELEMETRY_AGGREGATOR, ["TCP"], 180),
    (DeviceRole.INFUSION_PUMP, DeviceRole.NURSE_STATION, ["TCP"], 50),
    (DeviceRole.VENTILATOR, DeviceRole.TELEMETRY_AGGREGATOR, ["TCP"], 100),

    # IT infrastructure
    (DeviceRole.NURSE_STATION, DeviceRole.AD_SERVER, ["LDAP", "Kerberos"], 30),
    (DeviceRole.EHR_FRONTEND, DeviceRole.AD_SERVER, ["LDAP", "Kerberos"], 20),
    (DeviceRole.FILE_SHARE, DeviceRole.AD_SERVER, ["SMB"], 10),
    (DeviceRole.BACKUP_SERVER, DeviceRole.FILE_SHARE, ["SMB"], 8),
    (DeviceRole.SOC_COLLECTOR, DeviceRole.PACS_SERVER, ["Syslog"], 15),

    # Device management
    (DeviceRole.DEVICE_MGMT, DeviceRole.PATIENT_MONITOR, ["HTTPS", "SNMP"], 20),
    (DeviceRole.DEVICE_MGMT, DeviceRole.INFUSION_PUMP, ["HTTPS", "SNMP"], 15),
    (DeviceRole.DEVICE_MGMT, DeviceRole.VENTILATOR, ["HTTPS", "SNMP"], 10),

    # Vendor remote access (sparse)
    (DeviceRole.VENDOR_JUMPHOST, DeviceRole.DEVICE_MGMT, ["SSH", "RDP"], 2),

    # External-facing
    (DeviceRole.GATEWAY, DeviceRole.WEB_PORTAL, ["HTTPS"], 100),
    (DeviceRole.GATEWAY, DeviceRole.FHIR_SERVER, ["HTTPS"], 40),
]
