"""
IoMT Medical NIDS Simulator — Labeling Engine (v2)
Per-flow and per-window label assignment with:
- Ambiguous transition window support
- Complete event extraction for ALL 24 scenarios
"""

from typing import List, Dict, Optional
from config import SimConfig, ATTACK_SCENARIOS


class LabelingEngine:
    """Assigns labels to flows and windows based on attack timing."""

    def __init__(self, config: SimConfig):
        self.config = config
        self.attack_start = config.attack_start_s
        self.attack_end = config.attack_start_s + config.attack_duration_s
        self.scenario = ATTACK_SCENARIOS.get(config.scenario_id)
        self.transition_window = min(10.0, config.attack_duration_s * 0.05)

    def label_flow(self, flow: dict) -> dict:
        if flow.get("attack_id"):
            return flow
        ts = flow.get("ts_start", 0)
        if (self.attack_start - self.transition_window <= ts < self.attack_start):
            flow["label"] = "benign"
        elif ts >= self.attack_end and ts < self.attack_end + self.transition_window:
            flow["label"] = "benign"
        else:
            flow["label"] = flow.get("label", "benign")
        return flow

    def label_flows(self, flows: List[dict]) -> List[dict]:
        return [self.label_flow(f) for f in flows]

    def label_window(self, window: dict, window_flows: List[dict]) -> dict:
        attack_flows = [f for f in window_flows if f.get("attack_id")]

        if attack_flows:
            window["label"] = self.scenario.label if self.scenario else "attack"
            window["attack_id"] = self.config.scenario_id
            window["scenario_id"] = self.config.scenario_id

            attack_ratio = len(attack_flows) / max(1, len(window_flows))
            if attack_ratio < 0.3:
                window["label"] = "transition"
        else:
            window["label"] = "benign"
            window["attack_id"] = ""
            window["scenario_id"] = ""

        return window

    def get_events(self, flows: List[dict]) -> List[dict]:
        """
        Extract high-level protocol events from flows for events.csv.
        Covers ALL 24 attack scenarios.
        """
        events = []
        for flow in flows:
            ts = flow.get("ts_start", 0)
            base_event = {
                "timestamp": ts,
                "src_ip": flow.get("src_ip", ""),
                "dst_ip": flow.get("dst_ip", ""),
                "protocol": flow.get("proto", ""),
                "label": flow.get("label", "benign"),
                "attack_id": flow.get("attack_id", ""),
                "scenario_id": flow.get("scenario_id", ""),
            }

            # ── Auth events (A03, A04, A06, A07, A09, A10) ──
            if flow.get("auth_failures", 0) > 0:
                e = {**base_event}
                e["event_type"] = "login_failure"
                e["details"] = (f"auth_attempts={flow.get('auth_attempts', 0)}, "
                               f"failures={flow.get('auth_failures', 0)}")
                events.append(e)

            if flow.get("auth_attempts", 0) > 0 and flow.get("auth_failures", 0) == 0:
                if flow.get("attack_id"):  # Only flag successful logins during attacks
                    e = {**base_event}
                    e["event_type"] = "successful_login"
                    e["details"] = f"auth_attempts={flow.get('auth_attempts', 0)}"
                    events.append(e)

            # ── DICOM events (A13, A14, A21) ──
            if flow.get("dicom_query_cnt", 0) >= 3:
                e = {**base_event}
                e["event_type"] = "dicom_query_burst"
                e["protocol"] = "DICOM"
                e["details"] = (f"query_cnt={flow.get('dicom_query_cnt', 0)}, "
                               f"move_cnt={flow.get('dicom_move_cnt', 0)}")
                events.append(e)

            if flow.get("dicom_move_cnt", 0) >= 2:
                e = {**base_event}
                e["event_type"] = "dicom_bulk_transfer"
                e["protocol"] = "DICOM"
                e["details"] = (f"move_cnt={flow.get('dicom_move_cnt', 0)}, "
                               f"store_cnt={flow.get('dicom_store_cnt', 0)}, "
                               f"bytes={flow.get('dicom_bytes', 0)}")
                events.append(e)

            # ── Large data transfer (A14, A20) ──
            if flow.get("bytes_fwd", 0) > 100000 and flow.get("attack_id"):
                e = {**base_event}
                e["event_type"] = "large_outbound_transfer"
                e["details"] = (f"bytes_fwd={flow.get('bytes_fwd', 0)}, "
                               f"bytes_rev={flow.get('bytes_rev', 0)}")
                events.append(e)

            # ── Config write (A07, A24) ──
            if flow.get("config_write_cnt", 0) > 0:
                e = {**base_event}
                e["event_type"] = "config_write"
                e["details"] = f"config_writes={flow.get('config_write_cnt', 0)}"
                events.append(e)

            # ── Firmware update (A12) ──
            if flow.get("device_update_flag", 0):
                e = {**base_event}
                e["event_type"] = "firmware_update"
                e["details"] = f"reboot={flow.get('reboot_flag', 0)}"
                events.append(e)

            # ── Backup deletion (A19) ──
            if flow.get("backup_delete_flag", 0):
                e = {**base_event}
                e["event_type"] = "backup_deletion"
                e["details"] = "backup_delete=1"
                events.append(e)

            # ── BLE replay (A11) ──
            if flow.get("ble_replay_flag", 0):
                e = {**base_event}
                e["event_type"] = "ble_replay"
                e["protocol"] = "BLE"
                e["details"] = f"ble_telemetry_cnt={flow.get('ble_telemetry_cnt', 0)}"
                events.append(e)

            # ── Patient value anomaly (A23) ──
            if flow.get("patient_value_jump_score", 0) > 0.3:
                e = {**base_event}
                e["event_type"] = "patient_value_anomaly"
                e["details"] = f"jump_score={flow.get('patient_value_jump_score', 0)}"
                events.append(e)

            # ── HL7 errors (A16) ──
            if flow.get("hl7_error_cnt", 0) >= 2:
                e = {**base_event}
                e["event_type"] = "hl7_error_burst"
                e["protocol"] = "HL7"
                e["details"] = (f"msg_cnt={flow.get('hl7_msg_cnt', 0)}, "
                               f"error_cnt={flow.get('hl7_error_cnt', 0)}")
                events.append(e)

            # ── HL7 flood (A16) ──
            if flow.get("hl7_msg_cnt", 0) >= 10:
                e = {**base_event}
                e["event_type"] = "hl7_message_flood"
                e["protocol"] = "HL7"
                e["details"] = f"msg_cnt={flow.get('hl7_msg_cnt', 0)}"
                events.append(e)

            # ── FHIR bulk read (A15) ──
            if flow.get("fhir_read_cnt", 0) >= 5:
                e = {**base_event}
                e["event_type"] = "fhir_bulk_read"
                e["protocol"] = "FHIR"
                e["details"] = f"read_cnt={flow.get('fhir_read_cnt', 0)}"
                events.append(e)

            # ── Recon / port scan (A01) — short flow + RST ──
            if (flow.get("rst_cnt", 0) > 0 and
                flow.get("duration_ms", 0) < 100 and
                flow.get("attack_id")):
                e = {**base_event}
                e["event_type"] = "port_scan"
                e["details"] = (f"duration_ms={flow.get('duration_ms', 0)}, "
                               f"rst_cnt={flow.get('rst_cnt', 0)}")
                events.append(e)

            # ── HTTP error flood (A22) ──
            if flow.get("http_status", 0) >= 400 and flow.get("attack_id"):
                e = {**base_event}
                e["event_type"] = "http_error"
                e["details"] = f"http_status={flow.get('http_status', 0)}"
                events.append(e)

            # ── Remote admin from unusual source (A05, A17) ──
            if (flow.get("remote_admin_flag", 0) and
                flow.get("attack_id") and
                flow.get("zone_src") in ("zone_f", "zone_b")):
                e = {**base_event}
                e["event_type"] = "unusual_remote_admin"
                e["details"] = (f"zone_src={flow.get('zone_src')}, "
                               f"zone_dst={flow.get('zone_dst')}")
                events.append(e)

            # ── Cross-zone lateral movement (A17, A18) ──
            if (flow.get("attack_id") and
                flow.get("zone_src") != flow.get("zone_dst") and
                flow.get("proto") in ("SMB", "RDP") and
                flow.get("zone_src") not in ("zone_a",)):
                e = {**base_event}
                e["event_type"] = "lateral_movement"
                e["details"] = (f"proto={flow.get('proto')}, "
                               f"zone_src={flow.get('zone_src')} → zone_dst={flow.get('zone_dst')}")
                events.append(e)

            # ── High retransmission (A21 DoS) ──
            if flow.get("retrans_cnt", 0) >= 5 and flow.get("attack_id"):
                e = {**base_event}
                e["event_type"] = "high_retransmission"
                e["details"] = (f"retrans_cnt={flow.get('retrans_cnt', 0)}, "
                               f"syn_cnt={flow.get('syn_cnt', 0)}")
                events.append(e)

        return events
