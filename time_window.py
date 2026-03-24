"""
IoMT Medical NIDS Simulator — Time Window Aggregation
Aggregates flows into configurable time windows with 28+ aggregate features.
"""

from typing import List, Dict
from config import SimConfig, WINDOW_FEATURE_FIELDS, WINDOW_LABEL_FIELDS, Zone


class TimeWindowAggregator:
    """Aggregates flow records into fixed-size time windows with features."""

    def __init__(self, config: SimConfig):
        self.config = config
        self.window_size = config.window_size_s

    def aggregate(self, flows: List[dict], labeling_engine=None) -> List[dict]:
        """
        Aggregate all flows into time windows.

        Returns a list of window records with aggregate features and labels.
        """
        if not flows:
            return []

        # Sort by start time
        flows_sorted = sorted(flows, key=lambda f: f.get("ts_start", 0))

        # Determine time range
        t_min = flows_sorted[0].get("ts_start", 0)
        t_max = max(f.get("ts_end", f.get("ts_start", 0)) for f in flows_sorted)

        windows = []
        w_start = int(t_min / self.window_size) * self.window_size

        while w_start < t_max:
            w_end = w_start + self.window_size
            # Get flows in this window
            window_flows = [
                f for f in flows_sorted
                if f.get("ts_start", 0) >= w_start and f.get("ts_start", 0) < w_end
            ]

            window = self._compute_features(window_flows, w_start, w_end)

            # Label the window
            if labeling_engine:
                window = labeling_engine.label_window(window, window_flows)
            else:
                attack_flows = [f for f in window_flows if f.get("attack_id")]
                if attack_flows:
                    window["label"] = attack_flows[0].get("label", "attack")
                    window["attack_id"] = attack_flows[0].get("attack_id", "")
                    window["scenario_id"] = attack_flows[0].get("scenario_id", "")
                else:
                    window["label"] = "benign"
                    window["attack_id"] = ""
                    window["scenario_id"] = ""

            windows.append(window)
            w_start = w_end

        return windows

    def _compute_features(self, flows: List[dict],
                          w_start: float, w_end: float) -> dict:
        """Compute all aggregate features for a single time window."""
        w = {
            "window_start": round(w_start, 6),
            "window_end": round(w_end, 6),
        }

        if not flows:
            # Empty window — all zeros
            for field in WINDOW_FEATURE_FIELDS:
                if field not in ("window_start", "window_end"):
                    w[field] = 0
            for field in WINDOW_LABEL_FIELDS:
                w[field] = "" if field != "label" else "benign"
            return w

        n = len(flows)

        # Basic counts
        w["flow_count"] = n
        w["pkt_count"] = sum(f.get("pkts_fwd", 0) + f.get("pkts_rev", 0) for f in flows)
        w["byte_count"] = sum(f.get("bytes_fwd", 0) + f.get("bytes_rev", 0) for f in flows)

        # Unique IP/port counts
        w["unique_src_ip"] = len(set(f.get("src_ip", "") for f in flows))
        w["unique_dst_ip"] = len(set(f.get("dst_ip", "") for f in flows))
        w["unique_dst_port"] = len(set(f.get("dst_port", 0) for f in flows))

        # External peer tracking
        external_ips = set()
        for f in flows:
            for ip_field in ("src_ip", "dst_ip"):
                ip = f.get(ip_field, "")
                if ip.startswith("198.51.") or ip.startswith("203.0.113."):
                    external_ips.add(ip)
        w["new_external_peers"] = len(external_ips)

        # Login metrics
        w["failed_login_count"] = sum(f.get("auth_failures", 0) for f in flows)
        w["successful_login_count"] = sum(
            max(0, f.get("auth_attempts", 0) - f.get("auth_failures", 0))
            for f in flows
        )

        # Vendor / remote sessions
        w["vendor_remote_sessions"] = sum(
            1 for f in flows
            if f.get("zone_src") == Zone.F.value
        )
        w["remote_admin_sessions"] = sum(
            1 for f in flows
            if f.get("remote_admin_flag", 0)
        )

        # Medical protocol rates (per window, effectively per-second if window=5s)
        dt = max(1, self.window_size)
        w["dicom_query_rate"] = round(sum(f.get("dicom_query_cnt", 0) for f in flows) / dt, 4)
        w["dicom_move_rate"] = round(sum(f.get("dicom_move_cnt", 0) for f in flows) / dt, 4)
        w["dicom_bytes_out"] = sum(f.get("dicom_bytes", 0) for f in flows)
        w["fhir_read_rate"] = round(sum(f.get("fhir_read_cnt", 0) for f in flows) / dt, 4)
        w["hl7_msg_rate"] = round(sum(f.get("hl7_msg_cnt", 0) for f in flows) / dt, 4)
        w["hl7_error_rate"] = round(sum(f.get("hl7_error_cnt", 0) for f in flows) / dt, 4)

        # BLE / IoMT metrics
        w["ble_telemetry_rate"] = round(sum(f.get("ble_telemetry_cnt", 0) for f in flows) / dt, 4)
        w["replay_alerts"] = sum(f.get("ble_replay_flag", 0) for f in flows)
        w["config_write_rate"] = round(sum(f.get("config_write_cnt", 0) for f in flows) / dt, 4)
        w["device_update_events"] = sum(f.get("device_update_flag", 0) for f in flows)
        w["reboot_events"] = sum(f.get("reboot_flag", 0) for f in flows)

        # East-west and cross-zone traffic
        w["east_west_flow_count"] = sum(
            1 for f in flows
            if f.get("zone_src", "") not in (Zone.A.value, "") and
               f.get("zone_dst", "") not in (Zone.A.value, "") and
               f.get("zone_src") != f.get("zone_dst")
        )
        w["enterprise_to_clinical_flows"] = sum(
            1 for f in flows
            if f.get("zone_src") == Zone.B.value and
               f.get("zone_dst") in (Zone.C.value, Zone.D.value, Zone.E.value)
        )
        w["clinical_to_external_bytes"] = sum(
            f.get("bytes_fwd", 0) for f in flows
            if f.get("zone_src") in (Zone.C.value, Zone.D.value, Zone.E.value) and
               f.get("zone_dst") == Zone.A.value
        )
        w["backup_server_flows"] = sum(
            1 for f in flows
            if "backup" in f.get("device_role_src", "") or
               "backup" in f.get("device_role_dst", "")
        )

        # Error/anomaly rates
        total_pkts = max(1, w["pkt_count"])
        w["retransmission_rate"] = round(
            sum(f.get("retrans_cnt", 0) for f in flows) / total_pkts, 6
        )
        w["rst_rate"] = round(
            sum(f.get("rst_cnt", 0) for f in flows) / total_pkts, 6
        )

        http_flows = [f for f in flows if f.get("http_status", 0) > 0]
        if http_flows:
            errors = sum(1 for f in http_flows if f.get("http_status", 0) >= 400)
            w["error_4xx_5xx_rate"] = round(errors / len(http_flows), 4)
            unavail = sum(1 for f in http_flows if f.get("http_status", 0) == 503)
            w["service_unavailable_rate"] = round(unavail / len(http_flows), 4)
        else:
            w["error_4xx_5xx_rate"] = 0
            w["service_unavailable_rate"] = 0

        # Patient value anomaly
        jump_scores = [f.get("patient_value_jump_score", 0) for f in flows
                       if f.get("patient_value_jump_score", 0) > 0]
        w["patient_value_jump_score"] = round(max(jump_scores), 3) if jump_scores else 0

        return w
