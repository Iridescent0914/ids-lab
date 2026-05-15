from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from app.detection.threshold_detector import ThresholdDetector, ThresholdSettings
from app.parser.models import PacketInfo
from app.storage.database import DatabaseManager


BASE_TIME = datetime(2026, 5, 9, 12, 0, 0)


def _detector(
    port_threshold: int = 3,
    horizontal_threshold: int = 3,
    icmp_threshold: int = 3,
) -> ThresholdDetector:
    return ThresholdDetector(
        ThresholdSettings(
            window_seconds=10,
            port_scan_unique_ports=port_threshold,
            horizontal_scan_unique_hosts=horizontal_threshold,
            icmp_high_frequency_count=icmp_threshold,
        )
    )


def _tcp_packet(offset: float, dst_port: int, flags: str = "S") -> PacketInfo:
    return PacketInfo(
        timestamp=BASE_TIME + timedelta(seconds=offset),
        protocol="TCP",
        packet_length=60,
        src_ip="10.0.0.2",
        dst_ip="10.0.0.10",
        src_port=40000 + int(offset),
        dst_port=dst_port,
        tcp_flags=flags,
    )


def _tcp_packet_to(offset: float, dst_ip: str, dst_port: int, flags: str = "S") -> PacketInfo:
    packet = _tcp_packet(offset, dst_port, flags)
    return PacketInfo(
        timestamp=packet.timestamp,
        protocol=packet.protocol,
        packet_length=packet.packet_length,
        src_ip=packet.src_ip,
        dst_ip=dst_ip,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        tcp_flags=packet.tcp_flags,
    )


def _udp_packet(offset: float, src_port: int, dst_port: int, dst_ip: str = "10.0.0.10") -> PacketInfo:
    return PacketInfo(
        timestamp=BASE_TIME + timedelta(seconds=offset),
        protocol="UDP",
        packet_length=60,
        src_ip="10.0.0.2",
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
    )


def _icmp_packet(offset: float, icmp_type: int, src_ip: str = "10.0.0.2") -> PacketInfo:
    return PacketInfo(
        timestamp=BASE_TIME + timedelta(seconds=offset),
        protocol="ICMP",
        packet_length=60,
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        icmp_type=icmp_type,
        icmp_code=0,
    )


class ThresholdDetectorTests(unittest.TestCase):
    def test_packet_timestamp_epoch_keeps_subsecond_precision(self) -> None:
        packet = _tcp_packet(0.356, 80)

        self.assertAlmostEqual(packet.timestamp_epoch, BASE_TIME.timestamp() + 0.356, places=3)

    def test_tcp_syn_port_scan_threshold_alert(self) -> None:
        detector = _detector()
        alerts = []

        for offset, port in enumerate([21, 22, 23]):
            alerts.extend(detector.detect(_tcp_packet(offset, port)))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "threshold_alert")
        self.assertEqual(alerts[0].severity, 1)
        self.assertIn("Possible port scan", alerts[0].message)

    def test_tcp_syn_below_threshold_does_not_alert(self) -> None:
        detector = _detector(port_threshold=3)
        alerts = []

        for offset, port in enumerate([21, 22]):
            alerts.extend(detector.detect(_tcp_packet(offset, port)))

        self.assertEqual(alerts, [])

    def test_same_destination_port_does_not_count_as_port_scan(self) -> None:
        detector = _detector(port_threshold=3)
        alerts = []

        for offset in range(3):
            alerts.extend(detector.detect(_tcp_packet(offset, 22)))

        self.assertEqual(alerts, [])

    def test_tcp_syn_ack_response_does_not_trigger_port_scan(self) -> None:
        detector = _detector(port_threshold=3)
        alerts = []

        for offset, port in enumerate([50001, 50002, 50003]):
            alerts.extend(detector.detect(_tcp_packet(offset, port, flags="SA")))

        self.assertEqual(alerts, [])

    def test_dns_responses_do_not_trigger_udp_port_scan(self) -> None:
        detector = _detector(port_threshold=3)
        alerts = []

        for offset, port in enumerate([50001, 50002, 50003]):
            alerts.extend(detector.detect(_udp_packet(offset, src_port=53, dst_port=port)))

        self.assertEqual(alerts, [])

    def test_multicast_destination_does_not_trigger_port_scan(self) -> None:
        detector = _detector(port_threshold=3)
        alerts = []

        for offset, port in enumerate([1900, 1901, 1902]):
            alerts.extend(
                detector.detect(
                    _udp_packet(offset, src_port=40000 + offset, dst_port=port, dst_ip="239.255.255.250")
                )
            )

        self.assertEqual(alerts, [])

    def test_packets_outside_window_do_not_trigger_port_scan(self) -> None:
        detector = _detector(port_threshold=3)
        alerts = []

        for offset, port in zip([0, 11, 22], [21, 22, 23]):
            alerts.extend(detector.detect(_tcp_packet(offset, port)))

        self.assertEqual(alerts, [])

    def test_window_boundary_is_inclusive_for_port_scan(self) -> None:
        detector = _detector(port_threshold=3)
        alerts = []

        for offset, port in zip([0, 5, 10], [21, 22, 23]):
            alerts.extend(detector.detect(_tcp_packet(offset, port)))

        self.assertEqual(len(alerts), 1)

    def test_port_scan_alert_suppression_is_scoped_to_pair_and_window(self) -> None:
        detector = _detector(port_threshold=3)
        alerts = []

        for offset, port in enumerate([21, 22, 23, 25, 80]):
            alerts.extend(detector.detect(_tcp_packet(offset, port)))

        for offset, port in zip([5, 6, 7], [21, 22, 23]):
            alerts.extend(detector.detect(_tcp_packet_to(offset, "10.0.0.20", port)))

        self.assertEqual(len(alerts), 2)
        self.assertEqual({alert.dst_ip for alert in alerts}, {"10.0.0.10", "10.0.0.20"})

    def test_same_pair_can_alert_again_after_suppression_window(self) -> None:
        detector = _detector(port_threshold=3)
        alerts = []

        for offset, port in enumerate([21, 22, 23]):
            alerts.extend(detector.detect(_tcp_packet(offset, port)))
        for offset, port in zip([12, 13, 14], [25, 80, 110]):
            alerts.extend(detector.detect(_tcp_packet(offset, port)))

        self.assertEqual(len(alerts), 2)

    def test_horizontal_scan_threshold_alert(self) -> None:
        detector = _detector(horizontal_threshold=3)
        alerts = []

        for offset, host in enumerate(["10.0.0.10", "10.0.0.11", "10.0.0.12"]):
            alerts.extend(detector.detect(_tcp_packet_to(offset, host, 445)))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "threshold_alert")
        self.assertEqual(alerts[0].severity, 1)
        self.assertIn("Possible horizontal scan", alerts[0].message)
        self.assertEqual(alerts[0].dst_port, 445)

    def test_horizontal_scan_below_threshold_does_not_alert(self) -> None:
        detector = _detector(horizontal_threshold=3)
        alerts = []

        for offset, host in enumerate(["10.0.0.10", "10.0.0.11"]):
            alerts.extend(detector.detect(_tcp_packet_to(offset, host, 445)))

        self.assertEqual(alerts, [])

    def test_same_destination_host_does_not_count_as_horizontal_scan(self) -> None:
        detector = _detector(horizontal_threshold=3)
        alerts = []

        for offset in range(3):
            alerts.extend(detector.detect(_tcp_packet_to(offset, "10.0.0.10", 445)))

        self.assertEqual(alerts, [])

    def test_horizontal_scan_uses_same_destination_port(self) -> None:
        detector = _detector(horizontal_threshold=3)
        alerts = []

        for offset, (host, port) in enumerate(
            [("10.0.0.10", 21), ("10.0.0.11", 22), ("10.0.0.12", 23)]
        ):
            alerts.extend(detector.detect(_tcp_packet_to(offset, host, port)))

        self.assertEqual(alerts, [])

    def test_horizontal_scan_ignores_syn_ack_responses(self) -> None:
        detector = _detector(horizontal_threshold=3)
        alerts = []

        for offset, host in enumerate(["10.0.0.10", "10.0.0.11", "10.0.0.12"]):
            alerts.extend(detector.detect(_tcp_packet_to(offset, host, 445, flags="SA")))

        self.assertEqual(alerts, [])

    def test_same_horizontal_scan_key_can_alert_again_after_suppression_window(self) -> None:
        detector = _detector(horizontal_threshold=3)
        alerts = []

        for offset, host in zip([0, 1, 2], ["10.0.0.10", "10.0.0.11", "10.0.0.12"]):
            alerts.extend(detector.detect(_tcp_packet_to(offset, host, 445)))
        for offset, host in zip([12, 13, 14], ["10.0.0.20", "10.0.0.21", "10.0.0.22"]):
            alerts.extend(detector.detect(_tcp_packet_to(offset, host, 445)))

        self.assertEqual(len(alerts), 2)

    def test_icmp_echo_request_high_frequency_threshold_alert(self) -> None:
        detector = _detector(icmp_threshold=3)
        alerts = []

        for offset in range(3):
            alerts.extend(detector.detect(_icmp_packet(offset, icmp_type=8)))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "threshold_alert")
        self.assertEqual(alerts[0].severity, 2)
        self.assertIn("ICMP high frequency", alerts[0].message)

    def test_icmp_echo_request_below_threshold_does_not_alert(self) -> None:
        detector = _detector(icmp_threshold=3)
        alerts = []

        for offset in range(2):
            alerts.extend(detector.detect(_icmp_packet(offset, icmp_type=8)))

        self.assertEqual(alerts, [])

    def test_icmp_reply_does_not_trigger_high_frequency_alert(self) -> None:
        detector = _detector(icmp_threshold=3)
        alerts = []

        for offset in range(3):
            alerts.extend(detector.detect(_icmp_packet(offset, icmp_type=0, src_ip="8.8.8.8")))

        self.assertEqual(alerts, [])

    def test_threshold_alert_can_be_inserted_into_database(self) -> None:
        detector = _detector(port_threshold=3)
        alerts = []

        for offset, port in enumerate([21, 22, 23]):
            alerts.extend(detector.detect(_tcp_packet(offset, port)))

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "lightids.db"
            database = DatabaseManager(db_path)
            database.initialize()
            alert_id = database.insert_alert(alerts[0])

            connection = sqlite3.connect(db_path)
            try:
                row = connection.execute(
                    "SELECT alert_type, severity, message FROM alerts WHERE id = ?",
                    (alert_id,),
                ).fetchone()
            finally:
                connection.close()

        self.assertEqual(row, ("threshold_alert", 1, alerts[0].message))


if __name__ == "__main__":
    unittest.main()
