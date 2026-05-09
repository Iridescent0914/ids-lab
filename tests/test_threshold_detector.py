from __future__ import annotations

import unittest
from datetime import datetime, timedelta

from app.detection.threshold_detector import ThresholdDetector, ThresholdSettings
from app.parser.models import PacketInfo


class ThresholdDetectorTests(unittest.TestCase):
    def test_port_scan_threshold_alert(self) -> None:
        detector = ThresholdDetector(
            ThresholdSettings(
                window_seconds=10,
                port_scan_unique_ports=3,
                icmp_high_frequency_count=5,
            )
        )
        base_time = datetime(2026, 5, 9, 12, 0, 0)
        alerts = []

        for offset, port in enumerate([21, 22, 23]):
            alerts.extend(
                detector.detect(
                    PacketInfo(
                        timestamp=base_time + timedelta(seconds=offset),
                        protocol="TCP",
                        packet_length=60,
                        src_ip="10.0.0.2",
                        dst_ip="10.0.0.10",
                        src_port=40000 + offset,
                        dst_port=port,
                        tcp_flags="S",
                    )
                )
            )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "threshold_alert")
        self.assertEqual(alerts[0].severity, 1)
        self.assertIn("Possible port scan", alerts[0].message)

    def test_icmp_high_frequency_threshold_alert(self) -> None:
        detector = ThresholdDetector(
            ThresholdSettings(
                window_seconds=10,
                port_scan_unique_ports=5,
                icmp_high_frequency_count=3,
            )
        )
        base_time = datetime(2026, 5, 9, 12, 0, 0)
        alerts = []

        for offset in range(3):
            alerts.extend(
                detector.detect(
                    PacketInfo(
                        timestamp=base_time + timedelta(seconds=offset),
                        protocol="ICMP",
                        packet_length=60,
                        src_ip="10.0.0.2",
                        dst_ip="8.8.8.8",
                        icmp_type=8,
                        icmp_code=0,
                    )
                )
            )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "threshold_alert")
        self.assertEqual(alerts[0].severity, 2)
        self.assertIn("ICMP high frequency", alerts[0].message)

    def test_icmp_reply_does_not_trigger_high_frequency_alert(self) -> None:
        detector = ThresholdDetector(
            ThresholdSettings(
                window_seconds=10,
                port_scan_unique_ports=5,
                icmp_high_frequency_count=3,
            )
        )
        base_time = datetime(2026, 5, 9, 12, 0, 0)
        alerts = []

        for offset in range(3):
            alerts.extend(
                detector.detect(
                    PacketInfo(
                        timestamp=base_time + timedelta(seconds=offset),
                        protocol="ICMP",
                        packet_length=60,
                        src_ip="8.8.8.8",
                        dst_ip="10.0.0.2",
                        icmp_type=0,
                        icmp_code=0,
                    )
                )
            )

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
