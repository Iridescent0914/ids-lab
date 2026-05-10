from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP
from scapy.packet import Raw

from app.detection.rule_engine import rule_matches_packet
from app.detection.signature_detector import SignatureDetector
from app.parser.models import AlertEvent
from app.parser.protocol_parser import parse_packet
from app.rules.rule_parser import parse_rule_line
from app.storage.database import DatabaseManager


class RuleEngineTests(unittest.TestCase):
    def test_port_rule_matches_packet(self) -> None:
        rule = parse_rule_line(
            'alert tcp any any -> any 22 (msg:"SSH access observed"; sid:1002; priority:2;)'
        )
        packet = parse_packet(IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=44444, dport=22))

        self.assertTrue(rule_matches_packet(rule, packet))

    def test_content_nocase_rule_matches_payload(self) -> None:
        rule = parse_rule_line(
            'alert tcp any any -> any 80 (msg:"HTTP GET request observed"; sid:1006; '
            'priority:4; content:"get"; nocase;)'
        )
        packet = parse_packet(
            IP(src="10.0.0.2", dst="10.0.0.3")
            / TCP(sport=44444, dport=80)
            / Raw(load=b"GET /index.html HTTP/1.1\r\n")
        )

        self.assertTrue(rule_matches_packet(rule, packet))

    def test_flags_rule_matches_tcp_syn(self) -> None:
        rule = parse_rule_line(
            'alert tcp any any -> any any (msg:"TCP SYN packet observed"; sid:1005; '
            "priority:4; flags:S;)"
        )
        packet = parse_packet(IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=44444, dport=80, flags="S"))

        self.assertTrue(rule_matches_packet(rule, packet))

    def test_flags_rule_does_not_match_syn_ack(self) -> None:
        rule = parse_rule_line(
            'alert tcp any any -> any any (msg:"TCP SYN packet observed"; sid:1005; '
            "priority:4; flags:S;)"
        )
        packet = parse_packet(
            IP(src="10.0.0.3", dst="10.0.0.2") / TCP(sport=80, dport=44444, flags="SA")
        )

        self.assertFalse(rule_matches_packet(rule, packet))

    def test_disabled_rule_does_not_match(self) -> None:
        rule = parse_rule_line(
            'alert icmp any any -> any any (msg:"ICMP packet observed"; sid:1001; priority:4;)'
        )
        rule.enabled = False
        packet = parse_packet(IP(src="10.0.0.2", dst="8.8.8.8") / ICMP())

        self.assertFalse(rule_matches_packet(rule, packet))

    def test_signature_detector_creates_alert_and_updates_rule_hit(self) -> None:
        rule = parse_rule_line(
            'alert icmp any any -> any any (msg:"ICMP packet observed"; sid:1001; priority:4;)'
        )
        packet = parse_packet(IP(src="10.0.0.2", dst="8.8.8.8") / ICMP())

        alerts = SignatureDetector([rule]).detect(packet)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].message, "ICMP packet observed")
        self.assertEqual(alerts[0].alert_type, "rule_event")
        self.assertEqual(alerts[0].rule_sid, 1001)
        self.assertEqual(rule.hit_count, 1)
        self.assertIsNotNone(rule.last_hit)

    def test_database_insert_alert(self) -> None:
        rule = parse_rule_line(
            'alert icmp any any -> any any (msg:"ICMP packet observed"; sid:1001; priority:4;)'
        )
        packet = parse_packet(IP(src="10.0.0.2", dst="8.8.8.8") / ICMP())
        alert = SignatureDetector([rule]).detect(packet)[0]

        with tempfile.TemporaryDirectory() as temp_dir:
            database = DatabaseManager(Path(temp_dir) / "lightids.db")
            database.initialize()
            alert_id = database.insert_alert(alert)

        self.assertEqual(alert_id, 1)

    def test_database_fetch_and_clear_alerts(self) -> None:
        rule = parse_rule_line(
            'alert icmp any any -> any any (msg:"ICMP packet observed"; sid:1001; priority:4;)'
        )
        packet = parse_packet(IP(src="10.0.0.2", dst="8.8.8.8") / ICMP())
        alert = SignatureDetector([rule]).detect(packet)[0]

        with tempfile.TemporaryDirectory() as temp_dir:
            database = DatabaseManager(Path(temp_dir) / "lightids.db")
            database.initialize()
            database.insert_alert(alert)

            alerts = database.fetch_alerts()
            deleted_count = database.clear_alerts()
            remaining_alerts = database.fetch_alerts()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "rule_event")
        self.assertEqual(alerts[0].rule_sid, 1001)
        self.assertEqual(alerts[0].message, "ICMP packet observed")
        self.assertEqual(deleted_count, 1)
        self.assertEqual(remaining_alerts, [])

    def test_database_insert_alerts_batch(self) -> None:
        rule = parse_rule_line(
            'alert icmp any any -> any any (msg:"ICMP packet observed"; sid:1001; priority:4;)'
        )
        packets = [
            parse_packet(IP(src=f"10.0.0.{index}", dst="8.8.8.8") / ICMP())
            for index in range(2, 5)
        ]
        alerts = []
        for packet in packets:
            alerts.extend(SignatureDetector([rule]).detect(packet))

        with tempfile.TemporaryDirectory() as temp_dir:
            database = DatabaseManager(Path(temp_dir) / "lightids.db")
            database.initialize()
            inserted_count = database.insert_alerts(alerts)
            stored_alerts = database.fetch_alerts()

        self.assertEqual(inserted_count, 3)
        self.assertEqual(len(stored_alerts), 3)

    def test_database_fetch_alerts_by_type(self) -> None:
        rule_alert = AlertEvent(
            timestamp=datetime(2026, 5, 9, 12, 0, 0),
            message="ICMP packet observed",
            severity=4,
            protocol="ICMP",
            alert_type="rule_event",
            rule_sid=1001,
        )
        threshold_alert = AlertEvent(
            timestamp=datetime(2026, 5, 9, 12, 0, 1),
            message="Possible port scan detected",
            severity=1,
            protocol="TCP",
            alert_type="threshold_alert",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            database = DatabaseManager(Path(temp_dir) / "lightids.db")
            database.initialize()
            database.insert_alerts([rule_alert, threshold_alert])

            all_alerts = database.fetch_alerts()
            threshold_alerts = database.fetch_alerts("threshold_alert")
            rule_alerts = database.fetch_alerts("rule_event")

        self.assertEqual(len(all_alerts), 2)
        self.assertEqual(len(threshold_alerts), 1)
        self.assertEqual(threshold_alerts[0].alert_type, "threshold_alert")
        self.assertEqual(len(rule_alerts), 1)
        self.assertEqual(rule_alerts[0].alert_type, "rule_event")


if __name__ == "__main__":
    unittest.main()
