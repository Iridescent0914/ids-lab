from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.rules.rule_parser import load_rules, parse_rule_line


class RuleParserTests(unittest.TestCase):
    def test_parse_tcp_content_rule(self) -> None:
        rule = parse_rule_line(
            'alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1003; '
            'priority:4; content:"GET"; nocase;)',
            line_number=1,
        )

        self.assertTrue(rule.is_valid)
        self.assertEqual(rule.protocol, "tcp")
        self.assertEqual(rule.dst_port, "80")
        self.assertEqual(rule.message, "HTTP traffic detected")
        self.assertEqual(rule.sid, 1003)
        self.assertEqual(rule.priority, 4)
        self.assertEqual(rule.content, "GET")
        self.assertTrue(rule.nocase)

    def test_parse_tcp_flags_rule(self) -> None:
        rule = parse_rule_line(
            'alert tcp any any -> any any (msg:"TCP SYN packet detected"; sid:1004; '
            "priority:4; flags:S;)",
            line_number=1,
        )

        self.assertTrue(rule.is_valid)
        self.assertEqual(rule.flags, "S")

    def test_parse_icmp_type_rule(self) -> None:
        rule = parse_rule_line(
            'alert icmp any any -> any any (msg:"ICMP echo request observed"; '
            "sid:1001; priority:4; itype:8;)",
            line_number=1,
        )

        self.assertTrue(rule.is_valid)
        self.assertEqual(rule.icmp_type, 8)

    def test_parse_icmp_type_alias_rule(self) -> None:
        rule = parse_rule_line(
            'alert icmp any any -> any any (msg:"ICMP echo request observed"; '
            "sid:1001; priority:4; icmp_type:8;)",
            line_number=1,
        )

        self.assertTrue(rule.is_valid)
        self.assertEqual(rule.icmp_type, 8)

    def test_detect_mismatched_icmp_type_aliases(self) -> None:
        rule = parse_rule_line(
            'alert icmp any any -> any any (msg:"ICMP echo request observed"; '
            "sid:1001; priority:4; itype:8; icmp_type:0;)",
            line_number=1,
        )

        self.assertFalse(rule.is_valid)
        self.assertIn("itype and icmp_type must match when both are set", rule.errors)

    def test_detect_missing_sid_and_bad_priority(self) -> None:
        rule = parse_rule_line(
            'alert icmp any any -> any any (msg:"ICMP packet"; priority:high;)',
            line_number=1,
        )

        self.assertFalse(rule.is_valid)
        self.assertIn("missing sid", rule.errors)
        self.assertIn("priority must be a number", rule.errors)

    def test_detect_duplicate_sid_when_loading_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "default.rules"
            path.write_text(
                "\n".join(
                    [
                        'alert icmp any any -> any any (msg:"one"; sid:1001; priority:3;)',
                        'alert tcp any any -> any 80 (msg:"two"; sid:1001; priority:3;)',
                    ]
                ),
                encoding="utf-8",
            )

            result = load_rules(path)

        self.assertEqual(len(result.rules), 2)
        self.assertTrue(result.rules[0].is_valid)
        self.assertFalse(result.rules[1].is_valid)
        self.assertIn("duplicate sid 1001", result.rules[1].errors[0])


if __name__ == "__main__":
    unittest.main()
