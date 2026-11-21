from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from vigil_fuse.flight_bus import (
    analyze_flight_bus,
    load_flight_bus_policy,
    parse_flight_bus_policy,
)
from vigil_fuse.scanner import scan
from vigil_fuse.model import SourceFile


def policy(*, validation: dict[str, str] | None = None) -> bytes:
    return json.dumps(
        {
            "version": 1,
            "applications": {
                "payload_app": {"trust_zone": "lower_trust"},
                "adcs_app": {"trust_zone": "flight_critical"},
            },
            "command_message_ids": ["ADCS_CMD_MID"],
            "message_origin_validation": validation or {},
        }
    ).encode()


def sources(*, subscriber: bool = True, alternate_api: bool = False) -> tuple[SourceFile, ...]:
    init = "CFE_SB_InitMsg(&Cmd, ADCS_CMD_MID, sizeof(Cmd), true);" if alternate_api else (
        "CFE_MSG_Init(&Cmd, CFE_SB_ValueToMsgId(ADCS_CMD_MID), sizeof(Cmd));"
    )
    transmit = "CFE_SB_TransmitBuffer(&Cmd);" if alternate_api else "CFE_SB_TransmitMsg(&Cmd, true);"
    publisher = SourceFile(
        path="payload_app.c",
        text=f"#define ADCS_CMD_MID 0x1802\nvoid publish(void) {{ {init} {transmit} }}\n",
    )
    if not subscriber:
        return (publisher,)
    subscribe = "CFE_SB_SubscribeEx(ADCS_CMD_MID, CmdPipe, &Qos, 8);" if alternate_api else (
        "CFE_SB_Subscribe(CFE_SB_ValueToMsgId(ADCS_CMD_MID), CmdPipe);"
    )
    consumer = SourceFile(
        path="adcs_app.c",
        text=(
            "#define ADCS_CMD_MID 0x1802\n"
            f"void init(void) {{ CFE_SB_CreatePipe(&CmdPipe, 8, \"cmd\"); {subscribe} }}\n"
        ),
    )
    return (publisher, consumer)


class FlightBusTests(unittest.TestCase):
    def test_publisher_subscriber_path_requires_explicit_policy(self) -> None:
        result = analyze_flight_bus(sources(), None)

        self.assertEqual(1, result.edge_count)
        self.assertEqual((), result.findings)
        self.assertEqual("partial", result.status)
        self.assertTrue(any("No operator mission policy" in item for item in result.limitations))

    def test_lower_trust_publisher_to_critical_command_subscriber_is_candidate(self) -> None:
        mission = parse_flight_bus_policy(policy())

        result = analyze_flight_bus(sources(), mission)

        self.assertEqual(1, len(result.findings))
        finding = result.findings[0]
        self.assertEqual("FUSE-FSW-001", finding.rule_id)
        self.assertEqual("unknown", finding.severity)
        self.assertEqual("candidate", finding.applicability)
        self.assertIn("operator-declared", finding.explanation)
        self.assertIn("CFE_SB_TransmitMsg", finding.evidence)
        self.assertIn("pipe creation observed in that source: yes", finding.evidence)

    def test_supported_older_and_newer_api_names_are_correlated(self) -> None:
        mission = parse_flight_bus_policy(policy())

        result = analyze_flight_bus(sources(alternate_api=True), mission)

        self.assertEqual(1, result.edge_count)
        self.assertEqual(1, len(result.findings))

    def test_no_subscriber_means_no_message_path(self) -> None:
        mission = parse_flight_bus_policy(policy())

        result = analyze_flight_bus(sources(subscriber=False), mission)

        self.assertEqual(0, result.edge_count)
        self.assertEqual((), result.findings)

    def test_operator_declared_origin_validation_is_not_reported_as_missing(self) -> None:
        mission = parse_flight_bus_policy(policy(validation={"0x1802": "present"}))

        result = analyze_flight_bus(sources(), mission)

        self.assertEqual((), result.findings)
        self.assertEqual(1, result.operator_validated_edges)

    def test_comments_and_string_literals_do_not_create_api_edges(self) -> None:
        source = SourceFile(
            path="payload_app.c",
            text='/* CFE_SB_TransmitMsg(&Cmd, true); */\nconst char *s = "CFE_SB_TransmitMsg";\n',
        )

        result = analyze_flight_bus((source,), parse_flight_bus_policy(policy()))

        self.assertEqual(0, result.edge_count)
        self.assertEqual((), result.findings)

    def test_malformed_policy_is_rejected(self) -> None:
        for data in (b"{", b'{"version":2,"applications":{}}'):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    parse_flight_bus_policy(data)
        with self.assertRaisesRegex(ValueError, "trust_zone"):
            parse_flight_bus_policy(
                json.dumps({"version": 1, "applications": {"PAYLOAD": {}}}).encode()
            )

    def test_policy_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                load_flight_bus_policy(root, "../outside.json")

    def test_scanner_integration_emits_candidate_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "payload_app.c").write_text(sources()[0].text, encoding="utf-8")
            (root / "adcs_app.c").write_text(sources()[1].text, encoding="utf-8")
            (root / "mission_policy.json").write_bytes(policy())

            result = scan(root, profile="cfs", flight_bus_policy="mission_policy.json")

        self.assertTrue(any(item.rule_id == "FUSE-FSW-001" for item in result.findings))
        status = next(item for item in result.analyzers if item.name == "cfs-software-bus-static")
        self.assertEqual("partial", status.status)


if __name__ == "__main__":
    unittest.main()
