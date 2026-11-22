import pytest

from vigil_fuse.flight_bus import MAX_BUS_FILE_BYTES, build_bus_graph, extract_bus_calls


def test_extracts_calls_with_nested_arguments_and_ignores_comments_and_strings() -> None:
    source = b"""// CFE_SB_Subscribe(FAKE, fake)
        const char *s = "CFE_SB_CreatePipe(fake)";
        CFE_SB_CreatePipe(&app.pipe, DEPTH, "cmd,pipe");
        CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CMD_MID), app.pipe);
        CFE_SB_TransmitMsg(CFE_MSG_PTR(app.Msg), true);
    """
    result = extract_bus_calls({"app.c": source})
    assert result.status == "partial"
    assert [call.api for call in result.calls] == [
        "CFE_SB_CreatePipe",
        "CFE_SB_Subscribe",
        "CFE_SB_TransmitMsg",
    ]
    assert result.calls[0].arguments == ("&app.pipe", "DEPTH", '"cmd,pipe"')
    assert result.calls[1].arguments == ("CFE_SB_ValueToMsgId(CMD_MID)", "app.pipe")
    assert result.calls[1].line == 4


def test_bounded_and_malformed_sources_remain_partial() -> None:
    result = extract_bus_calls(
        {"big.c": b"x" * (MAX_BUS_FILE_BYTES + 1), "bad.c": b"CFE_SB_Subscribe(X, ("}
    )
    assert result.status == "partial"
    assert not result.calls
    assert len(result.limitations) >= 3


def test_file_order_and_duplicate_calls_are_deterministic() -> None:
    call = b"CFE_SB_Subscribe(CMD_MID, pipe); CFE_SB_Subscribe(CMD_MID, pipe);"
    result = extract_bus_calls({"z.c": call, "a.c": call})
    assert [item.file for item in result.calls] == ["a.c", "a.c", "z.c", "z.c"]


def test_graph_uses_explicit_application_and_does_not_guess_transmit_message_id() -> None:
    calls = extract_bus_calls(
        {
            "app.c": b"""
      CFE_SB_CreatePipe(&app.pipe, DEPTH, "PIPE");
      CFE_SB_Subscribe(CMD_MID, app.pipe);
      CFE_SB_Subscribe(CMD_MID, app.pipe);
      CFE_SB_TransmitMsg(CFE_MSG_PTR(app.message), true);
    """
        }
    )
    graph = build_bus_graph(calls, {"app.c": "Payload"})
    assert graph.status == "partial"
    assert [edge.relation for edge in graph.edges] == [
        "creates",
        "subscribes_to",
        "subscribes_to",
        "subscribes_to",
        "subscribes_to",
        "transmits",
    ]
    transmitted = next(edge for edge in graph.edges if edge.relation == "transmits")
    assert next(node for node in graph.nodes if node.id == transmitted.target).kind == (
        "message_object_expression"
    )
    assert graph.to_json() == build_bus_graph(calls, {"app.c": "Payload"}).to_json()
    assert not build_bus_graph(calls, {}).edges
    assert len(graph.observations) == 1
    observation = graph.observations[0]
    assert observation.rule_id == "FUSE-FSW-001" and observation.count == 2
    assert observation.validation_status == "not-validated"
    assert observation.severity == "unknown"


def test_subscriptions_on_different_pipes_are_not_duplicate() -> None:
    calls = extract_bus_calls({"app.c": b"CFE_SB_Subscribe(MID, a); CFE_SB_Subscribe(MID, b);"})
    assert not build_bus_graph(calls, {"app.c": "app"}).observations


def test_graph_json_output_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    graph = build_bus_graph(
        extract_bus_calls({"a.c": b"CFE_SB_Subscribe(MID, pipe);"}), {"a.c": "app"}
    )
    monkeypatch.setattr("vigil_fuse.flight_bus.MAX_BUS_GRAPH_JSON_BYTES", 100)
    with pytest.raises(ValueError, match="size limit"):
        graph.to_json()


def test_set_message_id_and_transmit_share_only_identical_symbolic_object() -> None:
    calls = extract_bus_calls(
        {
            "app.c": b"""
      CFE_MSG_SetMsgId(CFE_MSG_PTR(app.Msg), CFE_SB_ValueToMsgId(CMD_MID));
      CFE_SB_TransmitMsg(CFE_MSG_PTR(app.Msg), true);
    """
        }
    )
    graph = build_bus_graph(calls, {"app.c": "PAYLOAD"})
    setter = next(edge for edge in graph.edges if edge.relation == "sets_message_id")
    sender = next(edge for edge in graph.edges if edge.relation == "transmits")
    assert setter.source == sender.target
    assert next(node for node in graph.nodes if node.id == setter.target).label == (
        "CFE_SB_ValueToMsgId(CMD_MID)"
    )
    assert graph.status == "partial"
