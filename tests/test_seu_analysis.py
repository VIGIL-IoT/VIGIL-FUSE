from vigil_fuse.seu_analysis import MAX_SEU_BYTES, inspect_critical_state


def test_observes_bounded_redundant_and_checksum_indicators() -> None:
    result = inspect_critical_state(b"""
        bool armed;
        uint32_t mission_timer;
        uint32_t thruster_state;
        uint32_t heater_state;
        uint32_t ordinary_count;
        if (mission_timer > 100) { reset(); }
        if (thruster_state != thruster_state_copy) { reset(); }
        if (check_crc(heater_state)) { reset(); }
        // if (armed > 0) { }
    """)
    states = {state.name: state for state in result.states}
    assert result.status == "partial"
    assert set(states) == {"armed", "mission_timer", "thruster_state", "heater_state"}
    assert states["armed"].status == "NO_PROTECTION_OBSERVED"
    for name in ("mission_timer", "thruster_state", "heater_state"):
        assert states[name].status == "PROTECTION_OBSERVED"
        assert states[name].indicators[0].startswith("line ")
        assert states[name].confidence == "low"


def test_ambiguous_and_incomplete_sources_are_not_clean() -> None:
    ambiguous = inspect_critical_state(b"bool armed;\nvoid f() { bool armed; }")
    assert ambiguous.states[0].status == "UNKNOWN"
    incomplete = inspect_critical_state(b"bool armed;\n/* unfinished")
    assert incomplete.states[0].status == "PARTIAL"
    assert inspect_critical_state(b"x" * (MAX_SEU_BYTES + 1)).status == "partial"


def test_unrelated_comparison_does_not_count_as_a_bound() -> None:
    result = inspect_critical_state(b"bool armed;\nif (x > y && armed) {}")
    assert result.states[0].status == "NO_PROTECTION_OBSERVED"
