from pathlib import Path

from vigil_fuse.build_context import inspect_platformio


def test_common_sections_and_ordered_parents_override_global_defaults(tmp_path: Path) -> None:
    (tmp_path / "platformio.ini").write_text(
        "[env]\nplatform = global\nboard = global\n"
        "[base]\nplatform = espressif32\nframework = arduino\n"
        "[first]\nboard = first\n"
        "[second]\nboard = second\n"
        "[env:release]\nextends = base, first, second ; later parent wins\n"
        "build_type = release\n"
        "[env:debug]\nextends = env:release\nboard = own\n",
        encoding="utf-8",
    )
    result = inspect_platformio(tmp_path)
    environments = {item.name: item for item in result.environments}
    assert result.status == "parsed"
    assert environments["release"].board == "second"
    assert environments["debug"].board == "own"
    assert environments["debug"].platform == "espressif32"
    assert environments["debug"].frameworks == ("arduino",)


def test_multiline_defaults_select_each_environment(tmp_path: Path) -> None:
    (tmp_path / "platformio.ini").write_text(
        "[platformio]\ndefault_envs =\n  one\n  two\n"
        "[env:one]\nboard = uno\n[env:two]\nboard = due\n",
        encoding="utf-8",
    )
    result = inspect_platformio(tmp_path)
    assert result.status == "parsed"
    assert result.selected_environments == ("one", "two")


def test_unresolved_metadata_is_partial_and_does_not_read_environment(tmp_path: Path) -> None:
    (tmp_path / "platformio.ini").write_text(
        "[env:board]\nboard = ${sysenv.FUSE_BOARD}\n", encoding="utf-8"
    )
    result = inspect_platformio(tmp_path)
    assert result.status == "partial"
    assert result.environments[0].board == "${sysenv.FUSE_BOARD}"
    assert any("unresolved interpolation" in item for item in result.limitations)


def test_inheritance_cycle_is_partial(tmp_path: Path) -> None:
    (tmp_path / "platformio.ini").write_text(
        "[a]\nextends = b\n[b]\nextends = a\n[env:board]\nextends = a\n",
        encoding="utf-8",
    )
    result = inspect_platformio(tmp_path)
    assert result.status == "partial"
    assert any("cycle" in item for item in result.limitations)


def test_large_board_matrix_remains_bounded(tmp_path: Path) -> None:
    configs = tmp_path / "variants"
    configs.mkdir()
    for index in range(200):
        (configs / f"{index:03}.ini").write_text(
            f"[env:board-{index}]\nboard = uno\n", encoding="utf-8"
        )
    (tmp_path / "platformio.ini").write_text(
        "[platformio]\nextra_configs = variants/*.ini\n", encoding="utf-8"
    )
    result = inspect_platformio(tmp_path)
    assert result.status == "parsed"
    assert len(result.environments) == 200
    assert len(result.configurations) == 201
