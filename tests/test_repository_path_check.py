from __future__ import annotations

from scripts.check_repository_paths import has_personal_profile_path


def test_detects_windows_profile_paths_without_matching_relative_paths() -> None:
    separator = bytes([92])
    path = (
        b"scan root: C:"
        + separator * 2
        + b"Users"
        + separator * 2
        + b"fixture-user"
        + separator * 2
        + b"embedded-project"
        + separator
        + b"main.c"
    )

    assert has_personal_profile_path(path)
    assert not has_personal_profile_path(b"embedded-project/src/main.c")


def test_detects_common_profile_names_in_absolute_paths() -> None:
    windows_prefix = b"C:" + b"/" + b"Users"
    home_prefix = b"/" + b"home"
    for username in (b"person", b"private", b"runner"):
        assert has_personal_profile_path(windows_prefix + b"/" + username + b"/project/file.c")
        assert has_personal_profile_path(home_prefix + b"/" + username + b"/project/file.c")


def test_detects_posix_home_paths_and_accepts_placeholders() -> None:
    path = b"project root: /" + b"home/" + b"fixture-user/embedded-project/src/main.c"

    assert has_personal_profile_path(path)
    assert not has_personal_profile_path(b"<USER_HOME>/embedded-project/src/main.c")
    assert not has_personal_profile_path(b"https://example.com/api/device")
