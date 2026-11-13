"""Tests for reading the settings file from disk safely (T-DATA-6)."""

import os
import stat
import threading
from pathlib import Path

import pytest

from potato.core.config import Settings, parse_settings
from potato.storage.settings_file import (
    MAX_SETTINGS_BYTES,
    SettingsFileError,
    default_settings_path,
    read_settings_file,
)


@pytest.fixture
def path(tmp_path: Path) -> Path:
    return tmp_path / "settings.toml"


def _write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Create the file with explicit permissions, whatever the umask is."""
    path.write_bytes(data)
    path.chmod(mode)


def test_default_path_is_inside_the_users_library() -> None:
    location = default_settings_path()

    assert location.is_relative_to(Path.home() / "Library" / "Application Support")
    assert location.name == "settings.toml"


def test_a_missing_file_is_not_an_error(path: Path) -> None:
    assert read_settings_file(path) is None


def test_a_normal_file_is_read(path: Path) -> None:
    _write(path, b'[ollama]\nhost = "::1"\n')

    assert read_settings_file(path) == '[ollama]\nhost = "::1"\n'


def test_reading_and_parsing_work_together(path: Path) -> None:
    _write(path, b"[assistant]\nidle_timeout_seconds = 120\n")

    text = read_settings_file(path)

    assert text is not None
    assert parse_settings(text).assistant.idle_timeout_seconds == 120


def test_no_file_means_the_defaults(path: Path) -> None:
    assert parse_settings(read_settings_file(path) or "") == Settings()


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o622, 0o666, 0o777])
def test_a_file_others_can_write_is_refused(path: Path, mode: int) -> None:
    _write(path, b"", mode)

    with pytest.raises(SettingsFileError, match="changed by other users"):
        read_settings_file(path)


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644, 0o400])
def test_a_file_only_the_owner_can_write_is_accepted(path: Path, mode: int) -> None:
    _write(path, b"", mode)

    assert read_settings_file(path) == ""


def test_a_file_owned_by_someone_else_is_refused(
    path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(path, b"")
    someone_else = os.getuid() + 1
    monkeypatch.setattr(os, "getuid", lambda: someone_else)

    with pytest.raises(SettingsFileError, match="another user"):
        read_settings_file(path)


def test_a_directory_is_refused(path: Path) -> None:
    path.mkdir()

    with pytest.raises(SettingsFileError, match="not a regular file"):
        read_settings_file(path)


def test_a_named_pipe_is_refused_without_waiting(path: Path) -> None:
    # Opening a pipe normally blocks until something writes to it. The read
    # runs in a helper thread so that a regression fails this test quickly
    # instead of hanging the whole run.
    os.mkfifo(path)
    assert stat.S_ISFIFO(path.stat().st_mode)
    outcome: list[BaseException | str | None] = []

    def attempt() -> None:
        try:
            outcome.append(read_settings_file(path))
        except SettingsFileError as error:
            outcome.append(error)

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive(), "reading a named pipe blocked"
    assert isinstance(outcome[0], SettingsFileError)
    assert "not a regular file" in str(outcome[0])


def test_a_symlink_to_a_missing_file_is_treated_as_missing(path: Path) -> None:
    path.symlink_to(path.with_name("does-not-exist.toml"))

    assert read_settings_file(path) is None


def test_a_file_at_the_size_limit_is_read(path: Path) -> None:
    _write(path, b"#" * MAX_SETTINGS_BYTES)

    text = read_settings_file(path)

    assert text is not None
    assert len(text) == MAX_SETTINGS_BYTES


def test_an_oversized_file_is_refused(path: Path) -> None:
    _write(path, b"#" * (MAX_SETTINGS_BYTES + 1))

    with pytest.raises(SettingsFileError, match="too large"):
        read_settings_file(path)


def test_a_file_that_is_not_utf8_is_refused(path: Path) -> None:
    _write(path, b"\xff\xfe\x00[")

    with pytest.raises(SettingsFileError, match="not UTF-8"):
        read_settings_file(path)


def test_errors_do_not_reveal_file_contents(path: Path) -> None:
    _write(path, b"secret-canary \xff")

    with pytest.raises(SettingsFileError) as raised:
        read_settings_file(path)

    assert "secret-canary" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_refusing_a_file_does_not_leave_it_open(path: Path) -> None:
    path.mkdir()
    before = len(list(Path("/dev/fd").iterdir()))

    for _ in range(5):
        with pytest.raises(SettingsFileError):
            read_settings_file(path)

    assert len(list(Path("/dev/fd").iterdir())) == before
