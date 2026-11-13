"""Tests for the checks on log folders and files (T-DATA-2)."""

import os
import stat
import threading
from pathlib import Path

import pytest

from potato.security.private_files import (
    PrivateFileError,
    ensure_private_directory,
    open_private_append,
)


def test_a_new_folder_is_created_private(tmp_path: Path) -> None:
    folder = tmp_path / "a" / "b" / "logs"

    ensure_private_directory(folder)

    assert stat.S_IMODE(folder.stat().st_mode) == 0o700


def test_a_file_where_the_folder_should_be_is_refused(tmp_path: Path) -> None:
    (tmp_path / "logs").write_text("", encoding="utf-8")

    with pytest.raises(FileExistsError):
        ensure_private_directory(tmp_path / "logs")


def test_a_folder_owned_by_someone_else_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    someone_else = os.getuid() + 1
    monkeypatch.setattr(os, "getuid", lambda: someone_else)

    with pytest.raises(PrivateFileError, match="another user"):
        ensure_private_directory(tmp_path / "logs")


def test_a_new_file_is_created_private_and_appends(tmp_path: Path) -> None:
    path = tmp_path / "file.log"

    for text in (b"one\n", b"two\n"):
        descriptor = open_private_append(path)
        os.write(descriptor, text)
        os.close(descriptor)

    assert path.read_bytes() == b"one\ntwo\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_file_owned_by_someone_else_is_refused_and_not_left_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "file.log"
    path.write_text("", encoding="utf-8")
    someone_else = os.getuid() + 1
    monkeypatch.setattr(os, "getuid", lambda: someone_else)
    before = len(list(Path("/dev/fd").iterdir()))

    with pytest.raises(PrivateFileError, match="another user"):
        open_private_append(path)

    assert len(list(Path("/dev/fd").iterdir())) == before


def test_a_folder_where_the_file_should_be_is_refused(tmp_path: Path) -> None:
    (tmp_path / "file.log").mkdir()

    with pytest.raises(PrivateFileError):
        open_private_append(tmp_path / "file.log")


def test_a_named_pipe_with_a_reader_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "file.log"
    os.mkfifo(path)
    reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        with pytest.raises(PrivateFileError, match="not a regular file"):
            open_private_append(path)
    finally:
        os.close(reader)


def test_a_named_pipe_without_a_reader_is_refused_without_waiting(tmp_path: Path) -> None:
    # Opening such a pipe for writing normally waits for a reader. The attempt
    # runs in a helper thread so that a regression fails quickly.
    path = tmp_path / "file.log"
    os.mkfifo(path)
    outcome: list[object] = []

    def attempt() -> None:
        try:
            outcome.append(open_private_append(path))
        except PrivateFileError as error:
            outcome.append(error)

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive(), "opening a named pipe blocked"
    assert isinstance(outcome[0], PrivateFileError)
