"""Reads the optional settings file from disk.

This module only fetches the text. Deciding what the text means, and whether
its values are allowed, is done by ``potato.core.config``.

The file is opened once and every check is made on that open file, not on the
path. Checking a path and then opening it leaves a gap in which the file could
be swapped for another.

A settings file that another account could have written is refused
(T-DATA-6 in ``docs/threat_model.md``). This does not defend against software
running as the same user, which the threat model places out of scope.
"""

import os
import stat
from pathlib import Path
from typing import Final

MAX_SETTINGS_BYTES: Final = 64 * 1024


class SettingsFileError(Exception):
    """The settings file exists but cannot be used safely."""


def default_settings_path() -> Path:
    """Return where Potato looks for its settings file on macOS."""
    return Path.home() / "Library" / "Application Support" / "Potato" / "settings.toml"


def read_settings_file(path: Path) -> str | None:
    """Return the text of the settings file, or ``None`` if there is none.

    A missing file is normal: Potato then runs on its built-in defaults.

    Args:
        path: Location of the settings file.

    Returns:
        The file's text, or ``None`` when the file does not exist.

    Raises:
        SettingsFileError: The file exists but is not a regular file, belongs
            to another user, can be written by other users, is too large or
            is not UTF-8 text.
    """
    try:
        # O_NONBLOCK: opening a named pipe would otherwise wait forever for a
        # writer. It has no effect on reading a regular file.
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SettingsFileError("the settings file could not be opened") from error

    try:
        _check_file(os.fstat(descriptor))
        # One byte more than allowed, so a file that grew after the size
        # check is still caught.
        data = _read_up_to(descriptor, MAX_SETTINGS_BYTES + 1)
    finally:
        os.close(descriptor)

    if len(data) > MAX_SETTINGS_BYTES:
        raise SettingsFileError("the settings file is too large")
    # The decoder's own error quotes bytes from the file, so it is dropped.
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    raise SettingsFileError("the settings file is not UTF-8 text")


def _check_file(status: os.stat_result) -> None:
    """Refuse anything that is not a small, regular file only its owner can change."""
    if not stat.S_ISREG(status.st_mode):
        raise SettingsFileError("the settings path is not a regular file")
    if status.st_uid != os.getuid():
        raise SettingsFileError("the settings file belongs to another user")
    if status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SettingsFileError(
            "the settings file can be changed by other users; "
            "remove write permission for group and others"
        )
    if status.st_size > MAX_SETTINGS_BYTES:
        raise SettingsFileError("the settings file is too large")


def _read_up_to(descriptor: int, limit: int) -> bytes:
    """Read at most ``limit`` bytes. A single ``os.read`` may return fewer."""
    chunks = []
    remaining = limit
    while remaining > 0:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
