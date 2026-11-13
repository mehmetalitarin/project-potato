"""Application logging: one JSON object per line, with secrets removed.

Every record passes through the redactor at the last possible moment, after
the message, its arguments, any extra fields and any exception text have been
put together. Redacting earlier would miss a secret that only appears once
the pieces are joined (T-DATA-1 in ``docs/threat_model.md``).

The handlers are installed on the root logger, so records from third-party
libraries are redacted as well. Each record is written as JSON on a single
line with control characters escaped, so text from outside cannot forge a
second log entry or send escape codes to a terminal.

This is the ordinary application log. The record of security decisions is
the audit log, in ``potato.security.audit``.
"""

import json
import logging
import os
import traceback
from datetime import UTC, datetime
from io import TextIOWrapper
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Final

from potato.security.private_files import ensure_private_directory, open_private_append
from potato.security.redaction import Redactor

LOG_FILE_NAME: Final = "potato.log"
MAX_LOG_BYTES: Final = 1024 * 1024
LOG_FILES_KEPT: Final = 5

# Longer text is cut, after redaction, so one record cannot fill the disk.
MAX_TEXT_CHARACTERS: Final = 8192
_CUT_MARKER: Final = " ...[cut]"

# What every LogRecord carries. Anything else was passed with ``extra=``.
_STANDARD_ATTRIBUTES: Final = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message",
    "asctime",
    "taskName",
}


def default_log_directory() -> Path:
    """Return where Potato keeps its logs on macOS."""
    return Path.home() / "Library" / "Logs" / "Potato"


class JsonFormatter(logging.Formatter):
    """Formats a record as one line of JSON, redacting every piece of text."""

    def __init__(self, redactor: Redactor) -> None:
        """Create a formatter that removes secrets with ``redactor``."""
        super().__init__()
        self._redactor = redactor

    def _clean(self, text: str) -> str:
        text = self._redactor.redact(text)
        if len(text) > MAX_TEXT_CHARACTERS:
            text = text[:MAX_TEXT_CHARACTERS] + _CUT_MARKER
        return text

    def format(self, record: logging.LogRecord) -> str:
        """Return the record as a single line of JSON."""
        try:
            message = record.getMessage()
        except Exception:
            # The message and its arguments did not fit together. The pieces
            # are not logged separately, since either could hold a secret.
            message = "[log message could not be formatted]"

        created = datetime.fromtimestamp(record.created, tz=UTC)
        entry: dict[str, Any] = {
            "time": created.isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": self._clean(record.name),
            "message": self._clean(message),
        }
        fields = {
            name: value
            for name, value in vars(record).items()
            if name not in _STANDARD_ATTRIBUTES and not name.startswith("_")
        }
        if fields:
            entry["fields"] = self._redactor.redact_value(fields)
        if record.exc_info:
            entry["exception"] = self._clean("".join(traceback.format_exception(*record.exc_info)))
        if record.stack_info:
            entry["stack"] = self._clean(record.stack_info)
        return json.dumps(entry, ensure_ascii=True, separators=(",", ":"))


class PrivateRotatingFileHandler(RotatingFileHandler):
    """A rotating log file that only its owner can read."""

    def _open(self) -> TextIOWrapper:
        descriptor = open_private_append(Path(self.baseFilename))
        return os.fdopen(descriptor, "a", encoding="utf-8", errors="backslashreplace")


def configure_logging(
    directory: Path, redactor: Redactor, *, level: int = logging.INFO
) -> logging.Handler:
    """Send all logging to a private, rotating, redacted JSON file.

    Any handlers already on the root logger are removed, because they would
    write records that have not been redacted.

    Args:
        directory: Folder for the log files. Created if needed, and made
            private to the user.
        redactor: Removes secrets from every record.
        level: Lowest level that is written.

    Returns:
        The installed handler, so that the caller can remove it on shutdown.

    Raises:
        PrivateFileError: The folder or file is not safe to use.
    """
    ensure_private_directory(directory)
    handler = PrivateRotatingFileHandler(
        directory / LOG_FILE_NAME,
        maxBytes=MAX_LOG_BYTES,
        backupCount=LOG_FILES_KEPT,
        encoding="utf-8",
    )
    handler.setFormatter(JsonFormatter(redactor))

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    return handler
