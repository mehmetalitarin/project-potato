"""Tests for application logging.

The central test plants a secret in every place a log record can carry text
and then searches the log files for it. This is item 11 of the
specification's required security tests: "secrets are not written to logs"
(T-DATA-1 in docs/threat_model.md).
"""

import json
import logging
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from potato.security.logs import (
    LOG_FILE_NAME,
    LOG_FILES_KEPT,
    MAX_TEXT_CHARACTERS,
    JsonFormatter,
    configure_logging,
    default_log_directory,
)
from potato.security.private_files import PrivateFileError
from potato.security.redaction import REDACTED, Redactor

CANARY = "-".join(["canary", "fake", "value", "0003"])


@pytest.fixture
def redactor() -> Redactor:
    redactor = Redactor()
    redactor.register_secret(CANARY)
    return redactor


@pytest.fixture
def clean_root_logger() -> Iterator[None]:
    """Put the root logger back as it was, so tests do not affect each other."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    for handler in list(root.handlers):
        if handler not in handlers:
            root.removeHandler(handler)
            handler.close()
    for handler in handlers:
        if handler not in root.handlers:
            root.addHandler(handler)
    root.setLevel(level)


@pytest.fixture
def directory(tmp_path: Path, redactor: Redactor, clean_root_logger: None) -> Path:
    directory = tmp_path / "Logs" / "Potato"
    configure_logging(directory, redactor)
    return directory


def _entries(directory: Path) -> list[dict[str, Any]]:
    for handler in logging.getLogger().handlers:
        handler.flush()
    text = (directory / LOG_FILE_NAME).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def _everything_written(directory: Path) -> str:
    for handler in logging.getLogger().handlers:
        handler.flush()
    return "".join(path.read_text(encoding="utf-8") for path in sorted(directory.iterdir()))


def test_default_directory_is_the_users_log_folder() -> None:
    assert default_log_directory() == Path.home() / "Library" / "Logs" / "Potato"


# --- Secrets are not written to logs (T-DATA-1) --------------------------------


def test_a_secret_never_reaches_the_log_file(directory: Path) -> None:
    logger = logging.getLogger("potato.test")

    logger.info(f"in the message: {CANARY}")
    logger.info("as an argument: %s", CANARY)
    logger.info("in a mapping argument: %(value)s", {"value": CANARY})
    logger.warning("in extra fields", extra={"detail": CANARY, "nested": {"deep": [CANARY]}})
    logger.warning("under a field name", extra={CANARY: "value"})
    logger.error("in stack text", stack_info=True, extra={"note": f"<{CANARY}>"})
    try:
        raise RuntimeError(f"in an exception: {CANARY}")
    except RuntimeError:
        logger.exception("with a traceback")
    try:
        try:
            raise ValueError(CANARY)
        except ValueError as error:
            raise RuntimeError("outer") from error
    except RuntimeError:
        logger.exception("in a chained exception")
    logging.getLogger(CANARY).info("as the name of the logger")
    logging.getLogger("thirdparty.library").info("from another library: token=%s", CANARY)

    written = _everything_written(directory)

    assert len(_entries(directory)) == 10
    assert CANARY not in written
    assert written.count(REDACTED) >= 10


def test_a_secret_registered_later_is_removed_from_later_records(
    directory: Path, redactor: Redactor
) -> None:
    late = "-".join(["late", "fake", "value", "0004"])
    redactor.register_secret(late)

    logging.getLogger("potato.test").info("now known: %s", late)

    assert late not in _everything_written(directory)


def test_secret_looking_fields_are_hidden_without_registration(directory: Path) -> None:
    hidden = "zq" + "9" * 6 + "kx"

    logging.getLogger("potato.test").info(
        "request failed: api_key=%s", hidden, extra={"password": hidden, "tool": "open_app"}
    )

    (entry,) = _entries(directory)
    assert hidden not in json.dumps(entry)
    assert entry["fields"] == {"password": REDACTED, "tool": "open_app"}


def test_a_secret_cut_by_the_length_limit_is_still_removed(directory: Path) -> None:
    # The secret straddles the cut. Cutting first would leave half of it.
    padding = "x" * (MAX_TEXT_CHARACTERS - 5)

    logging.getLogger("potato.test").info(padding + CANARY + "y" * 50)

    written = _everything_written(directory)
    assert CANARY[:8] not in written
    assert "...[cut]" in written


# --- Format --------------------------------------------------------------------


def test_each_record_is_one_line_of_json(directory: Path) -> None:
    logging.getLogger("potato.core").warning("state changed", extra={"new_state": "standby"})

    (entry,) = _entries(directory)
    assert set(entry) == {"time", "level", "logger", "message", "fields"}
    assert entry["level"] == "WARNING"
    assert entry["logger"] == "potato.core"
    assert entry["message"] == "state changed"
    assert entry["fields"] == {"new_state": "standby"}
    assert entry["time"].endswith("+00:00")


def test_text_from_outside_cannot_forge_a_second_record(directory: Path) -> None:
    forged = '{"time":"2026-01-01","level":"INFO","message":"all is well"}'

    logging.getLogger("potato.test").info("event title: %s", f"lunch\n{forged}\r\n\x1b[2J\x00")

    lines = (directory / LOG_FILE_NAME).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert "\x1b" not in lines[0]
    assert "\x00" not in lines[0]
    assert json.loads(lines[0])["message"].startswith("event title: lunch\n")


def test_non_ascii_text_is_escaped_not_dropped(directory: Path) -> None:
    logging.getLogger("potato.test").info("café \U0001f954")

    raw = (directory / LOG_FILE_NAME).read_text(encoding="utf-8")
    assert raw.isascii()
    assert json.loads(raw)["message"] == "café \U0001f954"


def test_a_message_that_does_not_fit_its_arguments_is_reported_safely(
    redactor: Redactor,
) -> None:
    record = logging.LogRecord(
        "potato.test", logging.INFO, __file__, 1, "two %s %s", (CANARY,), None
    )

    entry = json.loads(JsonFormatter(redactor).format(record))

    assert entry["message"] == "[log message could not be formatted]"
    assert CANARY not in json.dumps(entry)


def test_stack_text_is_redacted(redactor: Redactor) -> None:
    record = logging.LogRecord(
        "potato.test", logging.INFO, __file__, 1, "message", None, None, sinfo=f"frame {CANARY}"
    )

    entry = json.loads(JsonFormatter(redactor).format(record))

    assert entry["stack"] == f"frame {REDACTED}"


def test_objects_in_fields_are_logged_by_type_only(directory: Path) -> None:
    class Holder:
        def __repr__(self) -> str:
            return CANARY

    logging.getLogger("potato.test").info("object", extra={"thing": Holder()})

    (entry,) = _entries(directory)
    assert entry["fields"] == {"thing": "<Holder>"}


def test_debug_records_are_not_written_by_default(directory: Path) -> None:
    logging.getLogger("potato.test").debug("noise")
    logging.getLogger("potato.test").info("signal")

    assert [entry["message"] for entry in _entries(directory)] == ["signal"]


# --- Every record goes through redaction ----------------------------------------


def test_only_redacting_handlers_remain_on_the_root_logger(
    tmp_path: Path, redactor: Redactor, clean_root_logger: None
) -> None:
    root = logging.getLogger()
    unredacted = logging.StreamHandler()
    root.addHandler(unredacted)

    installed = configure_logging(tmp_path / "logs", redactor)

    assert root.handlers == [installed]
    assert isinstance(installed.formatter, JsonFormatter)


# --- Files are private, and rotate ---------------------------------------------


def test_log_folder_and_file_are_private_to_the_owner(directory: Path) -> None:
    logging.getLogger("potato.test").info("hello")

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((directory / LOG_FILE_NAME).stat().st_mode) == 0o600


def test_an_existing_loose_folder_and_file_are_tightened(
    tmp_path: Path, redactor: Redactor, clean_root_logger: None
) -> None:
    directory = tmp_path / "logs"
    directory.mkdir()
    directory.chmod(0o755)
    (directory / LOG_FILE_NAME).write_text("", encoding="utf-8")
    (directory / LOG_FILE_NAME).chmod(0o644)

    configure_logging(directory, redactor)

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((directory / LOG_FILE_NAME).stat().st_mode) == 0o600


def test_a_linked_log_file_is_refused(
    tmp_path: Path, redactor: Redactor, clean_root_logger: None
) -> None:
    directory = tmp_path / "logs"
    directory.mkdir()
    target = tmp_path / "somewhere-else.txt"
    target.write_text("", encoding="utf-8")
    (directory / LOG_FILE_NAME).symlink_to(target)

    with pytest.raises(PrivateFileError):
        configure_logging(directory, redactor)

    assert target.read_text(encoding="utf-8") == ""


def test_a_linked_log_folder_is_refused(
    tmp_path: Path, redactor: Redactor, clean_root_logger: None
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "logs").symlink_to(real, target_is_directory=True)

    with pytest.raises(PrivateFileError, match="not a real folder"):
        configure_logging(tmp_path / "logs", redactor)


def test_old_log_files_are_rotated_and_only_a_few_are_kept(
    tmp_path: Path, redactor: Redactor, clean_root_logger: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("potato.security.logs.MAX_LOG_BYTES", 2000)
    directory = tmp_path / "logs"
    configure_logging(directory, redactor)

    for number in range(400):
        logging.getLogger("potato.test").info("record number %d %s", number, CANARY)

    files = sorted(path.name for path in directory.iterdir())
    assert files == [LOG_FILE_NAME] + [f"{LOG_FILE_NAME}.{n}" for n in range(1, LOG_FILES_KEPT + 1)]
    for path in directory.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.stat().st_size < 2400
    assert CANARY not in _everything_written(directory)
