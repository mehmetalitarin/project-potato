"""Tests for the tamper-evident audit log (T-DATA-3, T-DATA-4, guarantee P11).

Two of these tests show what the hash chain does *not* catch. They are here
on purpose, so that the limits stay written down and visible.
"""

import errno
import hashlib
import json
import os
import stat
import threading
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from potato.security.audit import (
    AUDIT_FILE_NAME,
    GENESIS_HASH,
    MAX_DATA_ITEMS,
    MAX_VALUE_CHARACTERS,
    AuditEvent,
    AuditLog,
    AuditLogError,
    audit_files,
    verify_audit_chain,
    verify_audit_file,
)
from potato.security.redaction import REDACTED, Redactor

CANARY = "-".join(["audit", "fake", "value", "0005"])
FIXED_TIME = datetime(2026, 11, 13, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def redactor() -> Redactor:
    redactor = Redactor()
    redactor.register_secret(CANARY)
    return redactor


@pytest.fixture
def path(tmp_path: Path) -> Path:
    return tmp_path / "Logs" / "Potato" / AUDIT_FILE_NAME


@pytest.fixture
def open_log(path: Path, redactor: Redactor) -> Iterator[Callable[..., AuditLog]]:
    """Open audit logs that are closed again when the test ends."""
    opened: list[AuditLog] = []

    def opener(**options: Any) -> AuditLog:
        options.setdefault("clock", lambda: FIXED_TIME)
        log = AuditLog(path, redactor, **options)
        opened.append(log)
        return log

    yield opener
    for log in opened:
        log.close()


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="ascii").splitlines(keepends=True)


def _entries(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in _lines(path)]


def _fill(log: AuditLog, count: int) -> None:
    for number in range(count):
        log.append(AuditEvent.TOOL_EXECUTED, tool="open_app", number=number)


# --- Writing -------------------------------------------------------------------


def test_the_specification_events_all_exist() -> None:
    assert {event.value for event in AuditEvent} == {
        "app_started",
        "app_stopped",
        "state_changed",
        "permission_granted",
        "permission_denied",
        "approval_decided",
        "tool_executed",
        "security_alert",
        "integration_failed",
    }


def test_a_new_log_is_empty_and_valid(open_log: Callable[..., AuditLog], path: Path) -> None:
    log = open_log()

    assert log.sequence == 0
    assert log.last_hash == GENESIS_HASH
    assert verify_audit_chain(path).ok
    assert verify_audit_chain(path).entries == 0


def test_entries_are_numbered_timed_and_chained(
    open_log: Callable[..., AuditLog], path: Path
) -> None:
    log = open_log()

    first = log.append(AuditEvent.APP_STARTED, version="0.1.0")
    second = log.append(
        AuditEvent.PERMISSION_DENIED, tool="open_app", origin="voice", reason="UNKNOWN_TOOL"
    )

    one, two = _entries(path)
    assert one == {
        "version": 1,
        "sequence": 1,
        "time": "2026-11-13T12:00:00.000+00:00",
        "event": "app_started",
        "data": {"version": "0.1.0"},
        "previous": GENESIS_HASH,
        "hash": first,
    }
    assert two["sequence"] == 2
    assert two["previous"] == first
    assert two["hash"] == second == log.last_hash
    assert two["data"] == {"tool": "open_app", "origin": "voice", "reason": "UNKNOWN_TOOL"}
    assert log.sequence == 2


def test_the_hash_can_be_recomputed_independently(
    open_log: Callable[..., AuditLog], path: Path
) -> None:
    open_log().append(AuditEvent.STATE_CHANGED, new_state="standby", ok=True, count=3, none=None)

    (entry,) = _entries(path)
    stated = entry.pop("hash")
    text = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    assert hashlib.sha256(text.encode("ascii")).hexdigest() == stated


def test_times_are_stored_in_utc(open_log: Callable[..., AuditLog], path: Path) -> None:
    tokyo = datetime(2026, 11, 13, 21, 0, 0, tzinfo=timezone(timedelta(hours=9)))

    open_log(clock=lambda: tokyo).append(AuditEvent.APP_STARTED)

    assert _entries(path)[0]["time"] == "2026-11-13T12:00:00.000+00:00"


def test_text_is_stored_as_plain_ascii_on_one_line(
    open_log: Callable[..., AuditLog], path: Path
) -> None:
    open_log().append(AuditEvent.SECURITY_ALERT, note='line one\nline two "quoted" é \x1b[2J')

    raw = path.read_bytes()
    assert raw.isascii()
    assert raw.count(b"\n") == 1
    assert b"\x1b" not in raw
    assert verify_audit_chain(path).ok


def test_folder_and_files_are_private(open_log: Callable[..., AuditLog], path: Path) -> None:
    open_log().append(AuditEvent.APP_STARTED)

    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    for file in path.parent.iterdir():
        assert stat.S_IMODE(file.stat().st_mode) == 0o600


# --- What may be recorded (T-DATA-4, T-DATA-1) ----------------------------------


def test_secrets_are_removed_from_entries(open_log: Callable[..., AuditLog], path: Path) -> None:
    open_log().append(
        AuditEvent.INTEGRATION_FAILED,
        integration="market_data",
        error=f"request with key {CANARY} failed",
        api_key="anything at all",
    )

    assert CANARY not in path.read_text(encoding="ascii")
    assert _entries(path)[0]["data"] == {
        "integration": "market_data",
        "error": f"request with key {REDACTED} failed",
        "api_key": REDACTED,
    }
    assert verify_audit_chain(path).ok


@pytest.mark.parametrize(
    "data",
    [
        {"note": "x" * (MAX_VALUE_CHARACTERS + 1)},
        {"arguments": {"app": "safari"}},
        {"items": ["a", "b"]},
        {"ratio": 0.5},
        {"raw": b"bytes"},
        {"huge": 2**63},
        {"Tool": "open_app"},
        {"tool-name": "open_app"},
        {"1st": "x"},
        {"n" * 33: "x"},
        {"": "x"},
        {f"item_{number}": number for number in range(MAX_DATA_ITEMS + 1)},
    ],
    ids=lambda data: next(iter(data))[:12] or "empty-name",
)
def test_details_that_are_not_short_and_simple_are_refused(
    open_log: Callable[..., AuditLog], path: Path, data: dict[str, Any]
) -> None:
    log = open_log()

    with pytest.raises(ValueError, match="audit"):
        log.append(AuditEvent.TOOL_EXECUTED, **data)

    assert path.read_bytes() == b""
    assert log.sequence == 0


def test_values_at_the_limits_are_accepted(open_log: Callable[..., AuditLog], path: Path) -> None:
    data: dict[str, Any] = {f"item_{number}": number for number in range(MAX_DATA_ITEMS - 2)}
    data["text"] = "x" * MAX_VALUE_CHARACTERS
    data["big"] = 2**63 - 1

    open_log().append(AuditEvent.TOOL_EXECUTED, **data)

    assert verify_audit_chain(path).ok


@pytest.mark.parametrize("event", ["app_started", "made_up_event", None, 1])
def test_the_event_must_be_one_of_the_defined_kinds(
    open_log: Callable[..., AuditLog], event: Any
) -> None:
    with pytest.raises(ValueError, match="AuditEvent"):
        open_log().append(event)


def test_a_detail_may_be_called_event(open_log: Callable[..., AuditLog], path: Path) -> None:
    open_log().append(AuditEvent.SECURITY_ALERT, event="unexpected_listener")

    assert _entries(path)[0]["data"] == {"event": "unexpected_listener"}


# --- Tampering is detected (T-DATA-3) -------------------------------------------


@pytest.fixture
def five(open_log: Callable[..., AuditLog], path: Path) -> list[str]:
    """A closed, valid log of five entries. Returns its lines."""
    log = open_log()
    _fill(log, 5)
    log.close()
    assert verify_audit_chain(path).ok
    return _lines(path)


def _rewrite(path: Path, lines: list[str]) -> None:
    path.write_text("".join(lines), encoding="ascii")


def _edit(line: str, **changes: Any) -> str:
    entry = json.loads(line)
    entry.update(changes)
    return json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"


def test_changing_a_detail_is_detected(path: Path, five: list[str]) -> None:
    five[2] = five[2].replace('"number":2', '"number":7')
    _rewrite(path, five)

    result = verify_audit_chain(path)

    assert not result.ok
    assert (result.file_name, result.line) == (AUDIT_FILE_NAME, 3)
    assert result.problem == "the entry does not match its own hash"
    assert result.entries == 2


@pytest.mark.parametrize(
    "change",
    [
        {"event": "app_stopped"},
        {"time": "2020-01-01T00:00:00.000+00:00"},
        {"data": {}},
        {"data": {"tool": "open_app", "number": 2, "extra": "added"}},
        {"sequence": 30},
        {"previous": "f" * 64},
        {"hash": "f" * 64},
        {"version": 2},
    ],
    ids=lambda change: next(iter(change)),
)
def test_changing_any_field_is_detected(
    path: Path, five: list[str], change: dict[str, Any]
) -> None:
    five[2] = _edit(five[2], **change)
    _rewrite(path, five)

    result = verify_audit_chain(path)

    assert not result.ok
    assert result.line == 3


def test_changing_an_entry_and_fixing_its_hash_is_detected_at_the_next_entry(
    path: Path, five: list[str]
) -> None:
    entry = json.loads(five[2])
    entry["data"]["number"] = 7
    del entry["hash"]
    text = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    entry["hash"] = hashlib.sha256(text.encode("ascii")).hexdigest()
    five[2] = json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"
    _rewrite(path, five)

    result = verify_audit_chain(path)

    assert not result.ok
    assert result.line == 4
    assert result.problem == "the entry does not link to the one before it"


def test_removing_an_entry_from_the_middle_is_detected(path: Path, five: list[str]) -> None:
    del five[2]
    _rewrite(path, five)

    result = verify_audit_chain(path)

    assert not result.ok
    assert result.line == 3
    assert result.problem == "an entry is missing or out of order"


def test_removing_the_first_entry_is_detected_by_its_number(path: Path, five: list[str]) -> None:
    # The log now starts at entry 2, which is what retention also produces.
    # It verifies, but the result shows that the true beginning is gone.
    _rewrite(path, five[1:])

    result = verify_audit_chain(path)

    assert result.ok
    assert result.first_sequence == 2
    assert result.anchor != GENESIS_HASH


def test_swapping_two_entries_is_detected(path: Path, five: list[str]) -> None:
    five[1], five[2] = five[2], five[1]
    _rewrite(path, five)

    assert not verify_audit_chain(path).ok


def test_repeating_an_entry_is_detected(path: Path, five: list[str]) -> None:
    five.insert(3, five[2])
    _rewrite(path, five)

    result = verify_audit_chain(path)

    assert not result.ok
    assert result.line == 4


def test_a_forged_first_entry_must_start_from_the_beginning(path: Path, five: list[str]) -> None:
    forged = json.loads(five[0])
    forged["previous"] = "a" * 64
    del forged["hash"]
    text = json.dumps(forged, sort_keys=True, separators=(",", ":"))
    forged["hash"] = hashlib.sha256(text.encode("ascii")).hexdigest()
    _rewrite(path, [json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n"])

    result = verify_audit_chain(path)

    assert not result.ok
    assert result.problem == "the first entry does not start a new chain"


@pytest.mark.parametrize(
    ("damage", "problem"),
    [
        (lambda line: line[:-1], "the file ends in the middle of an entry"),
        (lambda line: line[: len(line) // 2], "the file ends in the middle of an entry"),
        (lambda line: line[: len(line) // 2] + "\n", "the entry is not valid JSON"),
        (lambda line: "not json\n", "the entry is not valid JSON"),
        (lambda line: "[1, 2, 3]\n", "the entry does not have the expected fields"),
        (lambda line: "{}\n", "the entry does not have the expected fields"),
        (lambda line: line.replace('"data"', ' "data"'), "the entry is not in its standard form"),
        (lambda line: line.replace(":", ": ", 1), "the entry is not in its standard form"),
        (lambda line: line[:-2] + ',"note":"x"}\n', "the entry does not have the expected fields"),
        (lambda line: line.replace("\n", "\r\n"), "the entry is not in its standard form"),
        (lambda line: "\n", "the entry is not valid JSON"),
        (lambda line: line[:-2] + " " * 20000 + "}\n", "the entry is too long"),
    ],
    ids=[
        "no-final-newline",
        "cut-in-half",
        "cut-with-newline",
        "not-json",
        "a-list",
        "empty-object",
        "extra-space",
        "space-after-colon",
        "extra-field",
        "windows-newline",
        "blank-line",
        "padded",
    ],
)
def test_a_damaged_last_entry_is_detected(
    path: Path, five: list[str], damage: Callable[[str], str], problem: str
) -> None:
    five[4] = damage(five[4])
    path.write_bytes("".join(five).encode("utf-8"))

    result = verify_audit_chain(path)

    assert not result.ok
    assert result.line == 5
    assert result.problem == problem
    assert result.entries == 4


def test_a_repeated_field_name_is_detected(path: Path, five: list[str]) -> None:
    # JSON readers keep the last of two fields with the same name. An entry
    # could show one event to a casual reader and another to the program.
    five[4] = five[4].replace('"event":', '"event":"app_stopped","event":', 1)
    _rewrite(path, five)

    assert verify_audit_chain(path).problem == "the entry is not in its standard form"


def test_bytes_that_are_not_text_are_detected(path: Path, five: list[str]) -> None:
    path.write_bytes("".join(five).encode("ascii") + b"\xff\xfe\n")

    assert verify_audit_chain(path).problem == "the entry is not valid JSON"


@pytest.mark.parametrize("value", [1.5, [1], {"a": 1}], ids=["fraction", "list", "object"])
def test_details_of_the_wrong_kind_are_detected_even_with_a_valid_hash(
    path: Path, five: list[str], value: Any
) -> None:
    entry = json.loads(five[4])
    entry["data"] = {"value": value}
    del entry["hash"]
    text = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    entry["hash"] = hashlib.sha256(text.encode("ascii")).hexdigest()
    five[4] = json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"
    _rewrite(path, five)

    assert verify_audit_chain(path).problem == "the entry has a field of the wrong kind"


# --- What the chain does not catch: stated, not hidden ---------------------------


def test_limit_entries_removed_from_the_end_are_not_detected(path: Path, five: list[str]) -> None:
    _rewrite(path, five[:3])

    result = verify_audit_chain(path)

    assert result.ok
    assert result.entries == 3


def test_limit_a_complete_rewrite_with_new_hashes_is_not_detected(
    path: Path, five: list[str]
) -> None:
    previous = GENESIS_HASH
    rewritten = []
    for line in five:
        entry = json.loads(line)
        entry["data"]["tool"] = "something_else"
        entry["previous"] = previous
        del entry["hash"]
        text = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        previous = entry["hash"] = hashlib.sha256(text.encode("ascii")).hexdigest()
        rewritten.append(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
    _rewrite(path, rewritten)

    assert verify_audit_chain(path).ok


# --- Reopening ------------------------------------------------------------------


def test_reopening_continues_the_same_chain(open_log: Callable[..., AuditLog], path: Path) -> None:
    first = open_log()
    _fill(first, 3)
    first.close()

    second = open_log()
    assert second.sequence == 3
    second.append(AuditEvent.APP_STARTED)

    result = verify_audit_chain(path)
    assert result.ok
    assert result.entries == 4
    assert result.anchor == GENESIS_HASH


def test_a_tampered_log_is_refused_on_opening(
    open_log: Callable[..., AuditLog], path: Path, five: list[str]
) -> None:
    five[1] = five[1].replace("open_app", "shut_down")
    _rewrite(path, five)

    with pytest.raises(AuditLogError, match=r"failed verification.*audit\.jsonl, line 2"):
        open_log()

    assert _lines(path) == five, "a refused log must be left exactly as it was found"


def test_a_refused_log_releases_its_lock(
    open_log: Callable[..., AuditLog], path: Path, five: list[str]
) -> None:
    _rewrite(path, [*five[:1], "damaged\n"])
    with pytest.raises(AuditLogError):
        open_log()

    _rewrite(path, five)

    assert open_log().sequence == 5


def test_only_one_writer_at_a_time(open_log: Callable[..., AuditLog]) -> None:
    first = open_log()

    with pytest.raises(AuditLogError, match="another copy"):
        open_log()

    first.close()
    assert open_log().sequence == 0


def test_a_closed_log_refuses_new_entries(open_log: Callable[..., AuditLog]) -> None:
    log = open_log()
    log.close()
    log.close()

    with pytest.raises(AuditLogError, match="closed"):
        log.append(AuditEvent.APP_STOPPED)


def test_the_log_closes_itself_after_a_with_block(path: Path, redactor: Redactor) -> None:
    with AuditLog(path, redactor) as log:
        log.append(AuditEvent.APP_STARTED)

    with pytest.raises(AuditLogError, match="closed"):
        log.append(AuditEvent.APP_STOPPED)
    with AuditLog(path, redactor) as again:
        assert again.sequence == 1


def test_a_linked_audit_file_is_refused(
    open_log: Callable[..., AuditLog], path: Path, tmp_path: Path
) -> None:
    target = tmp_path / "elsewhere.jsonl"
    target.write_text("", encoding="ascii")
    path.parent.mkdir(parents=True)
    path.symlink_to(target)

    with pytest.raises(AuditLogError, match="cannot be used"):
        open_log()


def test_invalid_options_are_refused(path: Path, redactor: Redactor) -> None:
    with pytest.raises(ValueError, match="max_bytes"):
        AuditLog(path, redactor, max_bytes=10)
    with pytest.raises(ValueError, match="files_kept"):
        AuditLog(path, redactor, files_kept=0)


# --- No action without a record (P11) --------------------------------------------


def test_a_failed_write_raises_and_leaves_the_chain_intact(
    open_log: Callable[..., AuditLog], path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = open_log()
    _fill(log, 2)
    real_write = os.write

    def half_then_fail(descriptor: int, data: bytes) -> int:
        real_write(descriptor, data[: len(data) // 2])
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "write", half_then_fail)
    with pytest.raises(AuditLogError, match="could not be written"):
        log.append(AuditEvent.TOOL_EXECUTED, tool="open_app")
    monkeypatch.undo()

    # The half-written entry was removed, and the counters did not move on.
    assert log.sequence == 2
    assert verify_audit_chain(path).entries == 2

    log.append(AuditEvent.TOOL_EXECUTED, tool="open_app")
    result = verify_audit_chain(path)
    assert result.ok
    assert result.entries == 3


def test_a_failed_flush_to_disk_also_counts_as_not_recorded(
    open_log: Callable[..., AuditLog], path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = open_log()

    def fail(descriptor: int) -> None:
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(AuditLogError):
        log.append(AuditEvent.APP_STARTED)
    monkeypatch.undo()

    assert log.sequence == 0
    assert path.read_bytes() == b""


def test_entries_from_many_threads_form_one_valid_chain(
    open_log: Callable[..., AuditLog], path: Path
) -> None:
    log = open_log()
    threads = [threading.Thread(target=_fill, args=(log, 25)) for _ in range(8)]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    result = verify_audit_chain(path)
    assert result.ok
    assert result.entries == 200
    assert [entry["sequence"] for entry in _entries(path)] == list(range(1, 201))


# --- Rotation and retention ------------------------------------------------------


def test_the_chain_continues_across_rotated_files(
    open_log: Callable[..., AuditLog], path: Path
) -> None:
    log = open_log(max_bytes=2048, files_kept=50)

    _fill(log, 60)

    files = audit_files(path)
    assert len(files) > 3
    assert files[-1] == path
    assert [file.name for file in files[:-1]] == [
        f"{AUDIT_FILE_NAME}.{number}" for number in range(len(files) - 1, 0, -1)
    ]
    result = verify_audit_chain(path)
    assert result.ok
    assert result.entries == 60
    assert result.anchor == GENESIS_HASH
    assert result.last_hash == log.last_hash
    for file in files[:-1]:
        assert stat.S_IMODE(file.stat().st_mode) == 0o400
        assert file.stat().st_size < 2048 + 512


def test_only_the_newest_files_are_kept(open_log: Callable[..., AuditLog], path: Path) -> None:
    log = open_log(max_bytes=2048, files_kept=2)

    _fill(log, 100)

    assert [file.name for file in audit_files(path)] == [
        f"{AUDIT_FILE_NAME}.2",
        f"{AUDIT_FILE_NAME}.1",
        AUDIT_FILE_NAME,
    ]
    result = verify_audit_chain(path)
    assert result.ok
    assert result.last_sequence == 100
    assert result.first_sequence > 1
    assert result.entries == 100 - result.first_sequence + 1


def test_keeping_fewer_files_than_before_removes_the_extra_ones(
    open_log: Callable[..., AuditLog], path: Path
) -> None:
    generous = open_log(max_bytes=2048, files_kept=6)
    _fill(generous, 80)
    generous.close()
    assert len(audit_files(path)) == 7

    frugal = open_log(max_bytes=2048, files_kept=2)
    _fill(frugal, 20)

    assert len(audit_files(path)) == 3
    assert verify_audit_chain(path).ok
    assert verify_audit_chain(path).last_sequence == 100


def test_reopening_straight_after_a_rotation_continues_the_chain(
    open_log: Callable[..., AuditLog], path: Path
) -> None:
    log = open_log(max_bytes=2048)
    while not path.with_name(f"{AUDIT_FILE_NAME}.1").exists():
        log.append(AuditEvent.TOOL_EXECUTED, tool="open_app")
    written = log.sequence
    log.close()
    path.write_bytes(b"")  # as if Potato stopped right after starting the new file

    reopened = open_log(max_bytes=2048)
    assert reopened.sequence == written - 1
    reopened.append(AuditEvent.APP_STARTED)

    assert verify_audit_chain(path).ok


def test_tampering_with_a_rotated_file_is_detected(
    open_log: Callable[..., AuditLog], path: Path
) -> None:
    log = open_log(max_bytes=2048)
    _fill(log, 40)
    log.close()
    rotated = path.with_name(f"{AUDIT_FILE_NAME}.2")
    rotated.chmod(0o600)
    lines = _lines(rotated)
    rotated.write_text("".join(lines[:-1]), encoding="ascii")

    result = verify_audit_chain(path)

    assert not result.ok
    assert result.problem == "the file does not continue from the one before it"
    assert result.file_name == f"{AUDIT_FILE_NAME}.1"
    with pytest.raises(AuditLogError, match="failed verification"):
        open_log(max_bytes=2048)


def test_a_missing_rotated_file_is_detected(open_log: Callable[..., AuditLog], path: Path) -> None:
    log = open_log(max_bytes=2048)
    _fill(log, 40)
    log.close()
    path.with_name(f"{AUDIT_FILE_NAME}.1").unlink()

    assert not verify_audit_chain(path).ok


def test_a_single_file_can_be_checked_alone(open_log: Callable[..., AuditLog], path: Path) -> None:
    log = open_log(max_bytes=2048)
    _fill(log, 40)

    result = verify_audit_file(path.with_name(f"{AUDIT_FILE_NAME}.1"))

    assert result.ok
    assert result.first_sequence > 1
    assert result.anchor != GENESIS_HASH


def test_unrelated_files_in_the_folder_are_ignored(
    open_log: Callable[..., AuditLog], path: Path
) -> None:
    log = open_log()
    _fill(log, 2)
    for name in ["audit.jsonl.bak", "audit.jsonl.1x", "audit.jsonl.-1", "other.jsonl.1"]:
        path.with_name(name).write_text("not an audit file\n", encoding="ascii")

    assert audit_files(path) == [path]
    assert verify_audit_chain(path).ok
