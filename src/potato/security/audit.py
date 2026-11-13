"""The audit log: an append-only, tamper-evident record of security events.

Each entry is one line of JSON that contains the SHA-256 hash of the entry
before it. Changing, removing or reordering any earlier entry breaks the
chain, and ``verify_audit_chain`` reports where (T-DATA-3 in
``docs/threat_model.md``).

What this does and does not give, stated plainly:

* **Tamper-evident, not tamper-proof.** Someone who can write the file can
  rewrite it from the altered entry onwards and recompute every hash. The
  chain catches careless or partial edits, corruption and truncated writes.
* **Entries removed from the end are not detected** by the file alone,
  because nothing after them remains to disagree.
* **No action without a record** (P11 in ``docs/permissions.md``). ``append``
  either stores the entry durably or raises. A caller that cannot record an
  action must not perform it.

Entries hold short, simple values only: text, whole numbers, true/false and
nothing. This keeps conversations, calendar text and tool arguments out of
the log by construction (T-DATA-4). Text values pass through the redactor as
a second line of defence (T-DATA-1).
"""

import fcntl
import hashlib
import json
import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Final, Self

from potato.security.private_files import (
    PrivateFileError,
    ensure_private_directory,
    open_private_append,
)
from potato.security.redaction import REDACTED, Redactor, is_secret_name

AUDIT_FILE_NAME: Final = "audit.jsonl"
FORMAT_VERSION: Final = 1

# What the very first entry of a new log points back to.
GENESIS_HASH: Final = "0" * 64

MAX_AUDIT_BYTES: Final = 5 * 1024 * 1024
AUDIT_FILES_KEPT: Final = 5

MAX_DATA_ITEMS: Final = 16
MAX_VALUE_CHARACTERS: Final = 256
_MAX_LINE_BYTES: Final = 16 * 1024
_MAX_INTEGER: Final = 2**63

_DATA_NAME: Final = re.compile(r"[a-z][a-z0-9_]{0,31}")
_HASH: Final = re.compile(r"[0-9a-f]{64}")
_ENTRY_NAMES: Final = frozenset(
    {"data", "event", "hash", "previous", "sequence", "time", "version"}
)

type AuditValue = str | int | bool | None


class AuditEvent(StrEnum):
    """The kinds of event the audit log records."""

    APP_STARTED = "app_started"
    APP_STOPPED = "app_stopped"
    STATE_CHANGED = "state_changed"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    APPROVAL_DECIDED = "approval_decided"
    TOOL_EXECUTED = "tool_executed"
    SECURITY_ALERT = "security_alert"
    INTEGRATION_FAILED = "integration_failed"


class AuditLogError(Exception):
    """The audit log cannot be trusted or cannot be written."""


@dataclass(frozen=True, slots=True)
class AuditVerification:
    """The result of checking a log's hash chain.

    Attributes:
        ok: ``True`` if every entry is well-formed and correctly linked.
        entries: How many entries were checked before stopping.
        first_sequence: Sequence number of the oldest entry checked.
        anchor: The hash the oldest entry points back to. ``GENESIS_HASH``
            for a log that still has its first entry; otherwise the hash of
            an entry that retention has already deleted, which cannot be
            checked.
        last_sequence: Sequence number of the newest entry checked.
        last_hash: Hash of the newest entry checked.
        problem: What is wrong, when ``ok`` is ``False``.
        file_name: The file with the problem.
        line: The line with the problem, counted from 1.
    """

    ok: bool
    entries: int = 0
    first_sequence: int = 0
    anchor: str = ""
    last_sequence: int = 0
    last_hash: str = ""
    problem: str | None = None
    file_name: str | None = None
    line: int | None = None


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _canonical(entry: dict[str, object]) -> str:
    """Return the one and only text form of an entry: sorted, compact, ASCII."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _entry_hash(entry: dict[str, object]) -> str:
    """Hash every field of an entry except the hash itself."""
    unhashed = {name: value for name, value in entry.items() if name != "hash"}
    return hashlib.sha256(_canonical(unhashed).encode("ascii")).hexdigest()


def _is_whole_number(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True, slots=True)
class _Link:
    """The parts of a verified entry that tie it to its neighbours."""

    sequence: int
    previous: str
    entry_hash: str


def _read_entry(raw: bytes) -> _Link | str:
    """Check one line. Return its links, or a description of what is wrong."""
    if not raw.endswith(b"\n"):
        return "the file ends in the middle of an entry"
    if len(raw) > _MAX_LINE_BYTES:
        return "the entry is too long"
    try:
        text = raw[:-1].decode("ascii")
        entry = json.loads(text)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return "the entry is not valid JSON"

    if not isinstance(entry, dict) or set(entry) != _ENTRY_NAMES:
        return "the entry does not have the expected fields"
    data = entry["data"]
    well_formed = (
        entry["version"] == FORMAT_VERSION
        and _is_whole_number(entry["version"])
        and _is_whole_number(entry["sequence"])
        and entry["sequence"] >= 1
        and isinstance(entry["time"], str)
        and isinstance(entry["event"], str)
        and isinstance(entry["previous"], str)
        and _HASH.fullmatch(entry["previous"]) is not None
        and isinstance(entry["hash"], str)
        and _HASH.fullmatch(entry["hash"]) is not None
        and isinstance(data, dict)
        and all(value is None or isinstance(value, (str, int)) for value in data.values())
    )
    if not well_formed:
        return "the entry has a field of the wrong kind"
    # An entry has exactly one valid spelling. This catches reordered fields,
    # extra spaces, repeated names and anything else a hand edit leaves behind.
    if _canonical(entry) != text:
        return "the entry is not in its standard form"
    if _entry_hash(entry) != entry["hash"]:
        return "the entry does not match its own hash"
    return _Link(entry["sequence"], entry["previous"], entry["hash"])


def verify_audit_file(path: Path) -> AuditVerification:
    """Check the hash chain inside a single audit file.

    Args:
        path: The file to check. An empty file is valid and has no entries.

    Returns:
        The result. The link from this file's first entry to an earlier file
        is reported as ``anchor`` and is not checked here.
    """
    entries = 0
    first_sequence = 0
    anchor = ""
    last_sequence = 0
    last_hash = ""

    def failed(problem: str, line: int) -> AuditVerification:
        return AuditVerification(
            False,
            entries,
            first_sequence,
            anchor,
            last_sequence,
            last_hash,
            problem,
            path.name,
            line,
        )

    with path.open("rb") as handle:
        for line, raw in enumerate(handle, start=1):
            link = _read_entry(raw)
            if isinstance(link, str):
                return failed(link, line)
            if entries == 0:
                first_sequence = link.sequence
                anchor = link.previous
            elif link.sequence != last_sequence + 1:
                return failed("an entry is missing or out of order", line)
            elif link.previous != last_hash:
                return failed("the entry does not link to the one before it", line)
            entries += 1
            last_sequence = link.sequence
            last_hash = link.entry_hash

    return AuditVerification(True, entries, first_sequence, anchor, last_sequence, last_hash)


def audit_files(path: Path) -> list[Path]:
    """Return the audit files that exist, oldest first.

    Args:
        path: The current audit file. Rotated files sit beside it as
            ``<name>.1`` (newest) up to ``<name>.N`` (oldest).
    """
    files = [candidate for _, candidate in sorted(_rotated_files(path), reverse=True)]
    if path.exists():
        files.append(path)
    return files


def _rotated_files(path: Path) -> list[tuple[int, Path]]:
    """Return each set-aside file with its number, in no particular order."""
    rotated = []
    for candidate in path.parent.glob(f"{path.name}.*"):
        suffix = candidate.name[len(path.name) + 1 :]
        if suffix.isascii() and suffix.isdigit():
            rotated.append((int(suffix), candidate))
    return rotated


def verify_audit_chain(path: Path) -> AuditVerification:
    """Check every audit file and the links between them.

    Args:
        path: The current audit file.

    Returns:
        The combined result. A log with no files or no entries is valid.
    """
    total = 0
    first_sequence = 0
    anchor = ""
    last_sequence = 0
    last_hash = ""

    for file in audit_files(path):
        result = verify_audit_file(file)
        if not result.ok:
            return AuditVerification(
                False,
                total + result.entries,
                first_sequence or result.first_sequence,
                anchor or result.anchor,
                result.last_sequence or last_sequence,
                result.last_hash or last_hash,
                result.problem,
                result.file_name,
                result.line,
            )
        if result.entries == 0:
            continue
        if total == 0:
            first_sequence = result.first_sequence
            anchor = result.anchor
        elif result.first_sequence != last_sequence + 1 or result.anchor != last_hash:
            return AuditVerification(
                False,
                total,
                first_sequence,
                anchor,
                last_sequence,
                last_hash,
                "the file does not continue from the one before it",
                file.name,
                1,
            )
        total += result.entries
        last_sequence = result.last_sequence
        last_hash = result.last_hash

    if total and first_sequence == 1 and anchor != GENESIS_HASH:
        return AuditVerification(
            False,
            total,
            first_sequence,
            anchor,
            last_sequence,
            last_hash,
            "the first entry does not start a new chain",
            audit_files(path)[0].name,
            1,
        )
    return AuditVerification(True, total, first_sequence, anchor, last_sequence, last_hash)


class AuditLog:
    """Appends entries to the audit log. One writer at a time, safe across threads.

    Opening the log checks the whole existing chain. A log that fails the
    check is refused, so tampering or corruption is noticed at start-up and
    cannot be silently built upon.
    """

    def __init__(
        self,
        path: Path,
        redactor: Redactor,
        *,
        max_bytes: int = MAX_AUDIT_BYTES,
        files_kept: int = AUDIT_FILES_KEPT,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        """Open the log, creating it if needed.

        Args:
            path: The current audit file, inside a folder that will be made
                private to the user.
            redactor: Removes secrets from text values.
            max_bytes: Size at which the current file is set aside and a new
                one started.
            files_kept: How many set-aside files to keep. The oldest is
                deleted when this is exceeded.
            clock: Returns the current time. Replaced in tests.

        Raises:
            AuditLogError: The existing log fails verification, another
                process is writing it, or it cannot be opened safely.
        """
        if max_bytes < 1024 or files_kept < 1:
            raise ValueError("max_bytes must be at least 1024 and files_kept at least 1")
        self._path = path
        self._redactor = redactor
        self._max_bytes = max_bytes
        self._files_kept = files_kept
        self._clock = clock
        self._thread_lock = threading.Lock()
        self._descriptor: int | None = None
        self._lock_descriptor: int | None = None

        try:
            ensure_private_directory(path.parent)
            self._lock_descriptor = self._acquire_writer_lock()
            existing = verify_audit_chain(path)
            if not existing.ok:
                raise AuditLogError(
                    f"the audit log failed verification: {existing.problem} "
                    f"({existing.file_name}, line {existing.line})"
                )
            self._sequence = existing.last_sequence
            self._last_hash = existing.last_hash or GENESIS_HASH
            self._descriptor = open_private_append(path)
        except PrivateFileError as error:
            self.close()
            raise AuditLogError(f"the audit log cannot be used: {error}") from error
        except BaseException:
            self.close()
            raise

    @property
    def sequence(self) -> int:
        """Sequence number of the newest entry, or 0 for an empty log."""
        return self._sequence

    @property
    def last_hash(self) -> str:
        """Hash of the newest entry, or ``GENESIS_HASH`` for an empty log."""
        return self._last_hash

    def append(self, event: AuditEvent, /, **data: AuditValue) -> str:
        """Record one event durably, or raise.

        Args:
            event: What kind of event this is.
            **data: A few short details. Names are lower-case identifiers.
                Values are text of at most 256 characters, whole numbers,
                ``True``/``False`` or ``None``. Pass digests and codes, not
                content: no arguments, no conversation, no calendar text.

        Returns:
            The hash of the new entry.

        Raises:
            ValueError: ``event`` or ``data`` is not of the allowed form.
            AuditLogError: The entry could not be stored. The caller must
                treat the action being recorded as not permitted.
        """
        if not isinstance(event, AuditEvent):
            raise ValueError("event must be an AuditEvent")
        cleaned = self._clean(data)

        with self._thread_lock:
            if self._descriptor is None:
                raise AuditLogError("the audit log is closed")
            descriptor = self._rotate_if_full(self._descriptor)
            entry: dict[str, object] = {
                "version": FORMAT_VERSION,
                "sequence": self._sequence + 1,
                "time": self._clock().astimezone(UTC).isoformat(timespec="milliseconds"),
                "event": event.value,
                "data": cleaned,
                "previous": self._last_hash,
            }
            entry_hash = _entry_hash(entry)
            entry["hash"] = entry_hash
            self._write(descriptor, (_canonical(entry) + "\n").encode("ascii"))
            # Only now does the entry count as part of the chain.
            self._sequence += 1
            self._last_hash = entry_hash
            return entry_hash

    def close(self) -> None:
        """Close the log and let another writer take over. Safe to call twice."""
        for name in ("_descriptor", "_lock_descriptor"):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)

    def __enter__(self) -> Self:
        """Return the log itself, for use in a ``with`` block."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the log when the ``with`` block ends."""
        self.close()

    def _acquire_writer_lock(self) -> int:
        """Take the lock that keeps two processes from interleaving entries."""
        descriptor = open_private_append(self._path.with_name(self._path.name + ".lock"))
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(descriptor)
            raise AuditLogError(
                "another copy of Potato is already writing the audit log"
            ) from error
        return descriptor

    def _clean(self, data: dict[str, AuditValue]) -> dict[str, object]:
        """Check the details of an entry and remove any secrets from them."""
        if len(data) > MAX_DATA_ITEMS:
            raise ValueError(f"an audit entry can hold at most {MAX_DATA_ITEMS} details")
        for name, value in data.items():
            if not _DATA_NAME.fullmatch(name):
                raise ValueError("audit detail names must be short lower-case identifiers")
            if value is None or isinstance(value, bool):
                continue
            if isinstance(value, str):
                if len(value) > MAX_VALUE_CHARACTERS:
                    raise ValueError(f"audit detail {name} is too long")
            elif isinstance(value, int):
                if abs(value) >= _MAX_INTEGER:
                    raise ValueError(f"audit detail {name} is too large")
            else:
                raise ValueError(f"audit detail {name} must be text, a whole number or true/false")
        cleaned: dict[str, object] = {}
        for name, value in data.items():
            if is_secret_name(name):
                cleaned[name] = REDACTED
            elif isinstance(value, str):
                cleaned[name] = self._redactor.redact(value)
            else:
                cleaned[name] = value
        return cleaned

    def _write(self, descriptor: int, line: bytes) -> None:
        """Append a whole line and flush it to disk, or leave the file as it was."""
        size_before = os.fstat(descriptor).st_size
        try:
            written = 0
            while written < len(line):
                written += os.write(descriptor, line[written:])
            os.fsync(descriptor)
        except OSError as error:
            # Half an entry would break the chain for every later entry.
            try:
                os.ftruncate(descriptor, size_before)
            except OSError:
                self.close()
            raise AuditLogError("the audit entry could not be written") from error

    def _numbered(self, number: int) -> Path:
        return self._path.with_name(f"{self._path.name}.{number}")

    def _rotate_if_full(self, descriptor: int) -> int:
        """Set the current file aside once it is full, and start a new one.

        The chain continues across files: the first entry of the new file
        points to the last entry of the old one.

        Returns:
            The descriptor to write to, which is a new one after a rotation.
        """
        if os.fstat(descriptor).st_size < self._max_bytes:
            return descriptor
        os.close(descriptor)
        self._descriptor = None
        try:
            # Retention: drop every file that would be pushed past the limit,
            # including leftovers from a time when more files were kept.
            for number, file in _rotated_files(self._path):
                if number >= self._files_kept:
                    file.unlink()
            for number in range(self._files_kept - 1, 0, -1):
                if self._numbered(number).exists():
                    self._numbered(number).replace(self._numbered(number + 1))
            self._path.replace(self._numbered(1))
            # Finished files are read-only, against accidental edits.
            self._numbered(1).chmod(0o400)
            fresh = open_private_append(self._path)
        except (OSError, PrivateFileError) as error:
            self.close()
            raise AuditLogError("the audit log could not start a new file") from error
        self._descriptor = fresh
        return fresh
