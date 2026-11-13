"""Physical approvals: proof that the user clicked "Approve" for one exact action.

A sensitive tool runs only with an approval (P7 in ``docs/permissions.md``).
An approval is a keyed hash (HMAC-SHA-256) over the tool name, the validated
arguments, a random nonce and two expiry times. The gate recomputes the hash
over what it is about to run, so:

- a changed tool or argument makes the approval invalid (T-APPR-2);
- an approval cannot be made without the key (T-APPR-3);
- it expires quickly and works once (T-APPR-1).

Making and checking are two separate objects that share the key:

- ``ApprovalIssuer`` makes approvals. The application hands it to the
  interface and to nothing else. Voice code never holds one, so voice has no
  way to approve anything (T-VOICE-3, R4).
- ``ApprovalVerifier`` checks them. The gate holds it. It cannot make one.

The key is 32 random bytes, made when the pair is created, kept in memory
only and never written anywhere. This does not defend against code running
inside Potato, which could read the key. It makes the link between "what the
user saw" and "what runs" a single check that cannot be half-done.

Two clocks decide expiry, and either one can end an approval. The monotonic
clock cannot be turned back, but on macOS it stops while the Mac sleeps. The
wall clock keeps counting through sleep, but can be changed. Together an
approval cannot be kept alive by sleeping the Mac or by changing the time.
"""

import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Final, NoReturn

from potato.security.audit import AuditEvent, AuditLog, AuditLogError
from potato.security.tools import ArgumentValue, digest_arguments

KEY_BYTES: Final = 32
NONCE_BYTES: Final = 16
TAG_BYTES: Final = hashlib.sha256().digest_size
MIN_LIFETIME_SECONDS: Final = 1.0
MAX_LIFETIME_SECONDS: Final = 120.0
MAX_REMEMBERED_NONCES: Final = 1024

# Separates these hashes from any other use of the same construction.
_PURPOSE: Final = b"potato-approval-v1\n"

Clock = Callable[[], float]


class ApprovalError(Exception):
    """An approval could not be made. Nothing was approved."""


class ApprovalCheck(StrEnum):
    """The result of checking an approval. Only ``VALID`` lets a tool run."""

    VALID = "valid"
    MALFORMED = "malformed"
    MISMATCH = "mismatch"
    EXPIRED = "expired"
    REPLAYED = "replayed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """The exact action waiting for the user's decision.

    Made by the gate from validated arguments. The interface builds its
    dialog from this and from nothing the model wrote.
    """

    tool: str
    arguments: Mapping[str, ArgumentValue]

    def __post_init__(self) -> None:
        """Keep a private, read-only copy of the arguments."""
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))


@dataclass(frozen=True, slots=True)
class Approval:
    """An approval token. Useless for any action but the one it was made for.

    The tag is left out of the printed form: for its short life it works
    like a password.
    """

    nonce: bytes
    expires_monotonic_ms: int
    expires_wall_ms: int
    tag: bytes = field(repr=False)


def _message(
    tool: str,
    arguments: Mapping[str, ArgumentValue],
    nonce: bytes,
    expires_monotonic_ms: int,
    expires_wall_ms: int,
) -> bytes:
    """Return the one canonical byte string that stands for this approval.

    JSON with sorted keys keeps every part apart: the text ``"3"`` and the
    number 3 differ, and no value can run into the next.
    """
    body = json.dumps(
        {
            "arguments": dict(arguments),
            "expires_monotonic_ms": expires_monotonic_ms,
            "expires_wall_ms": expires_wall_ms,
            "nonce": nonce.hex(),
            "tool": tool,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return _PURPOSE + body.encode("ascii")


def _tag(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def _require_plain_arguments(arguments: object) -> None:
    """Refuse anything but text names with text or whole-number values."""
    if not isinstance(arguments, Mapping):
        raise ValueError("arguments must be a mapping")
    for name, value in arguments.items():
        if type(name) is not str or type(value) not in (str, int):
            raise ValueError("arguments must be text names with text or whole-number values")


class _KeyHolder:
    """Shared behaviour for the two objects that hold the key."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        self._key = key

    def __repr__(self) -> str:
        """Never show the key."""
        return f"<{type(self).__name__}>"

    def __reduce__(self) -> NoReturn:
        """Refuse to be copied or saved, which would copy the key."""
        raise TypeError("an object holding the approval key cannot be copied or saved")


class ApprovalIssuer(_KeyHolder):
    """Makes approvals. Held by the interface only.

    Do not build one directly: use ``create_approval_pair``.
    """

    __slots__ = ("_audit", "_clock", "_lifetime_ms", "_wall_clock")

    def __init__(
        self, key: bytes, lifetime_seconds: float, audit: AuditLog, clock: Clock, wall_clock: Clock
    ) -> None:
        """Store the key and the settings. See ``create_approval_pair``."""
        super().__init__(key)
        self._lifetime_ms = round(lifetime_seconds * 1000)
        self._audit = audit
        self._clock = clock
        self._wall_clock = wall_clock

    def approve(self, request: ApprovalRequest) -> Approval:
        """Make an approval for exactly ``request``.

        Call this only from the handler of a click or key press on the
        approval dialog.

        Raises:
            ApprovalError: ``request`` is not a request from the gate, or the
                decision could not be recorded. Nothing was approved.
        """
        self._record(request, "approved", required=True)
        nonce = secrets.token_bytes(NONCE_BYTES)
        expires_monotonic_ms = round(self._clock() * 1000) + self._lifetime_ms
        expires_wall_ms = round(self._wall_clock() * 1000) + self._lifetime_ms
        message = _message(
            request.tool, request.arguments, nonce, expires_monotonic_ms, expires_wall_ms
        )
        return Approval(nonce, expires_monotonic_ms, expires_wall_ms, _tag(self._key, message))

    def deny(self, request: ApprovalRequest) -> None:
        """Record that the user refused ``request``. Makes nothing."""
        self._record(request, "denied", required=False)

    def _record(self, request: ApprovalRequest, decision: str, *, required: bool) -> None:
        try:
            if type(request) is not ApprovalRequest or type(request.tool) is not str:
                raise ValueError("not an approval request")
            _require_plain_arguments(request.arguments)
            self._audit.append(
                AuditEvent.APPROVAL_DECIDED,
                tool=request.tool,
                decision=decision,
                arguments_digest=digest_arguments(request.arguments),
            )
        except (AuditLogError, ValueError, TypeError):
            if required:
                raise ApprovalError("the approval could not be made") from None


class ApprovalVerifier(_KeyHolder):
    """Checks approvals and makes sure each is used once. Held by the gate.

    Not thread-safe on its own: the gate calls it with its lock held.
    """

    __slots__ = ("_clock", "_used", "_wall_clock")

    def __init__(self, key: bytes, clock: Clock, wall_clock: Clock) -> None:
        """Store the key and the clocks. See ``create_approval_pair``."""
        super().__init__(key)
        self._clock = clock
        self._wall_clock = wall_clock
        # Nonces already used, with the time after which each can be forgotten.
        self._used: dict[bytes, int] = {}

    def check(
        self, tool: str, arguments: Mapping[str, ArgumentValue], approval: object
    ) -> ApprovalCheck:
        """Check ``approval`` against the action about to run, and use it up.

        Args:
            tool: The name of the tool the gate is about to run.
            arguments: The validated arguments the gate is about to pass.
            approval: Untrusted until the hash has been checked.

        Returns:
            ``VALID`` exactly once per approval, and only for the action it
            was made for. Anything else means the tool must not run.
        """
        if (
            type(approval) is not Approval
            or type(approval.nonce) is not bytes
            or len(approval.nonce) != NONCE_BYTES
            or type(approval.tag) is not bytes
            or len(approval.tag) != TAG_BYTES
            or type(approval.expires_monotonic_ms) is not int
            or type(approval.expires_wall_ms) is not int
        ):
            return ApprovalCheck.MALFORMED

        # The hash first: until it matches, nothing in the token is believed.
        try:
            expected = _tag(
                self._key,
                _message(
                    tool,
                    arguments,
                    approval.nonce,
                    approval.expires_monotonic_ms,
                    approval.expires_wall_ms,
                ),
            )
        except (TypeError, ValueError):
            return ApprovalCheck.MALFORMED
        # Constant time, so that timing does not reveal how close a guess was.
        if not hmac.compare_digest(expected, approval.tag):
            return ApprovalCheck.MISMATCH

        now_ms = round(self._clock() * 1000)
        if now_ms >= approval.expires_monotonic_ms:
            return ApprovalCheck.EXPIRED
        if round(self._wall_clock() * 1000) >= approval.expires_wall_ms:
            return ApprovalCheck.EXPIRED

        self._forget_expired(now_ms)
        if approval.nonce in self._used:
            return ApprovalCheck.REPLAYED
        if len(self._used) >= MAX_REMEMBERED_NONCES:
            # Cannot remember another nonce, so cannot promise single use.
            return ApprovalCheck.UNAVAILABLE
        self._used[approval.nonce] = approval.expires_monotonic_ms
        return ApprovalCheck.VALID

    def _forget_expired(self, now_ms: int) -> None:
        """Drop nonces whose approvals have expired and so are refused anyway."""
        expired = [nonce for nonce, expires in self._used.items() if now_ms >= expires]
        for nonce in expired:
            del self._used[nonce]


def create_approval_pair(
    lifetime_seconds: float,
    audit: AuditLog,
    *,
    clock: Clock = time.monotonic,
    wall_clock: Clock = time.time,
) -> tuple[ApprovalIssuer, ApprovalVerifier]:
    """Make a fresh key and the two objects that share it.

    Called once when Potato starts. The issuer goes to the interface and the
    verifier to the gate.

    Args:
        lifetime_seconds: How long an approval stays valid.
        audit: Where the user's decisions are recorded.
        clock: Returns seconds from a monotonic clock. Tests replace it.
        wall_clock: Returns seconds since 1970. Tests replace it.

    Raises:
        ValueError: ``lifetime_seconds`` is outside the fixed bounds.
    """
    if (
        type(lifetime_seconds) not in (int, float)
        or not MIN_LIFETIME_SECONDS <= lifetime_seconds <= MAX_LIFETIME_SECONDS
    ):
        raise ValueError(
            f"lifetime_seconds must be from {MIN_LIFETIME_SECONDS} to {MAX_LIFETIME_SECONDS}"
        )
    key = secrets.token_bytes(KEY_BYTES)
    return (
        ApprovalIssuer(key, lifetime_seconds, audit, clock, wall_clock),
        ApprovalVerifier(key, clock, wall_clock),
    )
