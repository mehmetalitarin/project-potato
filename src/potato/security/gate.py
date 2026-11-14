"""The gate: the only way a tool can run.

The model can ask for a tool. It cannot decide. A request is a *proposal*,
and the gate checks it against rules written in code (``docs/permissions.md``):

0. Flood limit: each origin may submit a bounded number of proposals (P8).
1. Parse: exactly a tool name and arguments, nothing else (P12).
2. Allowlist: the tool must be one the gate was built with (P2).
3. Arguments: checked strictly against the tool's fields (P3).
4. Origin: voice reaches low-risk tools only (P6).
5. Approval: a sensitive tool needs a valid approval for exactly this tool
   and these arguments, made by a click in the interface (P7).
6. Rate limit for this tool (P8).
7. Audit: the decision is recorded, or the tool does not run (P11).
8. Run under a time limit (P9).
9. Audit the outcome.

Every check must pass. If a check itself fails with an error, the answer is
no (P10). A refusal carries a fixed code and sentence and nothing else (P13).

Where the request came from, and how risky the tool is, are never read from
the proposal. The calling code states the origin, and the risk is part of
the tool's definition.

One limit to know about: Python cannot stop a running function. When a tool
passes its time limit the gate stops waiting and reports ``TIMED_OUT``, but
the tool's own thread may still finish its work. The gate refuses further
calls to that tool until it has. Tools that wait on something outside
Potato must therefore set their own time limits too.
"""

import json
import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from potato.security.approvals import ApprovalCheck, ApprovalRequest, ApprovalVerifier
from potato.security.audit import AuditEvent, AuditLog, AuditLogError
from potato.security.tools import (
    ArgumentError,
    ArgumentValue,
    RiskLevel,
    ToolDefinition,
    digest_arguments,
)

_log = logging.getLogger(__name__)

MAX_SUBMISSIONS: Final = 30
SUBMISSION_PERIOD_SECONDS: Final = 60.0
MAX_RESULT_CHARACTERS: Final = 16 * 1024


class RequestOrigin(StrEnum):
    """Where a proposal came from. Stated by Potato's code, never by the model."""

    VOICE = "voice"
    TYPED = "typed"
    INTERFACE = "interface"


# Which risk levels each origin can reach at all. Sensitive tools need an
# approval as well.
REACH: Final[Mapping[RequestOrigin, frozenset[RiskLevel]]] = MappingProxyType(
    {
        RequestOrigin.VOICE: frozenset({RiskLevel.LOW}),
        RequestOrigin.TYPED: frozenset(RiskLevel),
        RequestOrigin.INTERFACE: frozenset(RiskLevel),
    }
)


class ReasonCode(StrEnum):
    """Why a request did not complete."""

    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    INVALID_ARGUMENTS = "INVALID_ARGUMENTS"
    ORIGIN_NOT_ALLOWED = "ORIGIN_NOT_ALLOWED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    RATE_LIMITED = "RATE_LIMITED"
    TIMED_OUT = "TIMED_OUT"
    TOOL_FAILED = "TOOL_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# The only text a refusal ever carries.
MESSAGES: Final[Mapping[ReasonCode, str]] = MappingProxyType(
    {
        ReasonCode.MALFORMED_REQUEST: "The request could not be understood.",
        ReasonCode.UNKNOWN_TOOL: "That is not something Potato can do.",
        ReasonCode.INVALID_ARGUMENTS: "The details of the request were not valid.",
        ReasonCode.ORIGIN_NOT_ALLOWED: "That cannot be done from here.",
        ReasonCode.APPROVAL_REQUIRED: "That needs your approval in the Potato window.",
        ReasonCode.APPROVAL_INVALID: "The approval was not valid.",
        ReasonCode.RATE_LIMITED: "Too many requests. Try again shortly.",
        ReasonCode.TIMED_OUT: "That took too long and was stopped.",
        ReasonCode.TOOL_FAILED: "That could not be completed.",
        ReasonCode.INTERNAL_ERROR: "Something went wrong, so the request was refused.",
    }
)


@dataclass(frozen=True, slots=True)
class GateResult:
    """What came of a proposal.

    Attributes:
        ok: ``True`` only if the tool ran and returned a usable result.
        reason: Why not, when ``ok`` is ``False``.
        message: The fixed sentence for ``reason``. Empty when ``ok``.
        result: The tool's output as plain data, when ``ok``.
        pending: With ``APPROVAL_REQUIRED`` only: the exact action the
            interface should ask the user about. Not for the model.
    """

    ok: bool
    reason: ReasonCode | None
    message: str
    result: Mapping[str, object] | None
    pending: ApprovalRequest | None = None


def _refusal(reason: ReasonCode, pending: ApprovalRequest | None = None) -> GateResult:
    return GateResult(
        ok=False, reason=reason, message=MESSAGES[reason], result=None, pending=pending
    )


class _RateLimiter:
    """Allows at most ``max_calls`` in any ``period_seconds``."""

    def __init__(self, max_calls: int, period_seconds: float) -> None:
        self._max_calls = max_calls
        self._period = period_seconds
        self._times: deque[float] = deque()

    def allow(self, now: float) -> bool:
        """Count one call if there is room for it, and say whether there was."""
        while self._times and now - self._times[0] >= self._period:
            self._times.popleft()
        if len(self._times) >= self._max_calls:
            return False
        self._times.append(now)
        return True


@dataclass(frozen=True, slots=True)
class _Permit:
    """A proposal that passed every check and was recorded."""

    tool: ToolDefinition
    arguments: dict[str, ArgumentValue]
    origin: RequestOrigin


class Gate:
    """Checks every proposal and runs the tool only if all checks pass.

    The set of tools is fixed when the gate is built. Thread-safe.
    """

    def __init__(
        self,
        tools: Iterable[ToolDefinition],
        audit: AuditLog,
        *,
        approvals: ApprovalVerifier | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_submissions: int = MAX_SUBMISSIONS,
        submission_period_seconds: float = SUBMISSION_PERIOD_SECONDS,
    ) -> None:
        """Build a gate for exactly these tools.

        Args:
            tools: The allowlist. Nothing can be added later.
            audit: Where every decision is recorded.
            approvals: Checks approvals for sensitive tools. Without one, no
                sensitive tool can run.
            clock: Returns seconds from a monotonic clock. Tests replace it.
            max_submissions: Proposals accepted per origin per period.
            submission_period_seconds: The length of that period.

        Raises:
            ValueError: A tool is not a ``ToolDefinition``, two tools share a
                name, or a limit is not above zero.
        """
        registry: dict[str, ToolDefinition] = {}
        for tool in tools:
            if not isinstance(tool, ToolDefinition):
                raise ValueError("every tool must be a ToolDefinition")
            if tool.name in registry:
                raise ValueError("two tools share a name")
            registry[tool.name] = tool
        if type(max_submissions) is not int or max_submissions < 1:
            raise ValueError("max_submissions must be at least 1")
        if not submission_period_seconds > 0:
            raise ValueError("submission_period_seconds must be above zero")

        self._tools: Mapping[str, ToolDefinition] = MappingProxyType(registry)
        self._audit = audit
        self._approvals = approvals
        self._clock = clock
        self._lock = threading.Lock()
        self._floods = {
            origin: _RateLimiter(max_submissions, submission_period_seconds)
            for origin in RequestOrigin
        }
        self._flood_recorded: set[RequestOrigin] = set()
        self._limits = {
            tool.name: _RateLimiter(tool.max_calls, tool.period_seconds)
            for tool in registry.values()
        }
        self._running: set[str] = set()

    def available_tools(self, origin: RequestOrigin) -> tuple[str, ...]:
        """Return the names of the tools ``origin`` can reach, sorted.

        Used to offer the model only what it could use. This is a
        convenience, not the defence: ``submit`` checks the origin again.
        """
        # A plain string equal to an origin's value is not an origin.
        reach = REACH[origin] if isinstance(origin, RequestOrigin) else frozenset()
        return tuple(sorted(name for name, tool in self._tools.items() if tool.risk in reach))

    def describe_tools(self, origin: RequestOrigin) -> tuple[dict[str, object], ...]:
        """Return descriptions of the tools ``origin`` can reach, for the model.

        Like ``available_tools``, a convenience and not the defence.
        """
        return tuple(self._tools[name].describe() for name in self.available_tools(origin))

    def submit(
        self, proposal: object, origin: RequestOrigin, approval: object = None
    ) -> GateResult:
        """Check ``proposal`` and, if every check passes, run the tool.

        Args:
            proposal: Untrusted. Expected to be a dict with exactly the keys
                ``"tool"`` and ``"arguments"``.
            origin: Where the proposal came from, stated by the caller.
            approval: An approval from the interface, for a sensitive tool.
                Never taken from the proposal. Ignored for other tools.

        Returns:
            The tool's result, or a refusal with a fixed code and sentence.
            Never raises.
        """
        try:
            with self._lock:
                decision = self._decide(proposal, origin, approval)
            if isinstance(decision, GateResult):
                return decision
            return self._run(decision)
        except Exception:
            # P10: a check that fails with an error is a refusal. The error's
            # text is dropped on purpose (P13).
            _log.error("A gate check failed unexpectedly; the request was refused")
            try:
                known = origin if isinstance(origin, RequestOrigin) else None
                with self._lock:
                    return self._deny(ReasonCode.INTERNAL_ERROR, known)
            except Exception:
                return _refusal(ReasonCode.INTERNAL_ERROR)

    def _decide(self, proposal: object, origin: object, approval: object) -> GateResult | _Permit:
        """Run checks 0 to 7. Called with the lock held."""
        if not isinstance(origin, RequestOrigin):
            return self._deny(ReasonCode.INTERNAL_ERROR, None)
        now = self._clock()

        # 0. Flood limit. Only the first refusal in a burst is recorded, so
        # that a flood cannot push older entries out of the audit log.
        if not self._floods[origin].allow(now):
            if origin in self._flood_recorded:
                return _refusal(ReasonCode.RATE_LIMITED)
            self._flood_recorded.add(origin)
            return self._deny(ReasonCode.RATE_LIMITED, origin)
        self._flood_recorded.discard(origin)

        # 1. Parse. Any extra key, such as "approved" or "risk", is refused.
        if type(proposal) is not dict or proposal.keys() != {"tool", "arguments"}:
            return self._deny(ReasonCode.MALFORMED_REQUEST, origin)
        name = proposal["tool"]
        if type(name) is not str or type(proposal["arguments"]) is not dict:
            return self._deny(ReasonCode.MALFORMED_REQUEST, origin)

        # 2. Allowlist. The unknown name is the model's text, so it is not
        # recorded.
        tool = self._tools.get(name)
        if tool is None:
            return self._deny(ReasonCode.UNKNOWN_TOOL, origin)

        # 3. Arguments.
        try:
            arguments = tool.validate(proposal["arguments"])
        except ArgumentError:
            return self._deny(ReasonCode.INVALID_ARGUMENTS, origin, tool)
        digest = digest_arguments(arguments)

        # 4. Origin.
        if tool.risk not in REACH[origin]:
            return self._deny(ReasonCode.ORIGIN_NOT_ALLOWED, origin, tool, digest)

        # 5. Approval, for anything that is not known to need none. A valid
        # approval is used up here, even if a later check refuses the call.
        approved = False
        if tool.risk not in (RiskLevel.LOW, RiskLevel.MEDIUM):
            if approval is None:
                pending = ApprovalRequest(tool.name, arguments)
                return self._deny(
                    ReasonCode.APPROVAL_REQUIRED, origin, tool, digest, pending=pending
                )
            check = (
                ApprovalCheck.UNAVAILABLE
                if self._approvals is None
                else self._approvals.check(tool.name, arguments, approval)
            )
            if check is not ApprovalCheck.VALID:
                return self._deny(
                    ReasonCode.APPROVAL_INVALID, origin, tool, digest, problem=str(check)
                )
            approved = True

        # 6. Rate limit, and one call at a time per tool.
        if tool.name in self._running or not self._limits[tool.name].allow(now):
            return self._deny(ReasonCode.RATE_LIMITED, origin, tool, digest)

        # 7. Audit. No record, no action.
        try:
            self._audit.append(
                AuditEvent.PERMISSION_GRANTED,
                tool=tool.name,
                origin=origin.value,
                arguments_digest=digest,
                **({"approved": True} if approved else {}),
            )
        except AuditLogError:
            _log.error("A decision could not be recorded, so the tool was not run")
            return _refusal(ReasonCode.INTERNAL_ERROR)

        self._running.add(tool.name)
        return _Permit(tool, arguments, origin)

    def _deny(
        self,
        reason: ReasonCode,
        origin: RequestOrigin | None,
        tool: ToolDefinition | None = None,
        digest: str | None = None,
        *,
        pending: ApprovalRequest | None = None,
        problem: str | None = None,
    ) -> GateResult:
        """Record a refusal and return it. The refusal stands even if recording fails."""
        try:
            self._audit.append(
                AuditEvent.PERMISSION_DENIED,
                tool=None if tool is None else tool.name,
                origin=None if origin is None else origin.value,
                reason=reason.value,
                arguments_digest=digest,
                **({} if problem is None else {"approval_problem": problem}),
            )
        except AuditLogError:
            _log.warning("A refusal could not be recorded")
        return _refusal(reason, pending)

    def _run(self, permit: _Permit) -> GateResult:
        """Run the tool in its own thread, wait up to its time limit and record the outcome."""
        tool = permit.tool
        started = self._clock()
        finished = threading.Event()
        output: list[object] = []

        def work() -> None:
            try:
                # A read-only view of a dict nothing else holds.
                output.append(tool.handler(MappingProxyType(permit.arguments)))
            except Exception:
                # The error's text is dropped on purpose (P13).
                _log.error("A tool failed")
            finally:
                with self._lock:
                    self._running.discard(tool.name)
                finished.set()

        try:
            threading.Thread(target=work, name=f"potato-tool-{tool.name}", daemon=True).start()
        except BaseException:
            with self._lock:
                self._running.discard(tool.name)
            raise

        if not finished.wait(tool.timeout_seconds):
            return self._outcome(permit, started, "timed_out", ReasonCode.TIMED_OUT)
        if not output:
            return self._outcome(permit, started, "failed", ReasonCode.TOOL_FAILED)
        result = _plain_result(output[0])
        if result is None:
            return self._outcome(permit, started, "bad_result", ReasonCode.TOOL_FAILED)
        self._record_outcome(permit, started, "ok")
        return GateResult(ok=True, reason=None, message="", result=result)

    def _outcome(
        self, permit: _Permit, started: float, outcome: str, reason: ReasonCode
    ) -> GateResult:
        self._record_outcome(permit, started, outcome)
        return _refusal(reason)

    def _record_outcome(self, permit: _Permit, started: float, outcome: str) -> None:
        """Record how the run ended. The tool has already run, so this cannot refuse it."""
        duration_ms = max(0, round((self._clock() - started) * 1000))
        try:
            self._audit.append(
                AuditEvent.TOOL_EXECUTED,
                tool=permit.tool.name,
                origin=permit.origin.value,
                outcome=outcome,
                duration_ms=duration_ms,
            )
        except AuditLogError:
            _log.error("The outcome of a tool could not be recorded")


def _plain_result(value: object) -> Mapping[str, object] | None:
    """Return ``value`` as a fresh copy made of plain data, or ``None`` if it is not usable.

    A result must be a dict that can be written as JSON within the size cap
    (P14). Going through JSON also means the tool keeps no reference to what
    the gate hands on.
    """
    if type(value) is not dict:
        return None
    try:
        text = json.dumps(value, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        return None
    if len(text) > MAX_RESULT_CHARACTERS:
        return None
    copy: dict[str, object] = json.loads(text)
    return copy
