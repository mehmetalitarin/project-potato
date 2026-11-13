"""Tests for the gate (P1 to P14 in docs/permissions.md; R8)."""

import json
import logging
import re
import threading
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

import potato.security.gate as gate_module
from potato.security.audit import AuditLog, AuditLogError, verify_audit_chain
from potato.security.gate import (
    MAX_RESULT_CHARACTERS,
    MESSAGES,
    REACH,
    Gate,
    GateResult,
    ReasonCode,
    RequestOrigin,
    digest_arguments,
)
from potato.security.redaction import Redactor
from potato.security.tools import (
    ArgumentValue,
    ChoiceField,
    IntegerField,
    RiskLevel,
    TextField,
    ToolDefinition,
)

VOICE, TYPED, INTERFACE = RequestOrigin.VOICE, RequestOrigin.TYPED, RequestOrigin.INTERFACE
CANARY = "canary-secret-8c41f0"

Handler = Callable[[Mapping[str, ArgumentValue]], Mapping[str, object]]


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Calls:
    """Records every time a tool actually runs."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, dict[str, ArgumentValue]]] = []

    def handler(self, name: str, result: Mapping[str, object] | None = None) -> Handler:
        def run(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
            self.seen.append((name, dict(arguments)))
            return {"done": name} if result is None else result

        return run


def _tool(name: str, risk: RiskLevel, handler: Handler, **options: Any) -> ToolDefinition:
    options.setdefault("arguments", {})
    return ToolDefinition(name=name, risk=risk, handler=handler, **options)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def calls() -> Calls:
    return Calls()


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "logs" / "audit.jsonl"


@pytest.fixture
def audit(audit_path: Path) -> Iterator[AuditLog]:
    redactor = Redactor()
    redactor.register_secret(CANARY)
    with AuditLog(audit_path, redactor) as log:
        yield log


@pytest.fixture
def gate(audit: AuditLog, clock: FakeClock, calls: Calls) -> Gate:
    tools = [
        _tool(
            "open_app",
            RiskLevel.LOW,
            calls.handler("open_app"),
            arguments={"name": ChoiceField(frozenset({"Safari", "Notes"}))},
        ),
        _tool(
            "add_holding",
            RiskLevel.MEDIUM,
            calls.handler("add_holding"),
            arguments={
                "symbol": TextField(re.compile(r"[A-Z]{1,5}"), 5),
                "units": IntegerField(1, 1000),
            },
        ),
        _tool("wipe_everything", RiskLevel.SENSITIVE, calls.handler("wipe_everything")),
    ]
    return Gate(tools, audit, clock=clock)


def _entries(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _open_app(name: object = "Safari") -> dict[str, object]:
    return {"tool": "open_app", "arguments": {"name": name}}


def _assert_refused(result: GateResult, reason: ReasonCode) -> None:
    assert result == GateResult(ok=False, reason=reason, message=MESSAGES[reason], result=None)


# --- A request that passes ---------------------------------------------------


def test_valid_request_runs_and_is_recorded_before_and_after(
    gate: Gate, calls: Calls, audit_path: Path
) -> None:
    result = gate.submit(_open_app(), VOICE)
    assert result == GateResult(ok=True, reason=None, message="", result={"done": "open_app"})
    assert calls.seen == [("open_app", {"name": "Safari"})]

    granted, executed = _entries(audit_path)
    assert granted["event"] == "permission_granted"
    assert granted["data"] == {
        "tool": "open_app",
        "origin": "voice",
        "arguments_digest": digest_arguments({"name": "Safari"}),
    }
    assert executed["event"] == "tool_executed"
    assert executed["data"] == {
        "tool": "open_app",
        "origin": "voice",
        "outcome": "ok",
        "duration_ms": 0,
    }
    assert verify_audit_chain(audit_path).ok


def test_the_decision_is_recorded_before_the_tool_runs(
    audit: AuditLog, audit_path: Path, clock: FakeClock
) -> None:
    seen_at_run: list[list[str]] = []

    def handler(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        seen_at_run.append([entry["event"] for entry in _entries(audit_path)])
        return {}

    gate = Gate([_tool("look", RiskLevel.LOW, handler)], audit, clock=clock)
    assert gate.submit({"tool": "look", "arguments": {}}, TYPED).ok
    assert seen_at_run == [["permission_granted"]]


def test_arguments_are_never_written_to_the_audit_log(gate: Gate, audit_path: Path) -> None:
    gate.submit({"tool": "add_holding", "arguments": {"symbol": "ZZQXJ", "units": 777}}, TYPED)
    assert "ZZQXJ" not in audit_path.read_text()
    # Hashes are random-looking hex, so the number is looked for as a value.
    for entry in _entries(audit_path):
        assert 777 not in entry["data"].values()
        assert "777" not in entry["data"].values()


def test_the_tool_cannot_change_the_validated_arguments(audit: AuditLog, clock: FakeClock) -> None:
    def handler(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        arguments["name"] = "Terminal"  # type: ignore[index]
        return {}

    tool = _tool(
        "open_app", RiskLevel.LOW, handler, arguments={"name": ChoiceField(frozenset({"Safari"}))}
    )
    result = Gate([tool], audit, clock=clock).submit(_open_app(), TYPED)
    _assert_refused(result, ReasonCode.TOOL_FAILED)


def test_digest_is_the_same_whatever_the_order_of_arguments() -> None:
    assert digest_arguments({"a": 1, "b": "x"}) == digest_arguments({"b": "x", "a": 1})
    assert digest_arguments({"a": 1}) != digest_arguments({"a": 2})
    assert re.fullmatch(r"[0-9a-f]{64}", digest_arguments({}))


# --- 1. Parse (P12) ----------------------------------------------------------


@pytest.mark.parametrize(
    "proposal",
    [
        None,
        "open_app",
        '{"tool": "open_app", "arguments": {"name": "Safari"}}',
        [],
        ["open_app", {"name": "Safari"}],
        {},
        {"tool": "open_app"},
        {"arguments": {"name": "Safari"}},
        {"tool": "open_app", "arguments": {"name": "Safari"}, "approved": True},
        {"tool": "open_app", "arguments": {"name": "Safari"}, "origin": "interface"},
        {"tool": "open_app", "arguments": {"name": "Safari"}, "risk": "low"},
        {"tool": "open_app", "arguments": {"name": "Safari"}, "approval": "token"},
        {"tool": ["open_app"], "arguments": {"name": "Safari"}},
        {"tool": None, "arguments": {}},
        {"tool": 7, "arguments": {}},
        {"tool": "open_app", "arguments": None},
        {"tool": "open_app", "arguments": [["name", "Safari"]]},
        {"tool": "open_app", "arguments": '{"name": "Safari"}'},
        {"Tool": "open_app", "arguments": {"name": "Safari"}},
    ],
)
def test_malformed_proposals_are_refused(
    gate: Gate, calls: Calls, audit_path: Path, proposal: object
) -> None:
    _assert_refused(gate.submit(proposal, INTERFACE), ReasonCode.MALFORMED_REQUEST)
    assert calls.seen == []
    (entry,) = _entries(audit_path)
    assert entry["event"] == "permission_denied"
    assert entry["data"] == {
        "tool": None,
        "origin": "interface",
        "reason": "MALFORMED_REQUEST",
        "arguments_digest": None,
    }


def test_a_proposal_cannot_state_its_own_origin_or_approval(gate: Gate, calls: Calls) -> None:
    # P12: the sensitive tool stays out of reach whatever the proposal claims.
    extras: list[dict[str, object]] = [{"origin": "interface"}, {"approved": True}, {"risk": "low"}]
    for extra in extras:
        proposal: dict[str, object] = {"tool": "wipe_everything", "arguments": {}, **extra}
        _assert_refused(gate.submit(proposal, VOICE), ReasonCode.MALFORMED_REQUEST)
    for arguments in [{"approved": True}, {"origin": "interface"}, {"approval": "yes"}]:
        proposal = {"tool": "wipe_everything", "arguments": arguments}
        _assert_refused(gate.submit(proposal, VOICE), ReasonCode.INVALID_ARGUMENTS)
    assert calls.seen == []


# --- 2. Allowlist (P2; required test 3) --------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "run_shell", "shell", "bash", "exec", "eval", "python", "run_python", "execute_code",
        "read_file", "write_file", "delete_file", "send_email", "sudo", "",
        "OPEN_APP", "open_app ", "open_app\n", "open-app", "__class__", "handler",
    ],
)  # fmt: skip
def test_unknown_tools_are_refused(gate: Gate, calls: Calls, audit_path: Path, name: str) -> None:
    proposal = {"tool": name, "arguments": {"command": "rm -rf ~", "code": "import os"}}
    _assert_refused(gate.submit(proposal, INTERFACE), ReasonCode.UNKNOWN_TOOL)
    assert calls.seen == []
    (entry,) = _entries(audit_path)
    assert entry["data"]["reason"] == "UNKNOWN_TOOL"
    assert entry["data"]["tool"] is None


def test_an_unknown_tool_name_is_not_written_anywhere(
    gate: Gate, audit_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        result = gate.submit({"tool": "model-chosen-text-91", "arguments": {}}, TYPED)
    assert "model-chosen-text-91" not in audit_path.read_text()
    assert "model-chosen-text-91" not in caplog.text
    assert "model-chosen-text-91" not in repr(result)


def test_the_allowlist_is_fixed_when_the_gate_is_built(audit: AuditLog, calls: Calls) -> None:
    tools = [_tool("look", RiskLevel.LOW, calls.handler("look"))]
    gate = Gate(tools, audit)
    tools.append(_tool("later", RiskLevel.LOW, calls.handler("later")))
    _assert_refused(gate.submit({"tool": "later", "arguments": {}}, TYPED), ReasonCode.UNKNOWN_TOOL)
    with pytest.raises(TypeError):
        gate._tools["later"] = tools[1]  # type: ignore[index]
    assert not any(name.startswith(("add", "register")) for name in dir(gate))


def test_gate_refuses_bad_construction(audit: AuditLog, calls: Calls) -> None:
    tool = _tool("look", RiskLevel.LOW, calls.handler("look"))
    with pytest.raises(ValueError, match="share a name"):
        Gate([tool, tool], audit)
    with pytest.raises(ValueError, match="ToolDefinition"):
        Gate([calls.handler("look")], audit)  # type: ignore[list-item]
    with pytest.raises(ValueError, match="max_submissions"):
        Gate([tool], audit, max_submissions=0)
    with pytest.raises(ValueError, match="submission_period_seconds"):
        Gate([tool], audit, submission_period_seconds=0)


# --- 3. Arguments (P3; required test 4) --------------------------------------


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"name": "Terminal"},
        {"name": "safari"},
        {"name": "Safari", "extra": 1},
        {"name": "Safari", "command": "rm -rf ~"},
        {"name": "/Applications/Safari.app"},
        {"name": "Safari; open Terminal"},
        {"name": ["Safari"]},
        {"name": None},
        {"name": True},
        {"Name": "Safari"},
    ],
)
def test_invalid_arguments_are_refused(
    gate: Gate, calls: Calls, audit_path: Path, arguments: dict[str, object]
) -> None:
    result = gate.submit({"tool": "open_app", "arguments": arguments}, INTERFACE)
    _assert_refused(result, ReasonCode.INVALID_ARGUMENTS)
    assert calls.seen == []
    (entry,) = _entries(audit_path)
    assert entry["data"] == {
        "tool": "open_app",
        "origin": "interface",
        "reason": "INVALID_ARGUMENTS",
        "arguments_digest": None,
    }


@pytest.mark.parametrize("units", ["5", 5.0, True, 0, 1001, None])
def test_numbers_are_not_converted(gate: Gate, calls: Calls, units: object) -> None:
    proposal = {"tool": "add_holding", "arguments": {"symbol": "AAPL", "units": units}}
    _assert_refused(gate.submit(proposal, TYPED), ReasonCode.INVALID_ARGUMENTS)
    assert calls.seen == []


# --- 4 and 5. Origin and approval (P5, P6, P7) -------------------------------


def test_reach_table_is_pinned() -> None:
    assert dict(REACH) == {
        VOICE: frozenset({RiskLevel.LOW}),
        TYPED: frozenset({RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.SENSITIVE}),
        INTERFACE: frozenset({RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.SENSITIVE}),
    }
    with pytest.raises(TypeError):
        REACH[VOICE] = frozenset(RiskLevel)  # type: ignore[index]


PROPOSALS = {
    RiskLevel.LOW: _open_app(),
    RiskLevel.MEDIUM: {"tool": "add_holding", "arguments": {"symbol": "AAPL", "units": 2}},
    RiskLevel.SENSITIVE: {"tool": "wipe_everything", "arguments": {}},
}


@pytest.mark.parametrize(
    ("origin", "risk", "expected"),
    [
        (VOICE, RiskLevel.LOW, None),
        (VOICE, RiskLevel.MEDIUM, ReasonCode.ORIGIN_NOT_ALLOWED),
        (VOICE, RiskLevel.SENSITIVE, ReasonCode.ORIGIN_NOT_ALLOWED),
        (TYPED, RiskLevel.LOW, None),
        (TYPED, RiskLevel.MEDIUM, None),
        (TYPED, RiskLevel.SENSITIVE, ReasonCode.APPROVAL_REQUIRED),
        (INTERFACE, RiskLevel.LOW, None),
        (INTERFACE, RiskLevel.MEDIUM, None),
        (INTERFACE, RiskLevel.SENSITIVE, ReasonCode.APPROVAL_REQUIRED),
    ],
)
def test_every_origin_and_risk_pair(
    gate: Gate,
    calls: Calls,
    audit_path: Path,
    origin: RequestOrigin,
    risk: RiskLevel,
    expected: ReasonCode | None,
) -> None:
    result = gate.submit(PROPOSALS[risk], origin)
    if expected is None:
        assert result.ok
        assert len(calls.seen) == 1
    else:
        _assert_refused(result, expected)
        assert calls.seen == []
        (entry,) = _entries(audit_path)
        assert entry["data"]["reason"] == expected.value
        assert entry["data"]["origin"] == origin.value
        assert entry["data"]["arguments_digest"] is not None


def test_a_sensitive_tool_never_runs_in_this_version(gate: Gate, calls: Calls) -> None:
    for origin in RequestOrigin:
        for _ in range(3):
            assert not gate.submit(PROPOSALS[RiskLevel.SENSITIVE], origin).ok
    assert calls.seen == []


@pytest.mark.parametrize("origin", ["interface", "voice", None, 1, object()])
def test_an_origin_that_is_not_a_real_origin_is_refused(
    gate: Gate, calls: Calls, audit_path: Path, origin: object
) -> None:
    result = gate.submit(_open_app(), origin)  # type: ignore[arg-type]
    _assert_refused(result, ReasonCode.INTERNAL_ERROR)
    assert calls.seen == []
    (entry,) = _entries(audit_path)
    assert entry["data"]["origin"] is None


def test_available_tools_follow_the_reach_table(gate: Gate) -> None:
    assert gate.available_tools(VOICE) == ("open_app",)
    assert gate.available_tools(TYPED) == ("add_holding", "open_app", "wipe_everything")
    assert gate.available_tools("voice") == ()  # type: ignore[arg-type]


# --- 0 and 6. Limits (P8) ----------------------------------------------------


def test_per_tool_rate_limit(audit: AuditLog, clock: FakeClock, calls: Calls) -> None:
    tool = _tool("look", RiskLevel.LOW, calls.handler("look"), max_calls=3, period_seconds=10.0)
    gate = Gate([tool], audit, clock=clock)
    proposal = {"tool": "look", "arguments": {}}
    for _ in range(3):
        assert gate.submit(proposal, TYPED).ok
    _assert_refused(gate.submit(proposal, TYPED), ReasonCode.RATE_LIMITED)
    clock.now += 9.9
    _assert_refused(gate.submit(proposal, TYPED), ReasonCode.RATE_LIMITED)
    clock.now += 0.1
    assert gate.submit(proposal, TYPED).ok
    assert len(calls.seen) == 4


def test_refused_requests_do_not_use_up_a_tools_limit(
    audit: AuditLog, clock: FakeClock, calls: Calls
) -> None:
    tool = _tool("change", RiskLevel.MEDIUM, calls.handler("change"), max_calls=1)
    gate = Gate([tool], audit, clock=clock)
    proposal = {"tool": "change", "arguments": {}}
    for _ in range(5):
        _assert_refused(gate.submit(proposal, VOICE), ReasonCode.ORIGIN_NOT_ALLOWED)
    assert gate.submit(proposal, TYPED).ok


def test_flood_limit_covers_refused_requests_too(
    audit: AuditLog, audit_path: Path, clock: FakeClock, calls: Calls
) -> None:
    tool = _tool("look", RiskLevel.LOW, calls.handler("look"))
    gate = Gate([tool], audit, clock=clock, max_submissions=5, submission_period_seconds=60.0)
    junk = {"tool": "no_such_tool", "arguments": {}}
    for _ in range(5):
        _assert_refused(gate.submit(junk, VOICE), ReasonCode.UNKNOWN_TOOL)
    for _ in range(200):
        _assert_refused(gate.submit(junk, VOICE), ReasonCode.RATE_LIMITED)
        _assert_refused(
            gate.submit({"tool": "look", "arguments": {}}, VOICE), ReasonCode.RATE_LIMITED
        )
    assert calls.seen == []
    # The flood wrote one entry, not four hundred.
    reasons = [entry["data"]["reason"] for entry in _entries(audit_path)]
    assert reasons == ["UNKNOWN_TOOL"] * 5 + ["RATE_LIMITED"]

    # A flood from voice does not lock out the interface.
    assert gate.submit({"tool": "look", "arguments": {}}, INTERFACE).ok

    clock.now += 60.0
    assert gate.submit({"tool": "look", "arguments": {}}, VOICE).ok
    # A second flood is recorded again.
    for _ in range(10):
        gate.submit(junk, VOICE)
    reasons = [entry["data"].get("reason") for entry in _entries(audit_path)]
    assert reasons.count("RATE_LIMITED") == 2


# --- 7. Audit (P11) ----------------------------------------------------------


def test_no_record_no_action(gate: Gate, audit: AuditLog, calls: Calls) -> None:
    audit.close()
    _assert_refused(gate.submit(_open_app(), INTERFACE), ReasonCode.INTERNAL_ERROR)
    assert calls.seen == []


def test_a_refusal_stands_even_if_it_cannot_be_recorded(
    gate: Gate, audit: AuditLog, calls: Calls
) -> None:
    audit.close()
    junk = {"tool": "no_such_tool", "arguments": {}}
    _assert_refused(gate.submit(junk, INTERFACE), ReasonCode.UNKNOWN_TOOL)
    assert calls.seen == []


def test_a_failed_record_does_not_leave_the_tool_marked_as_running(
    audit_path: Path, clock: FakeClock, calls: Calls
) -> None:
    class FlakyAudit:
        def __init__(self) -> None:
            self.fail = True

        def append(self, *args: object, **data: object) -> str:
            if self.fail:
                raise AuditLogError("no")
            return ""

    flaky = FlakyAudit()
    tool = _tool("look", RiskLevel.LOW, calls.handler("look"))
    gate = Gate([tool], flaky, clock=clock)  # type: ignore[arg-type]
    proposal = {"tool": "look", "arguments": {}}
    _assert_refused(gate.submit(proposal, TYPED), ReasonCode.INTERNAL_ERROR)
    flaky.fail = False
    assert gate.submit(proposal, TYPED).ok


# --- 8 and 9. Running, time limits and results (P9, P13, P14) ---------------


def test_a_failing_tool_reports_a_fixed_refusal(
    audit: AuditLog, audit_path: Path, clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    def handler(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        raise RuntimeError(f"internal detail {CANARY} /Users/someone/private")

    gate = Gate([_tool("look", RiskLevel.LOW, handler)], audit, clock=clock)
    with caplog.at_level(logging.DEBUG):
        result = gate.submit({"tool": "look", "arguments": {}}, TYPED)
    _assert_refused(result, ReasonCode.TOOL_FAILED)
    for text in [repr(result), caplog.text, audit_path.read_text()]:
        assert CANARY not in text
        assert "private" not in text
    assert _entries(audit_path)[-1]["data"]["outcome"] == "failed"


def test_a_slow_tool_times_out_and_is_blocked_until_it_finishes(
    audit: AuditLog, audit_path: Path, calls: Calls
) -> None:
    release = threading.Event()
    stopped = threading.Event()

    def handler(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        release.wait(timeout=30)
        stopped.set()
        return {}

    slow = _tool("slow", RiskLevel.LOW, handler, timeout_seconds=0.05)
    other = _tool("other", RiskLevel.LOW, calls.handler("other"))
    gate = Gate([slow, other], audit)
    proposal = {"tool": "slow", "arguments": {}}
    try:
        _assert_refused(gate.submit(proposal, TYPED), ReasonCode.TIMED_OUT)
        outcome = _entries(audit_path)[-1]["data"]
        assert outcome["outcome"] == "timed_out"
        assert outcome["duration_ms"] >= 50
        # Still running in the background: no second copy is started.
        _assert_refused(gate.submit(proposal, TYPED), ReasonCode.RATE_LIMITED)
        # Other tools are not affected.
        assert gate.submit({"tool": "other", "arguments": {}}, TYPED).ok
    finally:
        release.set()
    assert stopped.wait(timeout=5)
    _wait_until(lambda: "slow" not in gate._running)
    release.clear()
    release.set()
    assert gate.submit(proposal, TYPED).ok


def _wait_until(condition: Callable[[], bool]) -> None:
    done = threading.Event()
    for _ in range(500):
        if condition():
            return
        done.wait(0.01)
    raise AssertionError("condition was not met in time")


@pytest.mark.parametrize(
    "result",
    [
        None,
        "text",
        ["a", "list"],
        {"when": object()},
        {"value": float("nan")},
        {"value": float("inf")},
        {"data": b"bytes"},
        {"big": "x" * (MAX_RESULT_CHARACTERS + 1)},
        {("tuple", "key"): 1},
    ],
)
def test_results_that_are_not_plain_bounded_data_are_refused(
    audit: AuditLog, audit_path: Path, clock: FakeClock, result: object
) -> None:
    gate = Gate(
        [_tool("look", RiskLevel.LOW, lambda arguments: result)],  # type: ignore[arg-type,return-value]
        audit,
        clock=clock,
    )
    _assert_refused(gate.submit({"tool": "look", "arguments": {}}, TYPED), ReasonCode.TOOL_FAILED)
    assert _entries(audit_path)[-1]["data"]["outcome"] == "bad_result"


def test_result_is_a_copy_the_tool_cannot_change_later(audit: AuditLog, clock: FakeClock) -> None:
    kept: dict[str, object] = {"items": [1, 2]}
    gate = Gate([_tool("look", RiskLevel.LOW, lambda arguments: kept)], audit, clock=clock)
    result = gate.submit({"tool": "look", "arguments": {}}, TYPED)
    kept["items"] = "changed afterwards"
    assert result.result == {"items": [1, 2]}


# --- Fail closed (P10, R8) ---------------------------------------------------


class BoomError(Exception):
    pass


def _explode(*args: object, **kwargs: object) -> Any:
    raise BoomError(f"detail {CANARY}")


@pytest.mark.parametrize(
    "break_it",
    [
        lambda gate, monkeypatch: monkeypatch.setattr(gate, "_clock", _explode),
        lambda gate, monkeypatch: monkeypatch.setattr(gate, "_floods", {}),
        lambda gate, monkeypatch: monkeypatch.setattr(gate, "_tools", None),
        lambda gate, monkeypatch: monkeypatch.setattr(ToolDefinition, "validate", _explode),
        lambda gate, monkeypatch: monkeypatch.setattr(gate_module, "digest_arguments", _explode),
        lambda gate, monkeypatch: monkeypatch.setattr(gate_module, "REACH", {}),
        lambda gate, monkeypatch: monkeypatch.setattr(gate, "_limits", {}),
        lambda gate, monkeypatch: monkeypatch.setattr(gate, "_running", None),
        lambda gate, monkeypatch: monkeypatch.setattr(gate._audit, "append", _explode),
        lambda gate, monkeypatch: monkeypatch.setattr(threading, "Thread", _explode),
    ],
    ids=[
        "clock", "flood", "allowlist", "arguments", "digest", "origin", "limit", "running",
        "audit", "thread",
    ],
)  # fmt: skip
def test_an_error_in_any_check_is_a_refusal(
    gate: Gate,
    calls: Calls,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    break_it: Callable[[Gate, pytest.MonkeyPatch], None],
) -> None:
    break_it(gate, monkeypatch)
    with caplog.at_level(logging.DEBUG):
        result = gate.submit(_open_app(), INTERFACE)
    monkeypatch.undo()
    _assert_refused(result, ReasonCode.INTERNAL_ERROR)
    assert calls.seen == []
    assert CANARY not in caplog.text
    # The gate still works afterwards.
    assert gate.submit(_open_app(), INTERFACE).ok


# --- Refusals (P13) ----------------------------------------------------------


def test_every_reason_has_a_fixed_sentence() -> None:
    assert set(MESSAGES) == set(ReasonCode)
    for message in MESSAGES.values():
        assert message
        assert "{" not in message
        assert "%" not in message


def test_documented_reason_codes_match_the_code() -> None:
    text = (Path(__file__).parent.parent / "docs" / "permissions.md").read_text(encoding="utf-8")
    section = text.split("## Reason codes", 1)[1].split("\n## ", 1)[0]
    documented = set(re.findall(r"^\| `([A-Z_]+)` \|", section, flags=re.MULTILINE))
    assert documented == {code.value for code in ReasonCode}


# --- Many callers at once ----------------------------------------------------


def test_rate_limit_holds_under_concurrent_callers(audit: AuditLog, audit_path: Path) -> None:
    count = 0
    count_lock = threading.Lock()

    def handler(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        nonlocal count
        with count_lock:
            count += 1
        return {}

    tool = _tool("look", RiskLevel.LOW, handler, max_calls=5, period_seconds=3600.0)
    gate = Gate([tool], audit, max_submissions=1000)
    start = threading.Barrier(8)

    def caller() -> None:
        start.wait()
        for _ in range(10):
            gate.submit({"tool": "look", "arguments": {}}, TYPED)

    threads = [threading.Thread(target=caller) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert count == 5
    assert verify_audit_chain(audit_path).ok
