"""Tests for physical approvals (P7; T-APPR-1 to T-APPR-3, T-VOICE-3; required tests 6, 7, 8)."""

import copy
import dataclasses
import hmac
import json
import logging
import pickle
import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

import potato.security.approvals as approvals_module
from potato.security.approvals import (
    MAX_REMEMBERED_NONCES,
    NONCE_BYTES,
    TAG_BYTES,
    ApprovalCheck,
    ApprovalError,
    ApprovalIssuer,
    ApprovalRequest,
    ApprovalVerifier,
    create_approval_pair,
)
from potato.security.audit import AuditLog, verify_audit_chain
from potato.security.gate import MESSAGES, Gate, ReasonCode, RequestOrigin
from potato.security.redaction import Redactor
from potato.security.tools import (
    ArgumentValue,
    ChoiceField,
    IntegerField,
    RiskLevel,
    ToolDefinition,
    digest_arguments,
)

SOURCE = Path(__file__).parent.parent / "src" / "potato"
LIFETIME = 30.0
VOICE, TYPED, INTERFACE = RequestOrigin.VOICE, RequestOrigin.TYPED, RequestOrigin.INTERFACE
ARGUMENTS: dict[str, ArgumentValue] = {"target": "cache", "level": 2}
PROPOSAL: dict[str, object] = {"tool": "wipe", "arguments": ARGUMENTS}


class FakeClock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(5000.0)


@pytest.fixture
def wall() -> FakeClock:
    return FakeClock(1_800_000_000.0)


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "logs" / "audit.jsonl"


@pytest.fixture
def audit(audit_path: Path) -> Iterator[AuditLog]:
    with AuditLog(audit_path, Redactor()) as log:
        yield log


@pytest.fixture
def pair(
    audit: AuditLog, clock: FakeClock, wall: FakeClock
) -> tuple[ApprovalIssuer, ApprovalVerifier]:
    return create_approval_pair(LIFETIME, audit, clock=clock, wall_clock=wall)


@pytest.fixture
def issuer(pair: tuple[ApprovalIssuer, ApprovalVerifier]) -> ApprovalIssuer:
    return pair[0]


@pytest.fixture
def verifier(pair: tuple[ApprovalIssuer, ApprovalVerifier]) -> ApprovalVerifier:
    return pair[1]


@pytest.fixture
def ran() -> list[dict[str, ArgumentValue]]:
    return []


@pytest.fixture
def gate(
    audit: AuditLog,
    verifier: ApprovalVerifier,
    clock: FakeClock,
    ran: list[dict[str, ArgumentValue]],
) -> Gate:
    """A gate with a sensitive tool that exists only in these tests."""

    def wipe(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        ran.append(dict(arguments))
        return {"wiped": True}

    tools = [
        ToolDefinition(
            name="wipe",
            risk=RiskLevel.SENSITIVE,
            arguments={
                "target": ChoiceField(frozenset({"cache", "history"})),
                "level": IntegerField(1, 3),
            },
            handler=wipe,
        ),
        ToolDefinition(
            name="other_wipe", risk=RiskLevel.SENSITIVE, arguments={}, handler=lambda a: {}
        ),
        ToolDefinition(name="look", risk=RiskLevel.LOW, arguments={}, handler=lambda a: {}),
    ]
    return Gate(tools, audit, approvals=verifier, clock=clock)


def _request() -> ApprovalRequest:
    return ApprovalRequest("wipe", ARGUMENTS)


def _entries(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _assert_invalid(gate: Gate, audit_path: Path, approval: object, problem: str) -> None:
    result = gate.submit(PROPOSAL, INTERFACE, approval)
    assert not result.ok
    assert result.reason is ReasonCode.APPROVAL_INVALID
    # The refusal does not say which problem it was. The audit log does.
    assert result.message == MESSAGES[ReasonCode.APPROVAL_INVALID]
    assert result.pending is None
    assert _entries(audit_path)[-1]["data"]["approval_problem"] == problem


# --- The whole flow ----------------------------------------------------------


def test_the_whole_flow(
    gate: Gate, issuer: ApprovalIssuer, audit_path: Path, ran: list[dict[str, ArgumentValue]]
) -> None:
    # 1. Without an approval the gate refuses and describes the exact action.
    first = gate.submit(PROPOSAL, TYPED)
    assert first.reason is ReasonCode.APPROVAL_REQUIRED
    assert first.pending == ApprovalRequest("wipe", ARGUMENTS)
    assert ran == []

    # 2. The user clicks "Approve", and the request is sent again.
    assert first.pending is not None
    approval = issuer.approve(first.pending)
    second = gate.submit(PROPOSAL, INTERFACE, approval)
    assert second.ok
    assert ran == [ARGUMENTS]

    events = [(entry["event"], entry["data"]) for entry in _entries(audit_path)]
    digest = digest_arguments(ARGUMENTS)
    assert events == [
        ("permission_denied", {"tool": "wipe", "origin": "typed", "reason": "APPROVAL_REQUIRED",
                               "arguments_digest": digest}),
        ("approval_decided", {"tool": "wipe", "decision": "approved", "arguments_digest": digest}),
        ("permission_granted", {"tool": "wipe", "origin": "interface", "arguments_digest": digest,
                                "approved": True}),
        ("tool_executed", {"tool": "wipe", "origin": "interface", "outcome": "ok",
                           "duration_ms": 0}),
    ]  # fmt: skip
    assert verify_audit_chain(audit_path).ok


def test_the_pending_request_is_read_only_and_holds_validated_values(gate: Gate) -> None:
    proposal = {"tool": "wipe", "arguments": {"target": "cache", "level": 2}}
    pending = gate.submit(proposal, TYPED).pending
    assert pending is not None
    proposal["arguments"]["target"] = "history"  # type: ignore[index]
    assert pending.arguments == ARGUMENTS
    with pytest.raises(TypeError):
        pending.arguments["target"] = "history"  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        pending.tool = "other_wipe"  # type: ignore[misc]


def test_a_refused_request_does_not_describe_an_action(gate: Gate) -> None:
    bad = {"tool": "wipe", "arguments": {"target": "everything", "level": 2}}
    result = gate.submit(bad, TYPED)
    assert result.reason is ReasonCode.INVALID_ARGUMENTS
    assert result.pending is None


def test_an_approval_is_ignored_for_a_tool_that_needs_none(
    gate: Gate, issuer: ApprovalIssuer
) -> None:
    approval = issuer.approve(_request())
    assert gate.submit({"tool": "look", "arguments": {}}, TYPED, approval).ok
    assert gate.submit({"tool": "look", "arguments": {}}, TYPED, "nonsense").ok
    # It was not used up.
    assert gate.submit(PROPOSAL, INTERFACE, approval).ok


# --- Voice (T-VOICE-3; required test 6) --------------------------------------


def test_voice_cannot_run_a_sensitive_tool_even_with_a_real_approval(
    gate: Gate, issuer: ApprovalIssuer, ran: list[dict[str, ArgumentValue]]
) -> None:
    approval = issuer.approve(_request())
    result = gate.submit(PROPOSAL, VOICE, approval)
    assert result.reason is ReasonCode.ORIGIN_NOT_ALLOWED
    assert result.pending is None
    assert ran == []
    # Voice did not use the approval up either.
    assert gate.submit(PROPOSAL, INTERFACE, approval).ok


@pytest.mark.parametrize(
    "spoken", ["yes", "approve", "approved", "I approve", "confirm", True, 1, {"approved": True}]
)
def test_saying_yes_is_not_an_approval(
    gate: Gate, audit_path: Path, ran: list[dict[str, ArgumentValue]], spoken: object
) -> None:
    for origin in (VOICE, TYPED, INTERFACE):
        assert not gate.submit(PROPOSAL, origin, spoken).ok
    _assert_invalid(gate, audit_path, spoken, "malformed")
    assert ran == []


def test_only_the_interface_package_refers_to_the_issuer() -> None:
    # R4: the names that can make an approval appear in the module that
    # defines them and, later, in the interface. Nowhere else.
    for path in SOURCE.rglob("*.py"):
        relative = path.relative_to(SOURCE).as_posix()
        if relative == "security/approvals.py" or relative.startswith("ui/"):
            continue
        text = path.read_text(encoding="utf-8")
        for name in ("ApprovalIssuer", "create_approval_pair", "_tag(", "_message("):
            assert name not in text, f"{relative} refers to {name}"


def test_voice_code_does_not_import_approvals_or_the_interface() -> None:
    for path in (SOURCE / "voice").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"^\s*(from|import)\s+potato\.(ui|security\.approvals)", text, re.M)
        assert "approvals" not in text.split('"""')[-1]


def test_the_verifier_cannot_make_approvals(verifier: ApprovalVerifier) -> None:
    public = {name for name in dir(verifier) if not name.startswith("_")}
    assert public == {"check"}


# --- Expiry (T-APPR-1; required test 7) --------------------------------------


def test_an_approval_works_until_just_before_it_expires(
    gate: Gate, issuer: ApprovalIssuer, clock: FakeClock, wall: FakeClock
) -> None:
    approval = issuer.approve(_request())
    clock.now += LIFETIME - 0.001
    wall.now += LIFETIME - 0.001
    assert gate.submit(PROPOSAL, INTERFACE, approval).ok


def test_an_expired_approval_is_refused(
    gate: Gate,
    issuer: ApprovalIssuer,
    clock: FakeClock,
    wall: FakeClock,
    audit_path: Path,
    ran: list[dict[str, ArgumentValue]],
) -> None:
    approval = issuer.approve(_request())
    clock.now += LIFETIME
    wall.now += LIFETIME
    _assert_invalid(gate, audit_path, approval, "expired")
    assert ran == []


def test_sleeping_the_mac_does_not_keep_an_approval_alive(
    gate: Gate, issuer: ApprovalIssuer, wall: FakeClock, audit_path: Path
) -> None:
    # The monotonic clock stands still during sleep. The wall clock does not.
    approval = issuer.approve(_request())
    wall.now += 3600
    _assert_invalid(gate, audit_path, approval, "expired")


def test_turning_the_clock_back_does_not_keep_an_approval_alive(
    gate: Gate, issuer: ApprovalIssuer, clock: FakeClock, wall: FakeClock, audit_path: Path
) -> None:
    approval = issuer.approve(_request())
    clock.now += LIFETIME
    wall.now -= 86400
    _assert_invalid(gate, audit_path, approval, "expired")


@pytest.mark.parametrize("edited", ["expires_monotonic_ms", "expires_wall_ms"])
def test_expiry_cannot_be_extended_by_editing_the_token(
    gate: Gate,
    issuer: ApprovalIssuer,
    clock: FakeClock,
    wall: FakeClock,
    audit_path: Path,
    edited: str,
) -> None:
    # Each expiry time is covered by the hash on its own.
    approval = issuer.approve(_request())
    longer = dataclasses.replace(approval, **{edited: getattr(approval, edited) + 10**9})
    _assert_invalid(gate, audit_path, longer, "mismatch")
    clock.now += LIFETIME
    wall.now += LIFETIME
    _assert_invalid(gate, audit_path, longer, "mismatch")


@pytest.mark.parametrize("lifetime", [0, 0.5, -1, 121, float("nan"), float("inf"), "30", True])
def test_lifetime_outside_the_bounds_is_refused(audit: AuditLog, lifetime: Any) -> None:
    with pytest.raises(ValueError, match="lifetime_seconds"):
        create_approval_pair(lifetime, audit)


# --- Changed actions (T-APPR-2; required test 8) -----------------------------


@pytest.mark.parametrize(
    "proposal",
    [
        {"tool": "wipe", "arguments": {"target": "history", "level": 2}},
        {"tool": "wipe", "arguments": {"target": "cache", "level": 3}},
        {"tool": "wipe", "arguments": {"target": "cache", "level": 1}},
    ],
)
def test_an_approval_does_not_cover_changed_arguments(
    gate: Gate,
    issuer: ApprovalIssuer,
    audit_path: Path,
    ran: list[dict[str, ArgumentValue]],
    proposal: dict[str, object],
) -> None:
    approval = issuer.approve(_request())
    result = gate.submit(proposal, INTERFACE, approval)
    assert result.reason is ReasonCode.APPROVAL_INVALID
    assert _entries(audit_path)[-1]["data"]["approval_problem"] == "mismatch"
    assert ran == []
    # The approval is still good for what the user actually approved.
    assert gate.submit(PROPOSAL, INTERFACE, approval).ok


def test_an_approval_does_not_cover_another_tool(
    gate: Gate, issuer: ApprovalIssuer, audit_path: Path
) -> None:
    approval = issuer.approve(ApprovalRequest("other_wipe", {}))
    _assert_invalid(gate, audit_path, approval, "mismatch")
    approval = issuer.approve(_request())
    result = gate.submit({"tool": "other_wipe", "arguments": {}}, INTERFACE, approval)
    assert result.reason is ReasonCode.APPROVAL_INVALID


def test_an_approval_does_not_cover_another_tool_with_the_same_arguments(
    issuer: ApprovalIssuer, verifier: ApprovalVerifier
) -> None:
    # The tool name is covered by the hash, not only the arguments.
    approval = issuer.approve(ApprovalRequest("wipe", {}))
    assert verifier.check("other_wipe", {}, approval) is ApprovalCheck.MISMATCH
    assert verifier.check("wipe", {}, approval) is ApprovalCheck.VALID


def test_text_and_number_arguments_are_told_apart(
    issuer: ApprovalIssuer, verifier: ApprovalVerifier
) -> None:
    approval = issuer.approve(ApprovalRequest("wipe", {"level": 2}))
    assert verifier.check("wipe", {"level": "2"}, approval) is ApprovalCheck.MISMATCH
    assert verifier.check("wipe", {"level": 2}, approval) is ApprovalCheck.VALID


def test_values_cannot_slide_between_fields(
    issuer: ApprovalIssuer, verifier: ApprovalVerifier
) -> None:
    approval = issuer.approve(ApprovalRequest("wipe", {"a": "x", "b": "y"}))
    for arguments in [{"a": "x,b:y"}, {"a": 'x","b":"y'}, {"a": "xy", "b": ""}, {"ab": "xy"}]:
        assert verifier.check("wipe", arguments, approval) is ApprovalCheck.MISMATCH
    assert verifier.check("wipea", {"": "x", "b": "y"}, approval) is ApprovalCheck.MISMATCH


def test_argument_order_does_not_matter(issuer: ApprovalIssuer, verifier: ApprovalVerifier) -> None:
    approval = issuer.approve(ApprovalRequest("wipe", {"target": "cache", "level": 2}))
    assert verifier.check("wipe", {"level": 2, "target": "cache"}, approval) is ApprovalCheck.VALID


@pytest.mark.parametrize("position", [0, TAG_BYTES // 2, TAG_BYTES - 1])
def test_a_changed_tag_is_refused(
    gate: Gate, issuer: ApprovalIssuer, audit_path: Path, position: int
) -> None:
    approval = issuer.approve(_request())
    tag = bytearray(approval.tag)
    tag[position] ^= 1
    _assert_invalid(gate, audit_path, dataclasses.replace(approval, tag=bytes(tag)), "mismatch")


def test_a_changed_nonce_is_refused(gate: Gate, issuer: ApprovalIssuer, audit_path: Path) -> None:
    approval = issuer.approve(_request())
    other = dataclasses.replace(approval, nonce=bytes(NONCE_BYTES))
    _assert_invalid(gate, audit_path, other, "mismatch")


# --- Replays (T-APPR-1) ------------------------------------------------------


def test_an_approval_works_once(
    gate: Gate, issuer: ApprovalIssuer, audit_path: Path, ran: list[dict[str, ArgumentValue]]
) -> None:
    approval = issuer.approve(_request())
    assert gate.submit(PROPOSAL, INTERFACE, approval).ok
    _assert_invalid(gate, audit_path, approval, "replayed")
    _assert_invalid(gate, audit_path, copy.copy(approval), "replayed")
    assert len(ran) == 1


def test_each_approval_is_different(issuer: ApprovalIssuer) -> None:
    approvals = [issuer.approve(_request()) for _ in range(50)]
    assert len({approval.nonce for approval in approvals}) == 50
    assert len({approval.tag for approval in approvals}) == 50


def test_two_approvals_allow_two_runs(
    gate: Gate, issuer: ApprovalIssuer, ran: list[dict[str, ArgumentValue]]
) -> None:
    first, second = issuer.approve(_request()), issuer.approve(_request())
    assert gate.submit(PROPOSAL, INTERFACE, first).ok
    assert gate.submit(PROPOSAL, INTERFACE, second).ok
    assert len(ran) == 2


def test_an_approval_is_used_up_even_if_a_later_check_refuses(
    audit: AuditLog, pair: tuple[ApprovalIssuer, ApprovalVerifier], clock: FakeClock
) -> None:
    issuer, verifier = pair
    tool = ToolDefinition(
        name="wipe", risk=RiskLevel.SENSITIVE, arguments={}, handler=lambda a: {}, max_calls=1
    )
    gate = Gate([tool], audit, approvals=verifier, clock=clock)
    proposal = {"tool": "wipe", "arguments": {}}
    request = ApprovalRequest("wipe", {})
    assert gate.submit(proposal, INTERFACE, issuer.approve(request)).ok
    second = issuer.approve(request)
    assert gate.submit(proposal, INTERFACE, second).reason is ReasonCode.RATE_LIMITED
    clock.now += 60
    assert gate.submit(proposal, INTERFACE, second).reason is ReasonCode.APPROVAL_INVALID


def test_used_nonces_are_forgotten_only_after_they_expire(
    issuer: ApprovalIssuer, verifier: ApprovalVerifier, clock: FakeClock
) -> None:
    approval = issuer.approve(_request())
    assert verifier.check("wipe", ARGUMENTS, approval) is ApprovalCheck.VALID
    clock.now += LIFETIME - 0.001
    fresh = issuer.approve(_request())
    assert verifier.check("wipe", ARGUMENTS, fresh) is ApprovalCheck.VALID
    assert approval.nonce in verifier._used
    assert verifier.check("wipe", ARGUMENTS, approval) is ApprovalCheck.REPLAYED
    clock.now += 0.001
    later = issuer.approve(_request())
    assert verifier.check("wipe", ARGUMENTS, later) is ApprovalCheck.VALID
    assert approval.nonce not in verifier._used
    assert verifier.check("wipe", ARGUMENTS, approval) is ApprovalCheck.EXPIRED


def test_when_no_more_nonces_can_be_remembered_approvals_are_refused(
    issuer: ApprovalIssuer, verifier: ApprovalVerifier
) -> None:
    for _ in range(MAX_REMEMBERED_NONCES):
        assert verifier.check("wipe", ARGUMENTS, issuer.approve(_request())) is ApprovalCheck.VALID
    extra = issuer.approve(_request())
    assert verifier.check("wipe", ARGUMENTS, extra) is ApprovalCheck.UNAVAILABLE


# --- Forgery (T-APPR-3) ------------------------------------------------------


def test_an_approval_from_another_key_is_refused(
    gate: Gate, audit: AuditLog, clock: FakeClock, wall: FakeClock, audit_path: Path
) -> None:
    other_issuer, _ = create_approval_pair(LIFETIME, audit, clock=clock, wall_clock=wall)
    _assert_invalid(gate, audit_path, other_issuer.approve(_request()), "mismatch")


def test_a_hash_without_the_key_is_refused(
    gate: Gate, issuer: ApprovalIssuer, audit_path: Path
) -> None:
    real = issuer.approve(_request())
    message = approvals_module._message(
        "wipe", ARGUMENTS, real.nonce, real.expires_monotonic_ms, real.expires_wall_ms
    )
    for guess in (b"", bytes(32), b"potato"):
        forged = dataclasses.replace(real, tag=approvals_module._tag(guess, message))
        _assert_invalid(gate, audit_path, forged, "mismatch")


@pytest.mark.parametrize(
    "changes",
    [
        {"nonce": b"short"},
        {"nonce": "0" * NONCE_BYTES},
        {"nonce": bytearray(NONCE_BYTES)},
        {"tag": b"short"},
        {"tag": "0" * TAG_BYTES},
        {"tag": None},
        {"expires_monotonic_ms": 1.5},
        {"expires_monotonic_ms": "9999999999"},
        {"expires_wall_ms": None},
        {"expires_wall_ms": True},
    ],
)
def test_malformed_tokens_are_refused(
    gate: Gate, issuer: ApprovalIssuer, audit_path: Path, changes: dict[str, Any]
) -> None:
    token = dataclasses.replace(issuer.approve(_request()), **changes)
    _assert_invalid(gate, audit_path, token, "malformed")


def test_a_lookalike_object_is_refused(
    gate: Gate, issuer: ApprovalIssuer, audit_path: Path
) -> None:
    real = issuer.approve(_request())

    class Lookalike:
        nonce = real.nonce
        tag = real.tag
        expires_monotonic_ms = real.expires_monotonic_ms
        expires_wall_ms = real.expires_wall_ms

    _assert_invalid(gate, audit_path, Lookalike(), "malformed")
    _assert_invalid(gate, audit_path, dataclasses.astuple(real), "malformed")


def test_comparison_is_constant_time(
    issuer: ApprovalIssuer, verifier: ApprovalVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    used: list[bool] = []
    real = hmac.compare_digest

    def recording(a: bytes, b: bytes) -> bool:
        used.append(True)
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", recording)
    assert verifier.check("wipe", ARGUMENTS, issuer.approve(_request())) is ApprovalCheck.VALID
    assert used == [True]
    source = (SOURCE / "security" / "approvals.py").read_text(encoding="utf-8")
    assert "== approval.tag" not in source
    assert "approval.tag ==" not in source


def test_a_gate_without_a_verifier_refuses_every_approval(
    audit: AuditLog, issuer: ApprovalIssuer, audit_path: Path, clock: FakeClock
) -> None:
    tool = ToolDefinition(
        name="wipe",
        risk=RiskLevel.SENSITIVE,
        arguments={"target": ChoiceField(frozenset({"cache"})), "level": IntegerField(1, 3)},
        handler=lambda a: {},
    )
    gate = Gate([tool], audit, clock=clock)
    _assert_invalid(gate, audit_path, issuer.approve(_request()), "unavailable")


@pytest.mark.parametrize("answer", ["valid", True, None, "VALID", 1])
def test_only_the_exact_valid_answer_lets_a_tool_run(
    gate: Gate,
    issuer: ApprovalIssuer,
    verifier: ApprovalVerifier,
    monkeypatch: pytest.MonkeyPatch,
    ran: list[dict[str, ArgumentValue]],
    answer: object,
) -> None:
    # Fail closed: a verifier that answers anything odd is treated as "no".
    class Odd:
        def check(self, *args: object) -> object:
            return answer

    monkeypatch.setattr(gate, "_approvals", Odd())
    assert not gate.submit(PROPOSAL, INTERFACE, issuer.approve(_request())).ok
    assert ran == []


def test_an_error_while_checking_an_approval_is_a_refusal(
    gate: Gate,
    issuer: ApprovalIssuer,
    verifier: ApprovalVerifier,
    monkeypatch: pytest.MonkeyPatch,
    ran: list[dict[str, ArgumentValue]],
) -> None:
    def explode() -> float:
        raise RuntimeError

    monkeypatch.setattr(verifier, "_clock", explode)
    result = gate.submit(PROPOSAL, INTERFACE, issuer.approve(_request()))
    assert result.reason is ReasonCode.INTERNAL_ERROR
    assert ran == []


# --- The key -----------------------------------------------------------------


def test_the_key_is_random_and_the_right_size(audit: AuditLog) -> None:
    keys = {create_approval_pair(LIFETIME, audit)[0]._key for _ in range(20)}
    assert len(keys) == 20
    assert all(type(key) is bytes and len(key) == 32 for key in keys)


def test_the_key_and_tag_never_appear_in_text(
    issuer: ApprovalIssuer,
    verifier: ApprovalVerifier,
    gate: Gate,
    audit_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        approval = issuer.approve(_request())
        gate.submit(PROPOSAL, INTERFACE, approval)
        gate.submit(PROPOSAL, INTERFACE, approval)
    texts = [repr(issuer), str(issuer), repr(verifier), repr(approval), str(approval),
             caplog.text, audit_path.read_text()]  # fmt: skip
    for secret in (issuer._key, approval.tag):
        for form in (secret.hex(), repr(secret), secret.hex().upper()):
            for text in texts:
                assert form not in text
    assert repr(issuer) == "<ApprovalIssuer>"
    assert repr(verifier) == "<ApprovalVerifier>"
    assert not hasattr(issuer, "__dict__")


def test_key_holders_cannot_be_copied_or_saved(
    issuer: ApprovalIssuer, verifier: ApprovalVerifier
) -> None:
    for holder in (issuer, verifier):
        with pytest.raises(TypeError):
            pickle.dumps(holder)
        with pytest.raises(TypeError):
            copy.copy(holder)
        with pytest.raises(TypeError):
            copy.deepcopy(holder)


# --- The issuer --------------------------------------------------------------


def test_no_record_no_approval(issuer: ApprovalIssuer, audit: AuditLog) -> None:
    audit.close()
    with pytest.raises(ApprovalError):
        issuer.approve(_request())


@pytest.mark.parametrize(
    "request_",
    [
        None,
        "wipe",
        {"tool": "wipe", "arguments": {}},
        ("wipe", {}),
        ApprovalRequest(5, {}),  # type: ignore[arg-type]
        ApprovalRequest("wipe", {"level": 2.5}),  # type: ignore[dict-item]
        ApprovalRequest("wipe", {"level": True}),
        ApprovalRequest("wipe", {"items": ["a"]}),  # type: ignore[dict-item]
        ApprovalRequest("wipe", {1: "a"}),  # type: ignore[dict-item]
    ],
)
def test_the_issuer_signs_only_real_requests(
    issuer: ApprovalIssuer, audit_path: Path, request_: Any
) -> None:
    with pytest.raises(ApprovalError) as caught:
        issuer.approve(request_)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__
    assert not audit_path.exists() or audit_path.read_text() == ""


def test_denying_is_recorded_and_makes_nothing(issuer: ApprovalIssuer, audit_path: Path) -> None:
    assert issuer.deny(_request()) is None  # type: ignore[func-returns-value]
    (entry,) = _entries(audit_path)
    assert entry["event"] == "approval_decided"
    assert entry["data"]["decision"] == "denied"


def test_denying_never_raises(issuer: ApprovalIssuer, audit: AuditLog) -> None:
    audit.close()
    issuer.deny(_request())
    issuer.deny("nonsense")  # type: ignore[arg-type]
