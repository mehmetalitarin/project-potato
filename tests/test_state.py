"""Tests for the assistant state manager (T-VOICE-1, T-VOICE-4; required test 13)."""

import itertools
import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from potato.core.state import (
    _EXPOSURE,
    CAPABILITIES,
    INITIAL_STATE,
    ORIGINS,
    TRANSITIONS,
    AssistantState,
    Capabilities,
    Event,
    Origin,
    StateManager,
    StateTransitionError,
)
from potato.security.audit import AuditLog, verify_audit_chain
from potato.security.redaction import Redactor

ARCHITECTURE = Path(__file__).parent.parent / "docs" / "architecture.md"
TIMEOUT = 300.0

S = AssistantState
CLOSED = Capabilities(False, False, False, False)


class FakeClock:
    """A clock the test moves by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def manager(clock: FakeClock) -> StateManager:
    return StateManager(TIMEOUT, clock=clock)


@pytest.fixture
def audit(tmp_path: Path) -> Iterator[AuditLog]:
    with AuditLog(tmp_path / "logs" / "audit.jsonl", Redactor()) as log:
        yield log


def _reach(manager: StateManager, state: AssistantState) -> None:
    """Drive a fresh manager to ``state`` using allowed events only."""
    route = {
        S.SLEEPING: [],
        S.STANDBY: [Event.INTERFACE_WAKE],
        S.ACTIVE: [Event.INTERFACE_TALK],
        S.ERROR: [Event.FAILURE],
    }[state]
    for event in route:
        manager.handle(event)
    assert manager.state is state


def _state(manager: StateManager) -> AssistantState:
    """Read the state afresh, so the type checker does not assume it is unchanged."""
    return manager.state


def _entries(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


# --- The rules themselves --------------------------------------------------


def test_starts_asleep_with_everything_closed(manager: StateManager) -> None:
    assert INITIAL_STATE is S.SLEEPING
    assert manager.state is S.SLEEPING
    assert manager.capabilities == CLOSED


def test_every_event_has_an_origin() -> None:
    assert set(ORIGINS) == set(Event)


def test_each_events_origin_is_pinned() -> None:
    # Labelling a voice event as the interface would let voice do what only
    # a click may do, so the exact split is fixed here.
    assert {e for e in Event if ORIGINS[e] is Origin.VOICE} == {
        Event.WAKE_WORD_HEARD,
        Event.VOICE_SLEEP,
    }
    assert {e for e in Event if ORIGINS[e] is Origin.INTERFACE} == {
        Event.INTERFACE_WAKE,
        Event.INTERFACE_TALK,
        Event.INTERFACE_SLEEP,
    }


def test_every_state_has_capabilities() -> None:
    assert set(CAPABILITIES) == set(AssistantState)


@pytest.mark.parametrize(
    ("state", "event"), list(itertools.product(AssistantState, Event)), ids=str
)
def test_every_pair_follows_the_table(
    manager: StateManager, state: AssistantState, event: Event
) -> None:
    _reach(manager, state)
    expected = TRANSITIONS.get((state, event))
    if expected is None:
        with pytest.raises(StateTransitionError, match="not allowed"):
            manager.handle(event)
        assert manager.state is state
    else:
        assert manager.handle(event) is expected
        assert manager.state is expected


@pytest.mark.parametrize("state", [S.SLEEPING, S.ERROR])
@pytest.mark.parametrize("event", [e for e in Event if ORIGINS[e] is Origin.VOICE])
def test_voice_can_never_leave_sleeping_or_error(state: AssistantState, event: Event) -> None:
    assert (state, event) not in TRANSITIONS


def _opens_something(old: AssistantState, new: AssistantState) -> bool:
    """Whether a change opens the microphone, starts transcribing or loads the model.

    Restarting the wake-word detector on the way from Active to Standby does
    not count: the microphone is already open, and the detector hears less
    than speech-to-text did.
    """
    before, after = CAPABILITIES[old], CAPABILITIES[new]
    return any(
        getattr(after, field) and not getattr(before, field)
        for field in ("microphone_open", "speech_to_text", "model_loaded")
    )


def test_the_codes_ranking_agrees_with_what_each_state_opens() -> None:
    # The audit rule (record before opening) relies on this ranking.
    for old, new in itertools.product(AssistantState, AssistantState):
        assert (_EXPOSURE[new] > _EXPOSURE[old]) == _opens_something(old, new), (old, new)


def test_the_only_thing_voice_can_open_is_a_conversation_from_standby() -> None:
    for (old, event), new in TRANSITIONS.items():
        if ORIGINS[event] is Origin.VOICE and _opens_something(old, new):
            assert (old, event, new) == (S.STANDBY, Event.WAKE_WORD_HEARD, S.ACTIVE)


def test_potato_itself_never_opens_anything() -> None:
    # Timeouts and failures only ever close things.
    for (old, event), new in TRANSITIONS.items():
        if ORIGINS[event] is Origin.SYSTEM:
            assert not _opens_something(old, new), (old, event, new)


def test_failure_reaches_error_from_every_state() -> None:
    for state in AssistantState:
        assert TRANSITIONS[(state, Event.FAILURE)] is S.ERROR


def test_error_and_sleeping_close_everything() -> None:
    assert CAPABILITIES[S.ERROR] == CLOSED
    assert CAPABILITIES[S.SLEEPING] == CLOSED


def test_speech_to_text_never_runs_with_the_wake_word() -> None:
    for capabilities in CAPABILITIES.values():
        assert not (capabilities.wake_word and capabilities.speech_to_text)
        if capabilities.wake_word or capabilities.speech_to_text:
            assert capabilities.microphone_open


def test_tables_cannot_be_changed_at_run_time() -> None:
    with pytest.raises(TypeError):
        TRANSITIONS[(S.SLEEPING, Event.WAKE_WORD_HEARD)] = S.ACTIVE  # type: ignore[index]
    with pytest.raises(TypeError):
        CAPABILITIES[S.SLEEPING] = CAPABILITIES[S.ACTIVE]  # type: ignore[index]


def test_unknown_event_is_refused(manager: StateManager) -> None:
    with pytest.raises(StateTransitionError, match="unknown"):
        manager.handle("interface_wake")  # type: ignore[arg-type]
    assert manager.state is S.SLEEPING


@pytest.mark.parametrize("timeout", [0.0, -1.0, float("nan")])
def test_bad_idle_timeout_is_refused(timeout: float) -> None:
    with pytest.raises(ValueError, match="idle_timeout_seconds"):
        StateManager(timeout)


def test_documented_state_table_matches_the_code() -> None:
    text = ARCHITECTURE.read_text(encoding="utf-8")
    section = text.split("## Assistant states", 1)[1].split("\n## ", 1)[0]
    rows: dict[str, Capabilities] = {}
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 5 or cells[0] in {"State", "---"}:
            continue
        name = re.sub(r"\s*\(.*\)", "", cells[0]).lower()
        mic, wake, speech, model = cells[1:]
        rows[name] = Capabilities(
            mic == "Open", wake == "Listening", speech == "On", model == "Yes"
        )
    assert rows.pop("off") == CLOSED
    assert rows == {state.value: capabilities for state, capabilities in CAPABILITIES.items()}


# --- Standby and the idle timeout (required test 13) -------------------------


def test_active_returns_to_standby_after_the_idle_timeout(
    manager: StateManager, clock: FakeClock
) -> None:
    _reach(manager, S.ACTIVE)
    clock.now += TIMEOUT - 1
    assert manager.check_idle() is False
    assert _state(manager) is S.ACTIVE

    clock.now += 1
    assert manager.check_idle() is True
    assert _state(manager) is S.STANDBY
    # Standby: listening for the wake word only, nothing transcribed, model unloaded.
    assert manager.capabilities == Capabilities(
        microphone_open=True, wake_word=True, speech_to_text=False, model_loaded=False
    )


def test_activity_restarts_the_idle_timer(manager: StateManager, clock: FakeClock) -> None:
    _reach(manager, S.ACTIVE)
    clock.now += TIMEOUT - 1
    manager.record_activity()
    clock.now += TIMEOUT - 1
    assert manager.check_idle() is False
    clock.now += 1
    assert manager.check_idle() is True


def test_entering_active_starts_a_fresh_timer(manager: StateManager, clock: FakeClock) -> None:
    clock.now += TIMEOUT * 10
    _reach(manager, S.ACTIVE)
    assert manager.check_idle() is False


@pytest.mark.parametrize("state", [S.SLEEPING, S.STANDBY, S.ERROR])
def test_idle_check_does_nothing_outside_active(
    manager: StateManager, clock: FakeClock, state: AssistantState
) -> None:
    _reach(manager, state)
    clock.now += TIMEOUT * 10
    assert manager.check_idle() is False
    assert manager.state is state


def test_listeners_hear_the_return_to_standby(manager: StateManager, clock: FakeClock) -> None:
    # This is how the model client will know to unload the model.
    changes: list[tuple[AssistantState, AssistantState]] = []
    _reach(manager, S.ACTIVE)
    manager.subscribe(lambda old, new: changes.append((old, new)))
    clock.now += TIMEOUT
    manager.check_idle()
    assert changes == [(S.ACTIVE, S.STANDBY)]


# --- Listeners and failing closed --------------------------------------------


def test_listeners_are_told_every_change_in_order(manager: StateManager) -> None:
    first: list[tuple[AssistantState, AssistantState]] = []
    second: list[tuple[AssistantState, AssistantState]] = []
    manager.subscribe(lambda old, new: first.append((old, new)))
    manager.subscribe(lambda old, new: second.append((old, new)))
    manager.handle(Event.INTERFACE_WAKE)
    manager.handle(Event.WAKE_WORD_HEARD)
    manager.handle(Event.VOICE_SLEEP)
    expected = [(S.SLEEPING, S.STANDBY), (S.STANDBY, S.ACTIVE), (S.ACTIVE, S.SLEEPING)]
    assert first == expected
    assert second == expected


def test_a_failing_listener_moves_potato_to_error(
    manager: StateManager, caplog: pytest.LogCaptureFixture
) -> None:
    heard: list[tuple[AssistantState, AssistantState]] = []

    def broken_microphone(old: AssistantState, new: AssistantState) -> None:
        if new is S.STANDBY:
            raise OSError("secret-detail-from-driver")

    manager.subscribe(broken_microphone)
    manager.subscribe(lambda old, new: heard.append((old, new)))
    with caplog.at_level(logging.ERROR):
        assert manager.handle(Event.INTERFACE_WAKE) is S.ERROR
    assert manager.state is S.ERROR
    assert manager.capabilities == CLOSED
    # The other listener still heard both changes, so it closed too.
    assert heard == [(S.SLEEPING, S.STANDBY), (S.STANDBY, S.ERROR)]
    assert "secret-detail-from-driver" not in caplog.text


def test_a_listener_failing_on_the_way_to_error_does_not_loop(manager: StateManager) -> None:
    calls: list[AssistantState] = []

    def always_broken(old: AssistantState, new: AssistantState) -> None:
        calls.append(new)
        raise RuntimeError

    manager.subscribe(always_broken)
    manager.handle(Event.INTERFACE_WAKE)
    assert manager.state is S.ERROR
    assert calls == [S.STANDBY, S.ERROR]


def test_a_listener_cannot_change_state_itself(manager: StateManager) -> None:
    def sneaky(old: AssistantState, new: AssistantState) -> None:
        if new is S.STANDBY:
            manager.handle(Event.WAKE_WORD_HEARD)

    manager.subscribe(sneaky)
    assert manager.handle(Event.INTERFACE_WAKE) is S.ERROR


def test_a_listener_calling_fail_still_ends_in_error(manager: StateManager) -> None:
    def calls_fail(old: AssistantState, new: AssistantState) -> None:
        if new is S.STANDBY:
            manager.fail()

    manager.subscribe(calls_fail)
    assert manager.handle(Event.INTERFACE_WAKE) is S.ERROR


@pytest.mark.parametrize("state", list(AssistantState))
def test_fail_works_from_every_state(manager: StateManager, state: AssistantState) -> None:
    _reach(manager, state)
    manager.fail()
    assert manager.state is S.ERROR


def test_error_can_be_left_by_the_interface(manager: StateManager) -> None:
    manager.fail()
    assert manager.handle(Event.INTERFACE_WAKE) is S.STANDBY


# --- The audit log -----------------------------------------------------------


def test_changes_are_recorded(audit: AuditLog, clock: FakeClock, tmp_path: Path) -> None:
    manager = StateManager(TIMEOUT, audit, clock=clock)
    manager.handle(Event.INTERFACE_WAKE)
    manager.handle(Event.WAKE_WORD_HEARD)
    manager.fail()
    path = tmp_path / "logs" / "audit.jsonl"
    data = [entry["data"] for entry in _entries(path)]
    assert data == [
        {"from_state": "sleeping", "to_state": "standby", "trigger": "interface_wake",
         "origin": "interface"},
        {"from_state": "standby", "to_state": "active", "trigger": "wake_word_heard",
         "origin": "voice"},
        {"from_state": "active", "to_state": "error", "trigger": "failure", "origin": "system"},
    ]  # fmt: skip
    assert all(entry["event"] == "state_changed" for entry in _entries(path))
    assert verify_audit_chain(path).ok


def test_fall_to_error_after_a_listener_fails_is_recorded(
    audit: AuditLog, clock: FakeClock, tmp_path: Path
) -> None:
    manager = StateManager(TIMEOUT, audit, clock=clock)

    def broken(old: AssistantState, new: AssistantState) -> None:
        raise RuntimeError

    manager.subscribe(broken)
    manager.handle(Event.INTERFACE_WAKE)
    states = [entry["data"]["to_state"] for entry in _entries(tmp_path / "logs" / "audit.jsonl")]  # type: ignore[index]
    assert states == ["standby", "error"]


@pytest.mark.parametrize(
    ("start", "event"),
    [
        (S.SLEEPING, Event.INTERFACE_WAKE),
        (S.SLEEPING, Event.INTERFACE_TALK),
        (S.STANDBY, Event.WAKE_WORD_HEARD),
        (S.ERROR, Event.INTERFACE_WAKE),
    ],
)
def test_opening_is_refused_when_it_cannot_be_recorded(
    audit: AuditLog, clock: FakeClock, start: AssistantState, event: Event
) -> None:
    manager = StateManager(TIMEOUT, audit, clock=clock)
    _reach(manager, start)
    heard: list[AssistantState] = []
    manager.subscribe(lambda old, new: heard.append(new))
    audit.close()
    with pytest.raises(StateTransitionError, match="could not be recorded"):
        manager.handle(event)
    assert manager.state is start
    assert heard == []


@pytest.mark.parametrize(
    ("start", "event", "expected"),
    [
        (S.ACTIVE, Event.IDLE_TIMEOUT, S.STANDBY),
        (S.ACTIVE, Event.VOICE_SLEEP, S.SLEEPING),
        (S.STANDBY, Event.INTERFACE_SLEEP, S.SLEEPING),
        (S.ACTIVE, Event.FAILURE, S.ERROR),
    ],
)
def test_closing_goes_ahead_when_it_cannot_be_recorded(
    audit: AuditLog,
    clock: FakeClock,
    caplog: pytest.LogCaptureFixture,
    start: AssistantState,
    event: Event,
    expected: AssistantState,
) -> None:
    manager = StateManager(TIMEOUT, audit, clock=clock)
    _reach(manager, start)
    audit.close()
    with caplog.at_level(logging.WARNING):
        assert manager.handle(event) is expected
    assert "could not be recorded" in caplog.text


def test_fail_goes_ahead_when_it_cannot_be_recorded(audit: AuditLog, clock: FakeClock) -> None:
    manager = StateManager(TIMEOUT, audit, clock=clock)
    _reach(manager, S.ACTIVE)
    audit.close()
    manager.fail()
    assert manager.state is S.ERROR
