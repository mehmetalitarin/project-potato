"""Tests for reading replies aloud (potato.voice.speaker)."""

import threading
from collections.abc import Callable

import pytest

from potato.core.state import AssistantState, Event, StateManager
from potato.core.turns import ToolOutcome, TurnResult, TurnStatus
from potato.voice.speaker import (
    MAX_SPEECH_SECONDS,
    SPEAKABLE_TOOLS,
    TEXT_ON_SCREEN,
    Speaker,
    what_to_say,
)


class FakeSpeech:
    def __init__(self, text: str, *, finishes: bool = True, stop_fails: bool = False) -> None:
        self.text = text
        self.finishes = finishes
        self.stop_fails = stop_fails
        self.stopped = 0
        self.waited: list[float] = []

    def wait(self, timeout: float) -> bool:
        self.waited.append(timeout)
        return self.finishes

    def stop(self) -> None:
        self.stopped += 1
        if self.stop_fails:
            raise OSError("cannot stop")


class Voice:
    """Starts fake speech and remembers it. Work is run only when asked."""

    def __init__(self, **options: bool) -> None:
        self.options = options
        self.started: list[FakeSpeech] = []
        self.pending: list[Callable[[], None]] = []
        self.on_start: Callable[[], None] | None = None

    def start(self, text: str) -> FakeSpeech | None:
        if self.on_start is not None:
            self.on_start()
        speech = FakeSpeech(text, **self.options)
        self.started.append(speech)
        return speech

    def run(self, work: Callable[[], None]) -> None:
        self.pending.append(work)

    def finish_all(self) -> None:
        while self.pending:
            self.pending.pop(0)()


def active() -> StateManager:
    state = StateManager(300.0)
    state.handle(Event.INTERFACE_TALK)
    assert state.state is AssistantState.ACTIVE
    return state


def answered(text: str, *tools: str | None) -> TurnResult:
    outcomes = tuple(ToolOutcome(tool, True, None, {}, None) for tool in tools)
    return TurnResult(TurnStatus.ANSWERED, text, outcomes)


# --- What is said ------------------------------------------------------------


def test_a_plain_answer_is_said() -> None:
    assert what_to_say(answered("Hello!")) == "Hello!"


@pytest.mark.parametrize(
    "tool",
    ["calendar_upcoming", "homework_deadlines", "portfolio_summary", "process_overview",
     "network_overview", "security_posture", "analyse_link", "portfolio_remove_holding",
     "something_new", None],
)  # fmt: skip
def test_private_or_detailed_answers_are_shown_not_spoken(tool: str | None) -> None:
    assert what_to_say(answered("You have a dentist at 3pm.", tool)) == TEXT_ON_SCREEN
    assert what_to_say(answered("Opened.", "open_app", tool)) == TEXT_ON_SCREEN


def test_only_listed_tools_may_be_read_out() -> None:
    assert frozenset({"open_app"}) == SPEAKABLE_TOOLS
    assert what_to_say(answered("Opening Safari.", "open_app")) == "Opening Safari."


def test_a_fixed_sentence_is_said_as_it_is() -> None:
    assert what_to_say(TurnResult(TurnStatus.OFFLINE, "The model is offline.")) == (
        "The model is offline."
    )


@pytest.mark.parametrize("odd", [None, "text", 5, object()])
def test_anything_but_a_result_says_nothing(odd: object) -> None:
    assert what_to_say(odd) == ""


# --- When it is said ---------------------------------------------------------


def test_it_speaks_while_active_and_reports_it() -> None:
    voice = Voice()
    speaker = Speaker(active(), voice.start, run=voice.run)
    told: list[bool] = []
    speaker.on_speaking(told.append)
    assert speaker.reply(answered("Hi"))
    assert [speech.text for speech in voice.started] == ["Hi"]
    seen = [speaker.speaking]
    voice.finish_all()
    seen.append(speaker.speaking)
    assert seen == [True, False]
    assert told == [True, False]
    assert voice.started[0].waited == [MAX_SPEECH_SECONDS]


@pytest.mark.parametrize(
    "events",
    [[], [Event.INTERFACE_WAKE], [Event.INTERFACE_WAKE, Event.FAILURE]],
    ids=["sleeping", "standby", "error"],
)
def test_it_never_speaks_unless_active(events: list[Event]) -> None:
    state = StateManager(300.0)
    for event in events:
        state.handle(event)
    voice = Voice()
    speaker = Speaker(state, voice.start, run=voice.run)
    assert not speaker.say("hello")
    assert voice.started == []


@pytest.mark.parametrize(
    "leave",
    [
        lambda state: state.handle(Event.INTERFACE_SLEEP),
        lambda state: state.handle(Event.VOICE_SLEEP),
        lambda state: state.handle(Event.IDLE_TIMEOUT),
        lambda state: state.fail(),
    ],
    ids=["sleep", "voice-sleep", "idle", "failure"],
)
def test_leaving_active_stops_the_speech_at_once(leave: Callable[[StateManager], None]) -> None:
    state = active()
    voice = Voice()
    speaker = Speaker(state, voice.start, run=voice.run)
    told: list[bool] = []
    speaker.on_speaking(told.append)
    speaker.say("a long story")
    leave(state)
    assert voice.started[0].stopped == 1
    assert not speaker.speaking
    assert told == [True, False]


def test_speech_that_cannot_be_stopped_moves_potato_to_error() -> None:
    state = active()
    voice = Voice(stop_fails=True)
    speaker = Speaker(state, voice.start, run=voice.run)
    speaker.say("hello")
    state.handle(Event.INTERFACE_SLEEP)
    assert state.state is AssistantState.ERROR


def test_falling_asleep_while_say_starts_stops_it() -> None:
    state = active()
    voice = Voice()

    def fall_asleep() -> None:
        state.handle(Event.INTERFACE_SLEEP)

    voice.on_start = fall_asleep
    speaker = Speaker(state, voice.start, run=voice.run)
    assert not speaker.say("hello")
    assert voice.started[0].stopped == 1
    assert not speaker.speaking
    assert voice.pending == []


def test_a_reply_that_runs_too_long_is_cut_off() -> None:
    voice = Voice(finishes=False)
    speaker = Speaker(active(), voice.start, run=voice.run, max_seconds=3.0)
    speaker.say("on and on")
    voice.finish_all()
    assert voice.started[0].waited == [3.0]
    assert voice.started[0].stopped == 1
    assert not speaker.speaking


def test_a_new_reply_stops_the_one_before() -> None:
    voice = Voice()
    speaker = Speaker(active(), voice.start, run=voice.run)
    told: list[bool] = []
    speaker.on_speaking(told.append)
    speaker.say("first")
    speaker.say("second")
    first, second = voice.started
    assert first.stopped == 1
    assert second.stopped == 0
    # The first one's watcher finishing late must not end the second.
    voice.pending.pop(0)()
    seen = [speaker.speaking]
    voice.finish_all()
    seen.append(speaker.speaking)
    assert seen == [True, False]
    assert told == [True, False, True, False]


def test_nothing_to_say_says_nothing() -> None:
    voice = Voice()
    speaker = Speaker(active(), voice.start, run=voice.run)
    assert not speaker.say("")
    assert not speaker.reply(None)
    assert voice.started == []


def test_say_that_cannot_start_is_not_speaking() -> None:
    speaker = Speaker(active(), lambda text: None)
    assert not speaker.say("hello")
    assert not speaker.speaking


def test_a_broken_listener_does_not_stop_anything() -> None:
    voice = Voice()
    speaker = Speaker(active(), voice.start, run=voice.run)

    def broken(speaking: bool) -> None:
        raise RuntimeError("no")

    told: list[bool] = []
    speaker.on_speaking(broken)
    speaker.on_speaking(told.append)
    speaker.say("hello")
    speaker.stop()
    assert told == [True, False]
    assert voice.started[0].stopped == 1


def test_by_default_the_watcher_runs_on_its_own_thread() -> None:
    names: list[str] = []
    done = threading.Event()

    class Speech(FakeSpeech):
        def wait(self, timeout: float) -> bool:
            names.append(threading.current_thread().name)
            done.set()
            return True

    speaker = Speaker(active(), lambda text: Speech(text))
    speaker.say("hello")
    assert done.wait(5)
    assert names == ["potato-speech"]
