"""Tests for the orb and the floating bubble (potato.ui.orb)."""

import math
from collections.abc import Callable, Iterator

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QColor, QImage
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from potato.core.state import AssistantState, Event, StateManager
from potato.core.turns import TurnResult, TurnStatus
from potato.security.gate import RequestOrigin
from potato.ui.orb import (
    BLEND_MS,
    BLEND_UP_MS,
    FRAME_MS,
    LISTENING_LEVEL,
    LOOKS,
    SLOW_FRAME_MS,
    Drawn,
    Orb,
    OrbBubble,
    OrbMode,
    blend,
    drawn,
    mode_for,
)
from potato.ui.window import PotatoWindow


@pytest.fixture(scope="module")
def app() -> QApplication:
    existing = QApplication.instance()
    return existing if isinstance(existing, QApplication) else QApplication([])


def render(orb: Orb, size: int = 200) -> QImage:
    orb.resize(size, size)
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(QColor(0, 0, 0))
    orb.render(image)
    return image


def average_colour(image: QImage) -> tuple[float, float, float]:
    totals = [0.0, 0.0, 0.0]
    count = 0
    for y in range(0, image.height(), 4):
        for x in range(0, image.width(), 4):
            colour = image.pixelColor(x, y)
            totals[0] += colour.red()
            totals[1] += colour.green()
            totals[2] += colour.blue()
            count += 1
    return (totals[0] / count, totals[1] / count, totals[2] / count)


# --- What the orb shows ------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "busy", "speaking", "mode"),
    [
        (AssistantState.SLEEPING, False, False, OrbMode.SLEEPING),
        (AssistantState.STANDBY, False, False, OrbMode.STANDBY),
        (AssistantState.ACTIVE, False, False, OrbMode.LISTENING),
        (AssistantState.ACTIVE, True, False, OrbMode.THINKING),
        (AssistantState.ACTIVE, True, True, OrbMode.SPEAKING),
        (AssistantState.ERROR, False, False, OrbMode.ERROR),
    ],
)
def test_the_mode_follows_the_state(
    state: AssistantState, busy: bool, speaking: bool, mode: OrbMode
) -> None:
    assert mode_for(state, busy=busy, speaking=speaking) is mode


@pytest.mark.parametrize(
    "state", [AssistantState.SLEEPING, AssistantState.STANDBY, AssistantState.ERROR]
)
def test_the_orb_never_looks_busy_unless_potato_is_active(state: AssistantState) -> None:
    # The orb doubles as a microphone indicator, so the state always wins.
    assert mode_for(state, busy=True, speaking=True) is mode_for(state)


def test_every_mode_has_its_own_look() -> None:
    assert set(LOOKS) == set(OrbMode)
    colours = {LOOKS[mode].colour.name() for mode in OrbMode}
    assert len(colours) == len(OrbMode)


def test_every_mode_draws_something(app: QApplication) -> None:
    orb = Orb()
    for mode in OrbMode:
        orb.set_mode(mode)
        assert average_colour(render(orb)) != (0.0, 0.0, 0.0), mode


def test_error_is_red_and_sleeping_is_dim(app: QApplication) -> None:
    orb = Orb()
    orb.set_mode(OrbMode.ERROR)
    red, green, blue = average_colour(render(orb))
    assert red > green * 1.5
    assert red > blue * 1.5
    orb.set_mode(OrbMode.LISTENING)
    listening = sum(average_colour(render(orb)))
    orb.set_mode(OrbMode.SLEEPING)
    sleeping = sum(average_colour(render(orb)))
    assert sleeping < listening * 0.6


@pytest.mark.parametrize("bad", ["listening", None, 3, AssistantState.ACTIVE])
def test_anything_but_a_mode_is_ignored(bad: object) -> None:
    orb = Orb()
    orb.set_mode(OrbMode.STANDBY)
    orb.set_mode(bad)
    assert orb.mode is OrbMode.STANDBY


@pytest.mark.parametrize(
    ("level", "kept"),
    [(0.5, 0.5), (2.0, 1.0), (-1.0, 0.0), (1, 1.0), (math.nan, None), (math.inf, None),
     (True, None), ("0.5", None), (None, None)],
)  # fmt: skip
def test_the_voice_level_is_kept_between_zero_and_one(level: object, kept: float | None) -> None:
    orb = Orb()
    orb.set_level(0.25)
    orb.set_level(level)
    assert orb._level == (0.25 if kept is None else kept)


# --- Animation ---------------------------------------------------------------


def test_it_animates_only_while_it_can_be_seen(app: QApplication) -> None:
    orb = Orb()
    orb.set_mode(OrbMode.LISTENING)
    seen = []
    seen.append(orb.animating)
    orb.show()
    seen.append(orb.animating)
    assert orb._timer.interval() == FRAME_MS
    orb.hide()
    seen.append(orb.animating)
    assert seen == [False, True, False]


def test_sleeping_animates_slowly(app: QApplication) -> None:
    orb = Orb()
    orb.show()
    orb.set_mode(OrbMode.SLEEPING)
    assert orb._timer.interval() == SLOW_FRAME_MS
    orb.set_mode(OrbMode.THINKING)
    assert orb._timer.interval() == FRAME_MS
    orb.hide()


def test_frames_advance_time_and_settle_the_level(app: QApplication) -> None:
    orb = Orb()
    orb.show()
    orb.set_mode(OrbMode.LISTENING)
    orb.set_level(1.0)
    orb._tick()
    assert orb._time > 0
    assert orb._level < 1.0
    orb.hide()


def test_a_click_is_reported(app: QApplication) -> None:
    orb = Orb()
    orb.resize(100, 100)
    orb.show()
    clicks: list[bool] = []
    orb.clicked.connect(lambda: clicks.append(True))
    QTest.mouseClick(orb, Qt.MouseButton.LeftButton, pos=QPoint(50, 50))
    QTest.mouseClick(orb, Qt.MouseButton.RightButton, pos=QPoint(50, 50))
    assert clicks == [True]
    orb.hide()


# --- The floating bubble -----------------------------------------------------


def test_the_bubble_floats_above_other_windows(app: QApplication) -> None:
    bubble = OrbBubble(lambda: None)
    flags = bubble.windowFlags()
    assert flags & Qt.WindowType.WindowStaysOnTopHint
    assert flags & Qt.WindowType.FramelessWindowHint
    assert flags & Qt.WindowType.Tool
    assert bubble.testAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)


def test_clicking_the_bubble_calls_back_and_dragging_does_not(app: QApplication) -> None:
    calls: list[bool] = []
    bubble = OrbBubble(lambda: calls.append(True))
    bubble.show()
    QTest.mouseClick(bubble, Qt.MouseButton.LeftButton, pos=QPoint(60, 60))
    assert calls == [True]
    QTest.mousePress(bubble, Qt.MouseButton.LeftButton, pos=QPoint(60, 60))
    QTest.mouseMove(bubble, QPoint(90, 90))
    QTest.mouseRelease(bubble, Qt.MouseButton.LeftButton, pos=QPoint(90, 90))
    assert calls == [True]
    bubble.close()


# --- In the window -----------------------------------------------------------


class Slow:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, words: str, origin: RequestOrigin) -> TurnResult:
        self.calls += 1
        return TurnResult(TurnStatus.ANSWERED, "ok")


@pytest.fixture
def window(
    app: QApplication,
) -> Iterator[tuple[PotatoWindow, StateManager, list[Callable[[], None]]]]:
    state = StateManager(300.0)
    pending: list[Callable[[], None]] = []
    made = PotatoWindow(Slow(), state, start=pending.append)
    yield made, state, pending
    made.close()


def mode_of(orb: Orb) -> OrbMode:
    """Read the mode through a call, so the type checker does not assume it is fixed."""
    return orb.mode


def test_the_window_orb_follows_state_and_work(
    app: QApplication, window: tuple[PotatoWindow, StateManager, list[Callable[[], None]]]
) -> None:
    made, state, pending = window
    assert mode_of(made.orb) is OrbMode.SLEEPING
    made.wake_button.click()
    assert mode_of(made.orb) is OrbMode.STANDBY
    made.entry.setText("hi")
    made.send()
    assert mode_of(made.orb) is OrbMode.THINKING
    pending.pop()()
    app.processEvents()
    assert mode_of(made.orb) is OrbMode.LISTENING
    state.handle(Event.FAILURE)
    app.processEvents()
    assert mode_of(made.orb) is OrbMode.ERROR
    assert mode_of(made.bubble.orb) is OrbMode.ERROR


def test_mini_shrinks_to_the_bubble_and_a_click_brings_it_back(
    app: QApplication, window: tuple[PotatoWindow, StateManager, list[Callable[[], None]]]
) -> None:
    made, _, _ = window
    made.show()
    made.mini_button.click()
    assert not made.isVisible()
    assert made.bubble.isVisible()
    assert made.bubble.orb.mode is made.orb.mode
    made.show_from_bubble()
    assert made.isVisible()
    assert not made.bubble.isVisible()


def test_closing_the_window_closes_the_bubble(
    app: QApplication, window: tuple[PotatoWindow, StateManager, list[Callable[[], None]]]
) -> None:
    made, _, _ = window
    made.show_bubble()
    made.close()
    assert not made.bubble.isVisible()


# --- Smooth changes ----------------------------------------------------------


def same(first: Drawn, second: Drawn) -> bool:
    return (
        first.colour.rgb() == second.colour.rgb()
        and first.accent.rgb() == second.accent.rgb()
        and math.isclose(first.speed, second.speed)
        and math.isclose(first.brightness, second.brightness)
        and math.isclose(first.sweep, second.sweep)
        and math.isclose(first.ripple, second.ripple)
    )


def ticks_to_finish(orb: Orb) -> int:
    count = 0
    while orb.blending:
        orb._tick()
        count += 1
        assert count < 1000
    return count


def test_blend_goes_from_start_to_end() -> None:
    start, end = drawn(OrbMode.SLEEPING), drawn(OrbMode.THINKING)
    assert same(blend(start, end, 0.0), start)
    assert same(blend(start, end, 1.0), end)
    middle = blend(start, end, 0.5)
    assert start.speed < middle.speed < end.speed
    assert 0.0 < middle.sweep < 1.0
    for odd in (-3.0, 7.0, math.nan, math.inf):
        result = blend(start, end, odd)
        assert same(result, start) or same(result, end)
    assert same(blend(start, end, math.nan), end)


def test_the_mode_changes_at_once_and_the_drawing_catches_up(app: QApplication) -> None:
    orb = Orb()
    orb.show()
    orb.set_mode(OrbMode.LISTENING)
    ticks_to_finish(orb)
    orb.set_mode(OrbMode.THINKING)
    assert orb.mode is OrbMode.THINKING
    assert orb.blending
    assert not same(orb.current, drawn(OrbMode.THINKING))
    orb._tick()
    part_way = orb.current.speed
    assert LOOKS[OrbMode.LISTENING].speed < part_way < LOOKS[OrbMode.THINKING].speed
    ticks_to_finish(orb)
    assert same(orb.current, drawn(OrbMode.THINKING))
    orb.hide()


def test_going_quieter_takes_about_half_a_second(app: QApplication) -> None:
    orb = Orb()
    orb.show()
    orb.set_mode(OrbMode.THINKING)
    ticks_to_finish(orb)
    orb.set_mode(OrbMode.STANDBY)
    assert ticks_to_finish(orb) == math.ceil(BLEND_MS / FRAME_MS)
    orb.hide()


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (OrbMode.SLEEPING, OrbMode.STANDBY),
        (OrbMode.SLEEPING, OrbMode.LISTENING),
        (OrbMode.ERROR, OrbMode.LISTENING),
        (OrbMode.STANDBY, OrbMode.LISTENING),
    ],
)
def test_waking_up_shows_almost_at_once(app: QApplication, before: OrbMode, after: OrbMode) -> None:
    # The orb must never look asleep while Potato could be listening.
    assert LISTENING_LEVEL[after] > LISTENING_LEVEL[before]
    orb = Orb()
    orb.show()
    orb.set_mode(before)
    ticks_to_finish(orb)
    orb.set_mode(after)
    assert orb._timer.interval() == FRAME_MS
    assert ticks_to_finish(orb) == math.ceil(BLEND_UP_MS / FRAME_MS)
    assert BLEND_UP_MS <= 150
    orb.hide()


def test_every_mode_has_a_listening_level() -> None:
    assert set(LISTENING_LEVEL) == set(OrbMode)
    assert LISTENING_LEVEL[OrbMode.SLEEPING] == LISTENING_LEVEL[OrbMode.ERROR] == 0


def test_a_hidden_orb_does_not_blend(app: QApplication) -> None:
    orb = Orb()
    orb.set_mode(OrbMode.SPEAKING)
    seen = [orb.blending]
    assert same(orb.current, drawn(OrbMode.SPEAKING))
    orb.show()
    orb.set_mode(OrbMode.SLEEPING)
    seen.append(orb.blending)
    orb.hide()
    seen.append(orb.blending)
    assert seen == [False, True, False]


def test_it_slows_down_only_once_the_blend_into_sleep_is_done(app: QApplication) -> None:
    orb = Orb()
    orb.show()
    orb.set_mode(OrbMode.LISTENING)
    ticks_to_finish(orb)
    orb.set_mode(OrbMode.SLEEPING)
    assert orb._timer.interval() == FRAME_MS
    ticks_to_finish(orb)
    assert orb._timer.interval() == SLOW_FRAME_MS
    orb.hide()


def test_a_change_of_speed_never_makes_the_picture_jump(app: QApplication) -> None:
    orb = Orb()
    orb.show()
    orb.set_mode(OrbMode.LISTENING)
    for _ in range(30):
        orb._tick()
    before = orb._phase
    orb.set_mode(OrbMode.THINKING)
    assert orb._phase == before
    orb._tick()
    assert 0 < orb._phase - before < 0.2
    orb.hide()


def test_the_same_mode_again_does_not_restart_the_blend(app: QApplication) -> None:
    orb = Orb()
    orb.show()
    orb.set_mode(OrbMode.LISTENING)
    ticks_to_finish(orb)
    orb.set_mode(OrbMode.LISTENING)
    assert not orb.blending
    orb.hide()
