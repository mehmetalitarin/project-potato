"""Tests for the potato mascot (potato.ui.mascot)."""

import ast
from pathlib import Path

import pytest
from PySide6.QtCore import QRectF, QSize
from PySide6.QtGui import QColor, QImage, QPainter
from PySide6.QtWidgets import QApplication

import potato.ui.mascot as mascot_module
from potato.core.state import AssistantState, Event, StateManager
from potato.core.turns import TurnResult, TurnStatus
from potato.security.gate import RequestOrigin
from potato.ui.mascot import (
    ICON_SIZES,
    Mascot,
    Mood,
    draw_potato,
    potato_icon,
    potato_pixmap,
)
from potato.ui.window import TEXT_EMPTY_CHAT, PotatoWindow


@pytest.fixture(scope="module")
def app() -> QApplication:
    existing = QApplication.instance()
    return existing if isinstance(existing, QApplication) else QApplication([])


def painted(image: QImage) -> list[QColor]:
    return [
        image.pixelColor(x, y)
        for y in range(image.height())
        for x in range(image.width())
        if image.pixelColor(x, y).alpha() > 0
    ]


# --- Drawing -----------------------------------------------------------------


@pytest.mark.parametrize("size", ICON_SIZES)
def test_it_draws_a_potato_coloured_shape_at_every_size(app: QApplication, size: int) -> None:
    pixels = painted(potato_pixmap(size).toImage())
    assert len(pixels) > size * size * 0.3
    red = sum(colour.red() for colour in pixels) / len(pixels)
    blue = sum(colour.blue() for colour in pixels) / len(pixels)
    assert red > blue * 1.3  # Brown, not blue.


def test_the_moods_look_different(app: QApplication) -> None:
    happy = potato_pixmap(128, Mood.HAPPY).toImage()
    sleepy = potato_pixmap(128, Mood.SLEEPY).toImage()
    assert happy != sleepy


def test_the_corners_stay_transparent(app: QApplication) -> None:
    image = potato_pixmap(64).toImage()
    for x, y in ((0, 0), (63, 0), (0, 63), (63, 63)):
        assert image.pixelColor(x, y).alpha() == 0


@pytest.mark.parametrize("box", [QRectF(0, 0, 0, 0), QRectF(0, 0, -5, 10), QRectF(0, 0, 10, 0)])
def test_an_empty_box_draws_nothing(app: QApplication, box: QRectF) -> None:
    image = QImage(16, 16, QImage.Format.Format_ARGB32)
    image.fill(QColor(0, 0, 0, 0))
    painter = QPainter(image)
    draw_potato(painter, box)
    painter.end()
    assert painted(image) == []


def test_the_icon_has_every_size(app: QApplication) -> None:
    sizes = potato_icon().availableSizes()
    assert sorted(size.width() for size in sizes) == sorted(ICON_SIZES)


def test_it_is_drawn_by_code_and_reads_no_files() -> None:
    source = Path(mascot_module.__file__).read_text(encoding="utf-8")
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name)
    assert not names & {"open", "load", "QImageReader", "QSvgRenderer", "fromData", "Path"}
    assert ".png" not in source
    assert ".svg" not in source


# --- The widget --------------------------------------------------------------


def test_the_widget_keeps_its_size_and_ignores_odd_moods(app: QApplication) -> None:
    mascot = Mascot(40)
    assert mascot.size() == QSize(40, 40)
    seen = [mascot.mood]
    for odd in ("sleepy", None, 1, AssistantState.SLEEPING):
        mascot.set_mood(odd)
        seen.append(mascot.mood)
    mascot.set_mood(Mood.SLEEPY)
    seen.append(mascot.mood)
    assert seen == [Mood.HAPPY] * 5 + [Mood.SLEEPY]


def test_the_widget_paints(app: QApplication) -> None:
    mascot = Mascot(64)
    image = QImage(64, 64, QImage.Format.Format_ARGB32)
    image.fill(QColor(0, 0, 0, 0))
    mascot.render(image)
    assert len(painted(image)) > 64 * 64 * 0.3


# --- In the window -----------------------------------------------------------


class Quiet:
    def run(self, words: str, origin: RequestOrigin) -> TurnResult:
        return TurnResult(TurnStatus.ANSWERED, "ok")


def test_the_window_mascot_sleeps_when_potato_sleeps(app: QApplication) -> None:
    state = StateManager(300.0)
    window = PotatoWindow(Quiet(), state)
    try:
        assert state.state is AssistantState.SLEEPING
        moods = [(window.mascot.mood, window.empty_mascot.mood)]
        state.handle(Event.INTERFACE_WAKE)
        app.processEvents()
        moods.append((window.mascot.mood, window.empty_mascot.mood))
        assert moods == [(Mood.SLEEPY, Mood.SLEEPY), (Mood.HAPPY, Mood.HAPPY)]
    finally:
        window.close()


def test_the_empty_chat_shows_the_mascot_until_the_first_message(app: QApplication) -> None:
    window = PotatoWindow(Quiet(), StateManager(300.0), start=lambda work: work())
    try:
        assert window.chat.currentWidget() is window.empty_chat
        assert TEXT_EMPTY_CHAT in [
            label.text() for label in window.findChildren(type(window.status))
        ]
        window.entry.setText("hello")
        window.send()
        app.processEvents()
        assert window.chat.currentWidget() is window.transcript
        assert "hello" in window.transcript.toPlainText()
    finally:
        window.close()
