"""Potato's mascot: a small, original potato drawn by code.

It is drawn entirely with QPainter from fixed shapes and colours. No image
files are loaded, and nothing a tool or the model wrote can change it. It has
two moods: happy, and sleepy while Potato is asleep.
"""

from enum import StrEnum
from typing import Final

from PySide6.QtCore import QPointF, QRectF, QSize, Qt
from PySide6.QtGui import (
    QColor,
    QIcon,
    QPainter,
    QPainterPath,
    QPaintEvent,
    QPen,
    QPixmap,
    QRadialGradient,
)
from PySide6.QtWidgets import QSizePolicy, QWidget

ICON_SIZES: Final = (16, 32, 64, 128, 256, 512)

SKIN_LIGHT: Final = QColor(240, 196, 132)
SKIN: Final = QColor(209, 150, 84)
SKIN_DARK: Final = QColor(160, 104, 52)
OUTLINE: Final = QColor(110, 68, 34)
SPOT: Final = QColor(150, 98, 50, 170)
LEAF: Final = QColor(112, 196, 78)
LEAF_DARK: Final = QColor(62, 138, 44)
FACE: Final = QColor(52, 34, 22)
CHEEK: Final = QColor(255, 122, 130, 120)


class Mood(StrEnum):
    """How the mascot looks."""

    HAPPY = "happy"
    SLEEPY = "sleepy"


def _body() -> QPainterPath:
    """A slightly lumpy potato, in a 100 by 100 box."""
    path = QPainterPath(QPointF(50, 16))
    path.cubicTo(QPointF(75, 13), QPointF(92, 30), QPointF(90, 53))
    path.cubicTo(QPointF(88, 77), QPointF(70, 91), QPointF(48, 89))
    path.cubicTo(QPointF(24, 87), QPointF(8, 72), QPointF(10, 51))
    path.cubicTo(QPointF(12, 29), QPointF(28, 18), QPointF(50, 16))
    path.closeSubpath()
    return path


def draw_potato(painter: QPainter, box: QRectF, mood: Mood = Mood.HAPPY) -> None:
    """Draw the mascot to fit inside ``box``, keeping its shape square."""
    side = min(box.width(), box.height())
    if side <= 0:
        return
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.translate(box.center().x() - side / 2, box.center().y() - side / 2)
    painter.scale(side / 100, side / 100)

    # A soft shadow underneath.
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(0, 0, 0, 55))
    painter.drawEllipse(QPointF(50, 93), 28, 3.5)

    # The sprout on top.
    stem = QPen(LEAF_DARK)
    stem.setWidthF(2.2)
    stem.setCapStyle(Qt.PenCapStyle.RoundCap)
    painter.setPen(stem)
    painter.drawLine(QPointF(50, 17), QPointF(51, 8))
    leaf_edge = QPen(LEAF_DARK)
    leaf_edge.setWidthF(1.2)
    painter.setPen(leaf_edge)
    painter.setBrush(LEAF)
    for leaf_x, leaf_y, angle in ((45, 7.5, -28.0), (57, 6.5, 24.0)):
        painter.save()
        painter.translate(leaf_x, leaf_y)
        painter.rotate(angle)
        painter.drawEllipse(QPointF(0, 0), 6, 3)
        painter.restore()

    # The body.
    skin = QRadialGradient(QPointF(40, 38), 58)
    skin.setColorAt(0.0, SKIN_LIGHT)
    skin.setColorAt(0.55, SKIN)
    skin.setColorAt(1.0, SKIN_DARK)
    outline = QPen(OUTLINE)
    outline.setWidthF(2.2)
    painter.setPen(outline)
    painter.setBrush(skin)
    painter.drawPath(_body())

    # The little dents every potato has.
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(SPOT)
    for spot_x, spot_y, size in (
        (74, 33, 2.4),
        (24, 68, 2.0),
        (69, 76, 1.7),
        (82, 60, 1.4),
        (30, 30, 1.3),
    ):
        painter.drawEllipse(QPointF(spot_x, spot_y), size, size * 0.8)

    # Rosy cheeks.
    painter.setBrush(CHEEK)
    painter.drawEllipse(QPointF(31, 59), 5.5, 3.2)
    painter.drawEllipse(QPointF(68, 59), 5.5, 3.2)

    # Eyes.
    face = QPen(FACE)
    face.setWidthF(2.0)
    face.setCapStyle(Qt.PenCapStyle.RoundCap)
    if mood is Mood.SLEEPY:
        painter.setPen(face)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        for x in (39.0, 60.0):
            painter.drawArc(QRectF(x - 4, 46, 8, 5), 180 * 16, 180 * 16)
    else:
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(FACE)
        for x in (39.0, 60.0):
            painter.drawEllipse(QPointF(x, 49), 3.2, 4.0)
        painter.setBrush(QColor(255, 255, 255))
        for x in (40.2, 61.2):
            painter.drawEllipse(QPointF(x, 47.4), 1.2, 1.2)

    # Mouth.
    painter.setPen(face)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    if mood is Mood.SLEEPY:
        painter.drawLine(QPointF(47, 60), QPointF(52, 60))
    else:
        painter.drawArc(QRectF(44.5, 53, 10, 8), 200 * 16, 140 * 16)
    painter.restore()


def potato_pixmap(size: int, mood: Mood = Mood.HAPPY) -> QPixmap:
    """The mascot on a transparent square ``size`` pixels wide."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    draw_potato(painter, QRectF(0, 0, size, size), mood)
    painter.end()
    return pixmap


def potato_icon() -> QIcon:
    """The application icon, drawn at every usual size."""
    icon = QIcon()
    for size in ICON_SIZES:
        icon.addPixmap(potato_pixmap(size))
    return icon


class Mascot(QWidget):
    """The mascot as a widget. Shows a mood; reads nothing on its own."""

    def __init__(self, side: int = 48, parent: QWidget | None = None) -> None:
        """Build a mascot ``side`` pixels square, happy."""
        super().__init__(parent)
        self._mood = Mood.HAPPY
        self._side = side
        self.setFixedSize(QSize(side, side))
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

    @property
    def mood(self) -> Mood:
        """The mood being shown."""
        return self._mood

    def set_mood(self, mood: object) -> None:
        """Show ``mood``. Anything that is not a ``Mood`` is ignored."""
        if isinstance(mood, Mood) and mood is not self._mood:
            self._mood = mood
            self.update()

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802 - Qt's name
        """Draw the mascot."""
        painter = QPainter(self)
        draw_potato(painter, QRectF(self.rect()), self._mood)
        painter.end()
