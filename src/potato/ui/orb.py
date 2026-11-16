"""The orb: an animated picture of what Potato is doing.

It is drawn by code from Potato's state alone, never from anything the model
wrote, so it can be trusted as an indicator. In particular, it shows at a
glance whether Potato could be listening:

- **Sleeping**: dim and almost still. Nothing is listening.
- **Standby**: a slow teal pulse. Only the wake word is being listened for.
- **Listening**: bright cyan. Potato is active and ready.
- **Thinking**: violet, spinning fast, with a scanning sweep.
- **Speaking**: green, rippling.
- **Error**: red. Everything was closed.

The orb is in the main window, and can also float on its own above other
applications (``OrbBubble``). It animates only while it can be seen.
"""

import math
import random
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QHideEvent,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPen,
    QRadialGradient,
    QShowEvent,
)
from PySide6.QtWidgets import QWidget

from potato.core.state import AssistantState

FRAME_MS: Final = 33
SLOW_FRAME_MS: Final = 100
PARTICLES: Final = 56
TICKS: Final = 72


class OrbMode(StrEnum):
    """What the orb shows."""

    SLEEPING = "sleeping"
    STANDBY = "standby"
    LISTENING = "listening"
    THINKING = "thinking"
    SPEAKING = "speaking"
    ERROR = "error"


def mode_for(state: AssistantState, *, busy: bool = False, speaking: bool = False) -> OrbMode:
    """Work out what the orb shows. The state always wins over activity.

    Thinking and speaking are shown only while Potato is active, so the orb
    can never look busy while the microphone is meant to be off.
    """
    if state is AssistantState.ERROR:
        return OrbMode.ERROR
    if state is AssistantState.SLEEPING:
        return OrbMode.SLEEPING
    if state is AssistantState.STANDBY:
        return OrbMode.STANDBY
    if speaking:
        return OrbMode.SPEAKING
    if busy:
        return OrbMode.THINKING
    return OrbMode.LISTENING


@dataclass(frozen=True, slots=True)
class Look:
    """How one mode looks."""

    colour: QColor
    accent: QColor
    speed: float
    brightness: float
    sweep: bool = False


LOOKS: Final[dict[OrbMode, Look]] = {
    OrbMode.SLEEPING: Look(QColor(90, 110, 140), QColor(60, 70, 90), 0.15, 0.35),
    OrbMode.STANDBY: Look(QColor(40, 190, 170), QColor(30, 120, 140), 0.45, 0.65),
    OrbMode.LISTENING: Look(QColor(60, 210, 255), QColor(120, 140, 255), 1.0, 1.0),
    OrbMode.THINKING: Look(QColor(160, 110, 255), QColor(255, 170, 80), 2.6, 1.0, sweep=True),
    OrbMode.SPEAKING: Look(QColor(70, 230, 150), QColor(60, 200, 255), 1.4, 1.0),
    OrbMode.ERROR: Look(QColor(240, 70, 70), QColor(150, 30, 30), 0.6, 0.9),
}


@dataclass(slots=True)
class _Particle:
    radius: float
    angle: float
    speed: float
    size: float
    wobble: float


Clock = Callable[[], float]


class Orb(QWidget):
    """The animated orb. Shows a mode; reads nothing on its own."""

    clicked = Signal()

    def __init__(self, parent: QWidget | None = None, *, seed: int = 7) -> None:
        """Build the orb, sleeping. ``seed`` fixes the particles, for tests."""
        super().__init__(parent)
        self._mode = OrbMode.SLEEPING
        self._level = 0.0
        self._time = 0.0
        randomness = random.Random(seed)  # noqa: S311 - decoration, not security
        self._particles = [
            _Particle(
                radius=randomness.uniform(0.55, 0.98),
                angle=randomness.uniform(0, math.tau),
                speed=randomness.uniform(0.2, 1.0) * randomness.choice((-1, 1)),
                size=randomness.uniform(0.8, 2.4),
                wobble=randomness.uniform(0, math.tau),
            )
            for _ in range(PARTICLES)
        ]
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.setMinimumSize(96, 96)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

    # --- What it shows ------------------------------------------------------

    @property
    def mode(self) -> OrbMode:
        """The mode being shown."""
        return self._mode

    def set_mode(self, mode: object) -> None:
        """Show ``mode``. Anything that is not an ``OrbMode`` is ignored."""
        if not isinstance(mode, OrbMode):
            return
        self._mode = mode
        self._restart_timer()
        self.update()

    def set_level(self, level: object) -> None:
        """How loud the voice is, from 0 to 1. Makes the orb ripple."""
        if isinstance(level, int | float) and not isinstance(level, bool) and math.isfinite(level):
            self._level = min(1.0, max(0.0, float(level)))

    @property
    def animating(self) -> bool:
        """Whether the animation timer is running."""
        return self._timer.isActive()

    # --- Animation ----------------------------------------------------------

    def _restart_timer(self) -> None:
        if not self.isVisible():
            self._timer.stop()
            return
        slow = self._mode in (OrbMode.SLEEPING, OrbMode.ERROR)
        self._timer.start(SLOW_FRAME_MS if slow else FRAME_MS)

    def _tick(self) -> None:
        self._time += self._timer.interval() / 1000.0
        self._level *= 0.85
        self.update()

    def showEvent(self, event: QShowEvent) -> None:  # noqa: N802 - Qt's name
        """Start animating when it can be seen."""
        super().showEvent(event)
        self._restart_timer()

    def hideEvent(self, event: QHideEvent) -> None:  # noqa: N802 - Qt's name
        """Stop animating when it cannot be seen."""
        super().hideEvent(event)
        self._timer.stop()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt's name
        """Report a click."""
        super().mouseReleaseEvent(event)
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()

    # --- Drawing ------------------------------------------------------------

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802 - Qt's name
        """Draw the layers: glow, ticks, rings, arcs, particles, core, sweep."""
        look = LOOKS[self._mode]
        side = min(self.width(), self.height())
        radius = side / 2 - 4
        centre = QPointF(self.width() / 2, self.height() / 2)
        t = self._time * look.speed
        breath = 0.5 + 0.5 * math.sin(self._time * (1.2 + look.speed))
        level = self._level if self._mode in (OrbMode.LISTENING, OrbMode.SPEAKING) else 0.0

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.translate(centre)

        def colour(base: QColor, alpha: float) -> QColor:
            shade = QColor(base)
            shade.setAlphaF(max(0.0, min(1.0, alpha * look.brightness)))
            return shade

        # Outer glow.
        glow = QRadialGradient(QPointF(0, 0), radius)
        glow.setColorAt(0.0, colour(look.colour, 0.30 + 0.25 * breath))
        glow.setColorAt(0.55, colour(look.accent, 0.10))
        glow.setColorAt(1.0, colour(look.colour, 0.0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(QPointF(0, 0), radius, radius)

        # Tick marks, like a dial.
        painter.save()
        painter.rotate(math.degrees(t * 0.15))
        for index in range(TICKS):
            long_tick = index % 6 == 0
            pen = QPen(colour(look.colour, 0.55 if long_tick else 0.25))
            pen.setWidthF(1.4 if long_tick else 0.8)
            painter.setPen(pen)
            inner = radius * (0.88 if long_tick else 0.92)
            painter.drawLine(QPointF(inner, 0), QPointF(radius * 0.96, 0))
            painter.rotate(360.0 / TICKS)
        painter.restore()

        # Dashed rings turning at different speeds and in different directions.
        for scale, dash, speed, width in (
            (0.80, [6.0, 4.0], 0.6, 1.6),
            (0.68, [2.0, 6.0], -1.1, 1.2),
            (0.56, [14.0, 3.0, 2.0, 3.0], 0.9, 1.0),
        ):
            painter.save()
            painter.rotate(math.degrees(t * speed))
            pen = QPen(colour(look.accent if scale < 0.6 else look.colour, 0.75))
            pen.setWidthF(width)
            pen.setDashPattern(dash)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            ring = radius * scale * (1.0 + 0.06 * level)
            painter.drawEllipse(QPointF(0, 0), ring, ring)
            painter.restore()

        # Arc segments sweeping around the outside.
        painter.save()
        arc_radius = radius * 0.74
        box = QRectF(-arc_radius, -arc_radius, arc_radius * 2, arc_radius * 2)
        for index, span in enumerate((48, 22, 70, 14, 36, 28)):
            pen = QPen(colour(look.colour if index % 2 else look.accent, 0.9))
            pen.setWidthF(3.0 if index % 3 == 0 else 1.8)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            start = math.degrees(t * (0.8 + 0.25 * index)) + index * 60
            painter.drawArc(box, int(start * 16), int(span * 16))
        painter.restore()

        # Particles drifting in orbit.
        painter.setPen(Qt.PenStyle.NoPen)
        for particle in self._particles:
            angle = particle.angle + t * particle.speed
            wobble = 1.0 + 0.04 * math.sin(self._time * 2 + particle.wobble) + 0.12 * level
            distance = radius * particle.radius * wobble
            painter.setBrush(colour(look.colour, 0.35 + 0.5 * abs(math.sin(angle * 3))))
            point = QPointF(math.cos(angle) * distance, math.sin(angle) * distance)
            painter.drawEllipse(point, particle.size, particle.size)

        # Speaking: ripples moving outwards.
        if self._mode is OrbMode.SPEAKING:
            painter.setBrush(Qt.BrushStyle.NoBrush)
            for index in range(3):
                phase = (self._time * 0.8 + index / 3) % 1.0
                pen = QPen(colour(look.colour, 0.6 * (1 - phase)))
                pen.setWidthF(1.5)
                painter.setPen(pen)
                ripple = radius * (0.35 + 0.55 * phase)
                painter.drawEllipse(QPointF(0, 0), ripple, ripple)

        # Thinking: a sweep, like radar.
        if look.sweep:
            painter.save()
            painter.rotate(math.degrees(self._time * 4.0))
            pen = QPen(colour(look.accent, 0.8))
            pen.setWidthF(2.0)
            painter.setPen(pen)
            painter.drawLine(QPointF(radius * 0.2, 0), QPointF(radius * 0.86, 0))
            painter.restore()

        # The core.
        core_radius = radius * (0.26 + 0.04 * breath + 0.10 * level)
        core = QRadialGradient(QPointF(0, 0), core_radius)
        core.setColorAt(0.0, colour(QColor(255, 255, 255), 0.95))
        core.setColorAt(0.35, colour(look.colour, 0.95))
        core.setColorAt(1.0, colour(look.accent, 0.0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(core)
        painter.drawEllipse(QPointF(0, 0), core_radius, core_radius)
        painter.end()


class OrbBubble(QWidget):
    """The orb on its own, floating above other applications, like Siri.

    Click it to bring back the main window. Drag it to move it.
    """

    def __init__(self, on_click: Callable[[], None]) -> None:
        """Build the bubble, hidden. ``on_click`` brings back the main window."""
        super().__init__(
            None,
            Qt.WindowType.Tool
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint,
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setWindowTitle("Potato")
        self.orb = Orb(self)
        self.orb.setGeometry(0, 0, 120, 120)
        self.resize(120, 120)
        self._on_click = on_click
        self._press: QPointF | None = None
        self._moved = False

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt's name
        """Start a drag or a click."""
        if event.button() == Qt.MouseButton.LeftButton:
            self._press = event.globalPosition() - QPointF(self.pos())
            self._moved = False

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt's name
        """Move the bubble with the mouse."""
        if self._press is not None:
            self._moved = True
            self.move((event.globalPosition() - self._press).toPoint())

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt's name
        """A click without a drag brings back the main window."""
        if event.button() == Qt.MouseButton.LeftButton and self._press is not None:
            self._press = None
            if not self._moved:
                self._on_click()
