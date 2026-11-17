"""The security dashboard: this Mac's protections, programs and network at a glance.

It shows what four tools report: the security posture, the process and
network overviews and, on request, the update check. How it stays safe:

- **Through the gate.** The dashboard runs the tools through the same gate as
  everything else, as ``RequestOrigin.INTERFACE``, so every run is checked,
  rate-limited and recorded in the audit log. It holds no tool of its own.
- **Read-only.** Every tool it can run only reads.
- **The model is not involved.** The tools' own data is shown, laid out by
  code here. Nothing goes through the model, so nothing can be distorted by
  it (T-LLM-4).
- **Plain text only.** Labels and table cells show plain text. Program and
  update names are the only text that did not come from Potato's code, and
  they go through ``displayable``. The style sheet is fixed text: nothing
  from a tool ever becomes part of it.
- **One refresh at a time, off the main thread.** While the dashboard is
  open it refreshes itself every 30 seconds, well inside the gate's limits.
  The update check, which contacts Apple, runs only when its button is
  pressed.
- **Everything, on request.** The dashboard asks the tools for every entry
  (up to their limits) and shows the busiest; "Show all" lists the rest.
  Such a long answer never reaches the model: anything longer than the model
  may read is replaced by a fixed note (``core/turns.py``).
"""

import math
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from PySide6.QtCore import QModelIndex, QObject, QPersistentModelIndex, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontDatabase,
    QHideEvent,
    QPainter,
    QPaintEvent,
    QShowEvent,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from potato.security.gate import MESSAGES, GateResult, RequestOrigin
from potato.ui.text import displayable

TITLE: Final = "Potato: security dashboard"
REFRESH_TOOLS: Final = ("security_posture", "process_overview", "network_overview")
UPDATE_TOOL: Final = "check_security_updates"
# The dashboard asks for every entry; the tables show the busiest, "Show all"
# the rest. These are the tools' own maximums; a test checks they match.
PROCESS_LIMIT: Final = 1000
NETWORK_LIMIT: Final = 500
ARGUMENTS: Final[Mapping[str, Mapping[str, int]]] = {
    "process_overview": {"limit": PROCESS_LIMIT},
    "network_overview": {"limit": NETWORK_LIMIT},
}
EXPANDABLE: Final = frozenset({"process_overview", "network_overview"})
SHORT_ROWS: Final = 8
AUTO_REFRESH_MS: Final = 30_000
PULSE_MS: Final = 40

TEXT_NOT_LOADED: Final = "Not checked yet."
TEXT_LOADING: Final = "Checking..."
TEXT_UPDATES_LOADING: Final = "Asking Apple's update tool. This can take a minute..."
TEXT_UPDATES_NOT_LOADED: Final = "Press Check for updates. This asks Apple and can take a minute."
TEXT_FAILED: Final = "This could not be checked just now."
TEXT_SHOW_ALL: Final = "Show all"
TEXT_SHOW_LESS: Final = "Show less"
TEXT_NEVER: Final = "Not refreshed yet"
TEXT_SEARCH: Final = "Filter by name"
TEXT_PARTIAL: Final = "Only your own programs are visible; system services are hidden by macOS."

PILLS: Final = {
    "on": ("ON", "pill_on"),
    "off": ("OFF", "pill_off"),
    "unknown": ("?", "pill_unknown"),
}
CHECK_NAMES: Final = {
    "disk_encryption": "Disk encryption (FileVault)",
    "firewall": "Firewall",
    "gatekeeper": "Gatekeeper",
    "system_integrity_protection": "System Integrity Protection",
}
PLACE_NAMES: Final = {
    "this_mac": "this Mac",
    "local_network": "local network",
    "internet": "internet",
}
OWNER_NAMES: Final = {"you": "you", "system": "system", "another_user": "other user"}

# Fixed text: nothing from a tool ever becomes part of it.
STYLE: Final = """
QDialog { background: #12141a; }
QScrollArea, QScrollArea > QWidget > QWidget { background: #12141a; border: none; }
QLabel { color: #e6e8ee; }
QLabel#title { font-size: 22px; font-weight: 600; }
QLabel#subtitle, QLabel#caption, QLabel#note { color: #8b90a0; }
QLabel#note { font-size: 11px; }
QLabel#summary { color: #c7cbd6; }
QLabel#metric { font-size: 26px; font-weight: 600; color: #ffffff; }
QLabel#metric_warn { font-size: 26px; font-weight: 600; color: #ff9b6b; }
QLabel#card_title { font-size: 15px; font-weight: 600; }
QFrame#card { background: #1b1e27; border: 1px solid #2a2e3a; border-radius: 12px; }
QFrame#tile { background: #222633; border-radius: 10px; }
QLabel#pill_on, QLabel#pill_off, QLabel#pill_unknown {
    border-radius: 9px; padding: 2px 10px; font-weight: 700; font-size: 11px;
}
QLabel#pill_on { background: #12351f; color: #5be38c; }
QLabel#pill_off { background: #3d1518; color: #ff6b6b; }
QLabel#pill_unknown { background: #3a2f10; color: #f2c14e; }
QPushButton {
    background: #2a2f3d; color: #e6e8ee; border: 1px solid #353b4b;
    border-radius: 8px; padding: 6px 14px;
}
QPushButton:hover { background: #343a4b; }
QPushButton:disabled { color: #5c6170; }
QPushButton#primary { background: #2d5bd7; border-color: #3a6af0; }
QLineEdit {
    background: #12141a; color: #e6e8ee; border: 1px solid #2a2e3a;
    border-radius: 8px; padding: 5px 8px;
}
QTableWidget {
    background: #1b1e27; color: #e6e8ee; border: none;
    gridline-color: #262a35; selection-background-color: #2d3a5c;
}
QTableWidget::item { padding: 0px 8px; }
QHeaderView::section {
    background: #1b1e27; color: #8b90a0; border: none;
    border-bottom: 1px solid #2a2e3a; padding: 4px 6px; font-weight: 600;
}
"""


class ToolGate(Protocol):
    """The part of the gate the dashboard needs."""

    def submit(
        self, proposal: object, origin: RequestOrigin, approval: object = None
    ) -> GateResult:
        """Check a proposal and, if every check passes, run the tool."""
        ...


# --- Reading tool data: odd data never raises and never shows -----------------


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _number(value: object) -> int:
    return value if type(value) is int else 0


def _decimal(value: object) -> float:
    if isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value):
        return float(value)
    return 0.0


def _items(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _name(value: object, limit: int = 40) -> str:
    return displayable(_text(value), limit) or "(no name)"


@dataclass(frozen=True, slots=True)
class PostureRow:
    """One protection: its name and whether it is on."""

    name: str
    state: str


@dataclass(frozen=True, slots=True)
class ProgramRow:
    """One running program."""

    name: str
    processor: float
    memory_megabytes: int
    owner: str


@dataclass(frozen=True, slots=True)
class ListeningRow:
    """One program accepting connections on a port."""

    name: str
    port: int
    reach: str


@dataclass(frozen=True, slots=True)
class ConnectedRow:
    """One program with connections open, counted by where they go."""

    name: str
    total: int
    this_mac: int
    local_network: int
    internet: int


@dataclass(frozen=True, slots=True)
class UpdateRow:
    """One update waiting."""

    title: str
    version: str
    restart: bool


def posture_rows(data: Mapping[str, object]) -> list[PostureRow]:
    """The four protections, with unknown names and states made safe."""
    return [
        PostureRow(
            CHECK_NAMES.get(_text(check.get("name")), "Unknown check"),
            _text(check.get("state")) if _text(check.get("state")) in PILLS else "unknown",
        )
        for check in _items(data.get("checks"))
    ]


def program_rows(data: Mapping[str, object]) -> list[ProgramRow]:
    """Every program returned, busiest first."""
    return [
        ProgramRow(
            _name(entry.get("name")),
            _decimal(entry.get("processor_percent")),
            _number(entry.get("memory_megabytes")),
            OWNER_NAMES.get(_text(entry.get("owner")), "unknown"),
        )
        for entry in _items(data.get("top_processor"))
    ]


def listening_rows(data: Mapping[str, object]) -> list[ListeningRow]:
    """Every program accepting connections, reachable ones first."""
    return [
        ListeningRow(
            _name(entry.get("name")),
            _number(entry.get("port")),
            "other devices" if entry.get("reach") == "network" else "this Mac only",
        )
        for entry in _items(data.get("listening"))
    ]


def connected_rows(data: Mapping[str, object]) -> list[ConnectedRow]:
    """Every program with connections open, busiest first."""
    return [
        ConnectedRow(
            _name(entry.get("name")),
            _number(entry.get("total")),
            _number(entry.get("this_mac")),
            _number(entry.get("local_network")),
            _number(entry.get("internet")),
        )
        for entry in _items(data.get("connected_programs"))
    ]


def update_rows(data: Mapping[str, object]) -> list[UpdateRow]:
    """Every update listed."""
    return [
        UpdateRow(
            _name(entry.get("title"), 80),
            displayable(_text(entry.get("version")), 30),
            entry.get("needs_restart") is True,
        )
        for entry in _items(data.get("updates"))
    ]


def describe_result(tool: str, result: object) -> str:
    """The one-sentence summary for a section, from the gate's result. Never raises.

    Every summary is a fixed sentence written in Potato's code: either the
    tool's own summary, which is fixed text, or one of the gate's messages.
    """
    if not isinstance(result, GateResult):
        return TEXT_FAILED
    if result.ok is not True or not isinstance(result.result, Mapping):
        reason = result.reason
        return MESSAGES.get(reason, TEXT_FAILED) if reason is not None else TEXT_FAILED
    return _text(result.result.get("summary")) or TEXT_FAILED


def ok_data(result: object) -> Mapping[str, object] | None:
    """The tool's data, if the gate says it ran."""
    if isinstance(result, GateResult) and result.ok is True and isinstance(result.result, Mapping):
        return result.result
    return None


def format_megabytes(value: int) -> str:
    """A memory size with a unit, in megabytes or gigabytes."""
    if value >= 1024:
        return f"{value / 1024:.1f} GB"
    return f"{value:,} MB"


# --- Building blocks ---------------------------------------------------------


def _label(text: str, name: str = "", *, wrap: bool = False) -> QLabel:
    label = QLabel(text)
    # A label guesses whether text is rich text unless told. Never guess.
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
    label.setOpenExternalLinks(False)
    label.setWordWrap(wrap)
    if name:
        label.setObjectName(name)
    return label


def _number_font() -> QFont:
    # Digits of equal width, so numbers line up in their column.
    return QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)


class NumberItem(QTableWidgetItem):
    """A table cell holding a number: right-aligned, and sorted as a number."""

    def __init__(self, value: float, shown: str) -> None:
        """Show ``shown``; sort and draw the bar by ``value``."""
        super().__init__(shown)
        self.value = value
        self.setData(Qt.ItemDataRole.UserRole, value)
        self.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.setFont(_number_font())
        self.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)

    def __lt__(self, other: QTableWidgetItem) -> bool:
        """Compare as numbers, not as text."""
        if isinstance(other, NumberItem):
            return self.value < other.value
        return super().__lt__(other)


def _text_item(text: str) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
    return item


class BarDelegate(QStyledItemDelegate):
    """Draws a bar behind a number, as long as its share of the column's top value."""

    def __init__(self, colour: QColor, parent: QObject | None = None) -> None:
        """Bars in ``colour``."""
        super().__init__(parent)
        self.colour = colour
        self.top = 1.0

    def paint(
        self,
        painter: QPainter,
        option: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
    ) -> None:
        """Draw the bar, then the number on top."""
        value = index.data(Qt.ItemDataRole.UserRole)
        if type(value) in (int, float) and self.top > 0:
            # A thin bar along the bottom of the cell, under the number.
            share = max(0.0, min(1.0, float(value) / self.top))
            rect = option.rect.adjusted(8, 0, -8, -5)
            track = QRectF(rect.left(), rect.bottom() - 3, rect.width(), 4)
            bar = QRectF(track.left(), track.top(), track.width() * share, track.height())
            background = QColor(self.colour)
            background.setAlphaF(0.12)
            colour = QColor(self.colour)
            colour.setAlphaF(0.9)
            painter.save()
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(background)
            painter.drawRoundedRect(track, 2, 2)
            painter.setBrush(colour)
            painter.drawRoundedRect(bar, 2, 2)
            painter.restore()
        super().paint(painter, option, index)


def _table(
    headings: Sequence[str],
    sort_column: int = 0,
    order: Qt.SortOrder = Qt.SortOrder.AscendingOrder,
) -> QTableWidget:
    table = QTableWidget(0, len(headings))
    table.setHorizontalHeaderLabels(list(headings))
    table.verticalHeader().setVisible(False)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setShowGrid(False)
    table.setAlternatingRowColors(False)
    table.setWordWrap(False)
    table.setSortingEnabled(True)
    table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    table.verticalHeader().setDefaultSectionSize(32)
    header = table.horizontalHeader()
    header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
    header.setMinimumSectionSize(90)
    for column in range(1, len(headings)):
        header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        header.resizeSection(column, 110)
    # Click a heading to sort by it; this is the order before any click.
    header.setSortIndicator(sort_column, order)
    return table


def _fit_height(table: QTableWidget) -> None:
    # The page scrolls, not each table, so a table is as tall as its rows.
    rows = sum(1 for row in range(table.rowCount()) if not table.isRowHidden(row))
    height = table.horizontalHeader().height() + 4
    height += sum(
        table.rowHeight(row) for row in range(table.rowCount()) if not table.isRowHidden(row)
    )
    table.setFixedHeight(max(height, table.horizontalHeader().height() + 4) if rows else 0)
    table.setVisible(rows > 0)


class Card(QFrame):
    """A rounded panel with a title and a summary sentence."""

    def __init__(self, title: str) -> None:
        """Build the card, empty."""
        super().__init__()
        self.setObjectName("card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(16, 14, 16, 14)
        self.body.setSpacing(10)
        top = QHBoxLayout()
        top.addWidget(_label(title, "card_title"))
        top.addStretch(1)
        self.header_row = top
        self.body.addLayout(top)
        self.summary = _label(TEXT_NOT_LOADED, "summary", wrap=True)
        self.body.addWidget(self.summary)


class Metric(QFrame):
    """A big number with a caption."""

    def __init__(self, caption: str) -> None:
        """Build the tile, showing a dash."""
        super().__init__()
        self.setObjectName("tile")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)
        self.value = _label("-", "metric")
        self.value.setFont(self.value.font())
        layout.addWidget(self.value)
        layout.addWidget(_label(caption, "caption"))

    def show_number(self, number: int | None, *, warn: bool = False) -> None:
        """Show ``number``, or a dash if it is not known."""
        self.value.setText("-" if number is None else f"{number:,}")
        name = "metric_warn" if warn and number else "metric"
        if self.value.objectName() != name:
            self.value.setObjectName(name)
            self.value.style().unpolish(self.value)
            self.value.style().polish(self.value)


class LiveDot(QWidget):
    """A small dot that pulses while a refresh is running."""

    def __init__(self) -> None:
        """Build the dot, still."""
        super().__init__()
        self.setFixedSize(12, 12)
        self._busy = False
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    @property
    def busy(self) -> bool:
        """Whether it is pulsing."""
        return self._busy

    def set_busy(self, busy: bool) -> None:
        """Pulse, or stop pulsing."""
        self._busy = busy
        if busy:
            self._timer.start(PULSE_MS)
        else:
            self._timer.stop()
        self.update()

    def _tick(self) -> None:
        self._phase = (self._phase + 0.08) % 1.0
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802 - Qt's name
        """Draw the dot: green and pulsing while busy, grey-green when idle."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        colour = QColor(91, 227, 140)
        if self._busy:
            colour.setAlphaF(0.45 + 0.55 * (0.5 + 0.5 * math.sin(self._phase * math.tau)))
        else:
            colour.setAlphaF(0.6)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(colour)
        painter.drawEllipse(QRectF(1, 1, 10, 10))
        painter.end()


# --- The dialog --------------------------------------------------------------


class _Bridge(QObject):
    finished = Signal(str, object)


Starter = Callable[[Callable[[], None]], None]
Clock = Callable[[], time.struct_time]


def _start_thread(work: Callable[[], None]) -> None:
    threading.Thread(target=work, name="potato-dashboard", daemon=True).start()


class SecurityDashboard(QDialog):
    """The dashboard window."""

    def __init__(
        self,
        gate: ToolGate,
        parent: QWidget | None = None,
        *,
        start: Starter = _start_thread,
        clock: Clock = time.localtime,
    ) -> None:
        """Build the dashboard. Nothing runs until it is shown or a button is pressed."""
        super().__init__(parent)
        self.setWindowTitle(TITLE)
        self.setStyleSheet(STYLE)
        self._gate = gate
        self._start = start
        self._running: set[str] = set()
        self._results: dict[str, object] = {}
        self._full: set[str] = set()
        self._bridge = _Bridge()
        self._bridge.finished.connect(self._show)

        # Header.
        self.live = LiveDot()
        self.updated = _label(TEXT_NEVER, "subtitle")
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setObjectName("primary")
        self.refresh_button.clicked.connect(self.refresh)
        header = QHBoxLayout()
        titles = QVBoxLayout()
        titles.addWidget(_label("Security", "title"))
        titles.addWidget(_label("What Potato can see about this Mac, read-only.", "subtitle"))
        header.addLayout(titles, 1)
        status = QHBoxLayout()
        status.setSpacing(6)
        status.addWidget(self.live)
        status.addWidget(self.updated)
        header.addLayout(status)
        header.addSpacing(12)
        header.addWidget(self.refresh_button)

        # Metric tiles.
        self.metrics = {
            "programs": Metric("programs running"),
            "yours": Metric("are yours"),
            "listening": Metric("accepting connections"),
            "reachable": Metric("reachable from other devices"),
            "internet": Metric("internet connections"),
        }
        tiles = QGridLayout()
        tiles.setSpacing(10)
        for column, tile in enumerate(self.metrics.values()):
            tiles.addWidget(tile, 0, column)

        # Protections.
        self.cards: dict[str, Card] = {}
        posture = Card("Protections")
        self.posture_grid = QGridLayout()
        self.posture_grid.setHorizontalSpacing(10)
        self.posture_grid.setVerticalSpacing(8)
        posture.body.addLayout(self.posture_grid)
        self.cards["security_posture"] = posture

        # Programs.
        programs = Card("Programs")
        self.search = QLineEdit()
        self.search.setPlaceholderText(TEXT_SEARCH)
        self.search.setMaxLength(60)
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._filter)
        programs.header_row.addWidget(self.search)
        self.process_table = _table(
            ["Program", "Processor", "Memory", "Owner"], 1, Qt.SortOrder.DescendingOrder
        )
        self.processor_bars = BarDelegate(QColor(124, 108, 255), self.process_table)
        self.memory_bars = BarDelegate(QColor(60, 190, 255), self.process_table)
        self.process_table.setItemDelegateForColumn(1, self.processor_bars)
        self.process_table.setItemDelegateForColumn(2, self.memory_bars)
        programs.body.addWidget(self.process_table)
        self.cards["process_overview"] = programs

        # Network.
        network = Card("Network")
        network.body.addWidget(_label("Accepting connections", "caption"))
        self.listening_table = _table(["Program", "Port", "Reachable from"], 2)
        network.body.addWidget(self.listening_table)
        network.body.addWidget(_label("Connections open", "caption"))
        self.connected_table = _table(
            ["Program", "Total", "This Mac", "Local", "Internet"], 1, Qt.SortOrder.DescendingOrder
        )
        self.connection_bars = BarDelegate(QColor(91, 227, 140), self.connected_table)
        self.connected_table.setItemDelegateForColumn(1, self.connection_bars)
        network.body.addWidget(self.connected_table)
        network.body.addWidget(_label(TEXT_PARTIAL, "note", wrap=True))
        self.cards["network_overview"] = network

        # Updates.
        updates = Card("macOS updates")
        updates.summary.setText(TEXT_UPDATES_NOT_LOADED)
        self.updates_button = QPushButton("Check for updates")
        self.updates_button.clicked.connect(self.check_updates)
        updates.header_row.addWidget(self.updates_button)
        self.updates_table = _table(["Update", "Version", "Restart"])
        updates.body.addWidget(self.updates_table)
        self.cards[UPDATE_TOOL] = updates

        self.show_all_buttons: dict[str, QPushButton] = {}
        for tool in sorted(EXPANDABLE):
            self.cards[tool].body.addWidget(self._show_all_button(tool))
        self.sections = {tool: card.summary for tool, card in self.cards.items()}
        self.tables = (
            self.process_table,
            self.listening_table,
            self.connected_table,
            self.updates_table,
        )
        for table in self.tables:
            _fit_height(table)

        content = QWidget()
        page = QVBoxLayout(content)
        page.setContentsMargins(20, 18, 20, 18)
        page.setSpacing(14)
        page.addLayout(header)
        page.addLayout(tiles)
        for card in self.cards.values():
            page.addWidget(card)
        page.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        self.resize(820, 860)

        self._clock = clock
        self._auto = QTimer(self)
        self._auto.setInterval(AUTO_REFRESH_MS)
        self._auto.timeout.connect(self.refresh)

    # --- Buttons ------------------------------------------------------------

    def _show_all_button(self, tool: str) -> QPushButton:
        button = QPushButton(TEXT_SHOW_ALL)
        button.setEnabled(False)
        button.clicked.connect(lambda: self.toggle_full(tool))
        self.show_all_buttons[tool] = button
        return button

    def toggle_full(self, tool: str) -> None:
        """Switch a section between the busiest entries and every entry."""
        if tool not in EXPANDABLE:
            return
        if tool in self._full:
            self._full.discard(tool)
        else:
            self._full.add(tool)
        self.show_all_buttons[tool].setText(TEXT_SHOW_LESS if tool in self._full else TEXT_SHOW_ALL)
        if tool in self._results:
            self._fill(tool, self._results[tool])

    # --- Refreshing ---------------------------------------------------------

    @property
    def auto_refreshing(self) -> bool:
        """Whether the 30-second refresh is running."""
        return self._auto.isActive()

    def showEvent(self, event: QShowEvent) -> None:  # noqa: N802 - Qt's name
        """Refresh every 30 seconds while the dashboard can be seen."""
        super().showEvent(event)
        self._auto.start()

    def hideEvent(self, event: QHideEvent) -> None:  # noqa: N802 - Qt's name
        """Stop refreshing when the dashboard is hidden."""
        super().hideEvent(event)
        self._auto.stop()

    def refresh(self) -> None:
        """Run the three quick read-only tools."""
        self._run(REFRESH_TOOLS, TEXT_LOADING)

    def check_updates(self) -> None:
        """Ask Apple's update tool. Slow, so it has its own button and never runs by itself."""
        self._run((UPDATE_TOOL,), TEXT_UPDATES_LOADING)

    def _run(self, tools: Sequence[str], loading: str) -> None:
        waiting = [tool for tool in tools if tool not in self._running]
        if not waiting:
            return
        for tool in waiting:
            self._running.add(tool)
            if tool not in self._results:
                self.sections[tool].setText(loading)
        self._buttons()
        gate = self._gate

        def work() -> None:
            # Runs on a worker thread: touches no widget.
            for tool in waiting:
                try:
                    arguments = dict(ARGUMENTS.get(tool, {}))
                    result: object = gate.submit(
                        {"tool": tool, "arguments": arguments}, RequestOrigin.INTERFACE
                    )
                except Exception:
                    result = None
                self._bridge.finished.emit(tool, result)

        self._start(work)

    def _show(self, tool: str, result: object) -> None:
        if tool not in self.sections:
            return
        self._running.discard(tool)
        self._results[tool] = result
        self._fill(tool, result)
        if tool in self.show_all_buttons:
            self.show_all_buttons[tool].setEnabled(ok_data(result) is not None)
        if tool in REFRESH_TOOLS and not self._running & set(REFRESH_TOOLS):
            now = self._clock()
            self.updated.setText(f"Updated {now.tm_hour:02d}:{now.tm_min:02d}:{now.tm_sec:02d}")
        self._buttons()

    def _buttons(self) -> None:
        refreshing = bool(self._running & set(REFRESH_TOOLS))
        self.refresh_button.setEnabled(not refreshing)
        self.updates_button.setEnabled(UPDATE_TOOL not in self._running)
        self.live.set_busy(bool(self._running))

    # --- Filling the sections -------------------------------------------------

    def _fill(self, tool: str, result: object) -> None:
        self.sections[tool].setText(describe_result(tool, result))
        data = ok_data(result)
        if tool == "security_posture":
            self._fill_posture([] if data is None else posture_rows(data))
        elif tool == "process_overview":
            self._fill_programs(data)
        elif tool == "network_overview":
            self._fill_network(data)
        elif tool == UPDATE_TOOL:
            self._fill_updates([] if data is None else update_rows(data))

    def _fill_posture(self, rows: list[PostureRow]) -> None:
        while self.posture_grid.count():
            item = self.posture_grid.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.deleteLater()
        self.pills: dict[str, QLabel] = {}
        for index, row in enumerate(rows[:8]):
            text, name = PILLS[row.state]
            pill = _label(text, name)
            pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
            pill.setFixedWidth(46)
            self.posture_grid.addWidget(pill, index // 2, (index % 2) * 2)
            self.posture_grid.addWidget(_label(row.name), index // 2, (index % 2) * 2 + 1)
            self.pills[row.name] = pill

    def _fill_programs(self, data: Mapping[str, object] | None) -> None:
        rows = [] if data is None else program_rows(data)
        if "process_overview" not in self._full:
            rows = rows[:SHORT_ROWS]
        table = self.process_table
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        self.processor_bars.top = max((row.processor for row in rows), default=1.0) or 1.0
        self.memory_bars.top = float(max((row.memory_megabytes for row in rows), default=1) or 1)
        for index, row in enumerate(rows):
            table.setItem(index, 0, _text_item(row.name))
            table.setItem(index, 1, NumberItem(row.processor, f"{row.processor:.1f} %"))
            table.setItem(
                index, 2, NumberItem(row.memory_megabytes, format_megabytes(row.memory_megabytes))
            )
            table.setItem(index, 3, _text_item(row.owner))
        table.setSortingEnabled(True)
        self._filter(self.search.text())
        owners = _mapping(None if data is None else data.get("owners"))
        total = None if data is None else _number(data.get("total"))
        self.metrics["programs"].show_number(total)
        self.metrics["yours"].show_number(None if data is None else _number(owners.get("you")))

    def _fill_network(self, data: Mapping[str, object] | None) -> None:
        listening = [] if data is None else listening_rows(data)
        connected = [] if data is None else connected_rows(data)
        if "network_overview" not in self._full:
            listening = listening[:SHORT_ROWS]
            connected = connected[:SHORT_ROWS]
        table = self.listening_table
        table.setSortingEnabled(False)
        table.setRowCount(len(listening))
        for index, row in enumerate(listening):
            table.setItem(index, 0, _text_item(row.name))
            table.setItem(index, 1, NumberItem(row.port, str(row.port)))
            table.setItem(index, 2, _text_item(row.reach))
        table.setSortingEnabled(True)
        table = self.connected_table
        table.setSortingEnabled(False)
        table.setRowCount(len(connected))
        self.connection_bars.top = float(max((item.total for item in connected), default=1) or 1)
        for index, entry in enumerate(connected):
            table.setItem(index, 0, _text_item(entry.name))
            for column, value in enumerate(
                (entry.total, entry.this_mac, entry.local_network, entry.internet), start=1
            ):
                table.setItem(index, column, NumberItem(value, f"{value:,}"))
        table.setSortingEnabled(True)
        self._filter(self.search.text())
        if data is None:
            for key in ("listening", "reachable", "internet"):
                self.metrics[key].show_number(None)
            return
        all_listening = listening_rows(data)
        self.metrics["listening"].show_number(_number(data.get("listening_total")))
        self.metrics["reachable"].show_number(
            sum(1 for row in all_listening if row.reach == "other devices"), warn=True
        )
        self.metrics["internet"].show_number(
            _number(_mapping(data.get("connections")).get("internet"))
        )

    def _fill_updates(self, rows: list[UpdateRow]) -> None:
        table = self.updates_table
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            table.setItem(index, 0, _text_item(row.title))
            table.setItem(index, 1, _text_item(row.version))
            table.setItem(index, 2, _text_item("yes" if row.restart else "no"))
        table.setSortingEnabled(True)
        _fit_height(table)

    def _filter(self, text: str) -> None:
        """Show only rows whose program name contains ``text``, ignoring case."""
        wanted = text.strip().lower()
        for table in (self.process_table, self.listening_table, self.connected_table):
            for row in range(table.rowCount()):
                item = table.item(row, 0)
                name = item.text().lower() if item is not None else ""
                table.setRowHidden(row, bool(wanted) and wanted not in name)
            _fit_height(table)
