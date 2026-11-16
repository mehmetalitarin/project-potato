"""The security dashboard: this Mac's protections, programs and network at a glance.

It shows what four tools report: the security posture, the process and
network overviews and, on request, the update check. How it stays safe:

- **Through the gate.** The dashboard runs the tools through the same gate as
  everything else, as ``RequestOrigin.INTERFACE``, so every run is checked,
  rate-limited and recorded in the audit log. It holds no tool of its own.
- **Read-only.** Every tool it can run only reads.
- **The model is not involved.** The tools' own data is shown, formatted by
  code here. Nothing goes through the model, so nothing can be distorted by
  it (T-LLM-4).
- **Plain text only.** Program names are the only text that did not come
  from Potato's code, and they are shown through ``displayable``.
- **One refresh at a time, off the main thread.**
"""

import threading
from collections.abc import Callable, Mapping, Sequence
from typing import Final, Protocol

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from potato.security.gate import MESSAGES, GateResult, RequestOrigin
from potato.ui.text import displayable

TITLE: Final = "Potato: security dashboard"
REFRESH_TOOLS: Final = ("security_posture", "process_overview", "network_overview")
UPDATE_TOOL: Final = "check_security_updates"

TEXT_NOT_LOADED: Final = "Not checked yet. Press Refresh."
TEXT_LOADING: Final = "Checking..."
TEXT_UPDATES_LOADING: Final = "Asking Apple's update tool. This can take a minute..."
TEXT_FAILED: Final = "This could not be checked just now."
STATE_MARKS: Final = {"on": "ON ", "off": "OFF", "unknown": " ? "}
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


class ToolGate(Protocol):
    """The part of the gate the dashboard needs."""

    def submit(
        self, proposal: object, origin: RequestOrigin, approval: object = None
    ) -> GateResult:
        """Check a proposal and, if every check passes, run the tool."""
        ...


# --- Formatting: tool data to lines of plain text ----------------------------


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _number(value: object) -> int:
    return value if type(value) is int else 0


def _items(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def format_posture(data: Mapping[str, object]) -> list[str]:
    """Lines for the posture section."""
    lines = [_text(data.get("summary"))]
    for check in _items(data.get("checks")):
        mark = STATE_MARKS.get(_text(check.get("state")), STATE_MARKS["unknown"])
        name = CHECK_NAMES.get(_text(check.get("name")), "Unknown check")
        lines.append(f"[{mark}] {name}")
    return lines


def format_processes(data: Mapping[str, object]) -> list[str]:
    """Lines for the process section."""
    lines = [_text(data.get("summary"))]
    if "total" not in data:
        return lines
    owners = data.get("owners")
    owners = owners if isinstance(owners, Mapping) else {}
    lines.append(
        f"{_number(data.get('total'))} programs running: {_number(owners.get('you'))} yours, "
        f"{_number(owners.get('system'))} system, {_number(owners.get('another_user'))} other users"
    )
    lines.append("Most processor:")
    for entry in _items(data.get("top_processor"))[:3]:
        name = displayable(_text(entry.get("name")), 40)
        percent = entry.get("processor_percent")
        shown = f"{percent:.1f}" if type(percent) is float else "?"
        lines.append(f"  {name}  {shown}%")
    lines.append("Most memory:")
    for entry in _items(data.get("top_memory"))[:3]:
        name = displayable(_text(entry.get("name")), 40)
        lines.append(f"  {name}  {_number(entry.get('memory_megabytes'))} MB")
    return lines


def format_network(data: Mapping[str, object]) -> list[str]:
    """Lines for the network section."""
    lines = [_text(data.get("summary"))]
    if "listening" not in data:
        return lines
    listening = _items(data.get("listening"))
    lines.append(f"Accepting connections: {_number(data.get('listening_total'))}")
    for entry in listening[:5]:
        name = displayable(_text(entry.get("name")), 40)
        reach = "other devices" if entry.get("reach") == "network" else "this Mac only"
        lines.append(f"  {name}  port {_number(entry.get('port'))}  ({reach})")
    connections = data.get("connections")
    connections = connections if isinstance(connections, Mapping) else {}
    counts = ", ".join(
        f"{_number(connections.get(key))} {label}" for key, label in PLACE_NAMES.items()
    )
    lines.append(f"Open connections: {counts}")
    warnings = data.get("warnings")
    if isinstance(warnings, list):
        lines.extend(_text(warning) for warning in warnings)
    lines.append(_text(data.get("note")))
    return lines


def format_updates(data: Mapping[str, object]) -> list[str]:
    """Lines for the updates section."""
    lines = [_text(data.get("summary"))]
    for entry in _items(data.get("updates")):
        title = displayable(_text(entry.get("title")), 80)
        version = _text(entry.get("version"))
        restart = " (needs a restart)" if entry.get("needs_restart") is True else ""
        lines.append(f"  {title} {version}{restart}".rstrip())
    return lines


FORMATTERS: Final[dict[str, Callable[[Mapping[str, object]], list[str]]]] = {
    "security_posture": format_posture,
    "process_overview": format_processes,
    "network_overview": format_network,
    UPDATE_TOOL: format_updates,
}


def describe_result(tool: str, result: object) -> str:
    """The text for one section, from the gate's result. Never raises."""
    if not isinstance(result, GateResult):
        return TEXT_FAILED
    if result.ok is not True or not isinstance(result.result, Mapping):
        reason = result.reason
        return MESSAGES.get(reason, TEXT_FAILED) if reason is not None else TEXT_FAILED
    try:
        lines = FORMATTERS[tool](result.result)
    except Exception:
        return TEXT_FAILED
    return "\n".join(line for line in lines if line)


# --- The dialog --------------------------------------------------------------


class _Bridge(QObject):
    finished = Signal(str, object)


Starter = Callable[[Callable[[], None]], None]


def _start_thread(work: Callable[[], None]) -> None:
    threading.Thread(target=work, name="potato-dashboard", daemon=True).start()


class SecurityDashboard(QDialog):
    """The dashboard window."""

    def __init__(
        self, gate: ToolGate, parent: QWidget | None = None, *, start: Starter = _start_thread
    ) -> None:
        """Build the dashboard. Nothing runs until Refresh or Check is pressed."""
        super().__init__(parent)
        self.setWindowTitle(TITLE)
        self._gate = gate
        self._start = start
        self._running: set[str] = set()
        self._bridge = _Bridge()
        self._bridge.finished.connect(self._show)

        self.sections: dict[str, QLabel] = {}
        layout = QVBoxLayout()
        for tool, heading in (
            ("security_posture", "Protections"),
            ("process_overview", "Programs"),
            ("network_overview", "Network"),
            (UPDATE_TOOL, "macOS updates"),
        ):
            box = QGroupBox(heading)
            inner = QVBoxLayout()
            label = QLabel(TEXT_NOT_LOADED)
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
            label.setOpenExternalLinks(False)
            label.setWordWrap(True)
            inner.addWidget(label)
            box.setLayout(inner)
            layout.addWidget(box)
            self.sections[tool] = label

        self.refresh_button = QPushButton("Refresh")
        self.updates_button = QPushButton("Check for updates")
        self.refresh_button.clicked.connect(self.refresh)
        self.updates_button.clicked.connect(self.check_updates)
        buttons = QHBoxLayout()
        buttons.addWidget(self.refresh_button)
        buttons.addWidget(self.updates_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        self.setLayout(layout)
        self.resize(520, 640)

    def refresh(self) -> None:
        """Run the three quick read-only tools."""
        self._run(REFRESH_TOOLS, TEXT_LOADING)

    def check_updates(self) -> None:
        """Ask Apple's update tool. Slow, so it has its own button."""
        self._run((UPDATE_TOOL,), TEXT_UPDATES_LOADING)

    def _run(self, tools: Sequence[str], loading: str) -> None:
        waiting = [tool for tool in tools if tool not in self._running]
        if not waiting:
            return
        for tool in waiting:
            self._running.add(tool)
            self.sections[tool].setText(loading)
        self._buttons()
        gate = self._gate

        def work() -> None:
            # Runs on a worker thread: touches no widget.
            for tool in waiting:
                try:
                    result: object = gate.submit(
                        {"tool": tool, "arguments": {}}, RequestOrigin.INTERFACE
                    )
                except Exception:
                    result = None
                self._bridge.finished.emit(tool, result)

        self._start(work)

    def _show(self, tool: str, result: object) -> None:
        if tool not in self.sections:
            return
        self._running.discard(tool)
        self.sections[tool].setText(describe_result(tool, result))
        self._buttons()

    def _buttons(self) -> None:
        self.refresh_button.setEnabled(not self._running & set(REFRESH_TOOLS))
        self.updates_button.setEnabled(UPDATE_TOOL not in self._running)
