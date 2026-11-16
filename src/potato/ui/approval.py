"""The approval dialog: the only way to say yes to a sensitive action.

A sensitive tool runs only with an approval, and an approval is made only
after the user approves in this dialog (P7 in ``docs/permissions.md``;
T-APPR-4 and T-VOICE-3 in ``docs/threat_model.md``).

What the dialog guarantees:

- **What is shown is what runs.** The text is built here, by code, from the
  gate's own validated copy of the action (``ApprovalRequest``). Nothing the
  model wrote as prose appears. Each detail is shown exactly: text in
  quotation marks, numbers bare. If a detail cannot be shown exactly, because
  it is too long or contains characters that are invisible or could be taken
  for a space, the action is not shown and cannot be approved.
- **Plain text only**, like the rest of the interface.
- **Deny is the default.** Return, Escape, closing the dialog and waiting too
  long all deny. Focus starts on Deny.
- **Approve needs a real press.** The Approve button acts only on a mouse or
  key event that arrived from the window system. A press made by code
  (``click()``, a posted event, an accessibility "press" action) does
  nothing.
- **No press in flight.** Approve is disabled for a moment after the dialog
  appears or comes back to the front, so a click or key press that was
  already on its way cannot approve.

What it cannot do: stop a user approving without reading, or stop software
that the user has allowed to control the computer from producing real input
events. Both are written down as limits (T-APPR-4).
"""

import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from PySide6.QtCore import QEvent, Qt, QTimer
from PySide6.QtGui import QFontDatabase, QShowEvent
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from potato.security.approvals import ApprovalRequest

MAX_VALUE_CHARACTERS: Final = 120
MAX_DETAILS: Final = 8
MAX_NUMBER: Final = 10**18
MAX_DESCRIPTION_CHARACTERS: Final = 200
APPROVE_DELAY_MS: Final = 1500
DIALOG_TIMEOUT_MS: Final = 60_000

_NAME: Final = re.compile(r"[a-z][a-z0-9_]{0,31}")
_PLAIN_SENTENCE: Final = re.compile(r"[\x20-\x7e]{1,200}")
# Characters that are never shown faithfully: controls, format characters
# (including direction overrides), private-use, surrogate and unassigned
# characters, and every separator. The ordinary space is allowed by name.
_UNSHOWABLE: Final = frozenset({"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp", "Zs"})

TITLE: Final = "Potato: approval needed"
TEXT_HEADING: Final = "Potato wants to do the following. It happens only if you approve."
TEXT_ACTION: Final = "Action"
TEXT_DETAILS: Final = "With exactly these details:"
TEXT_NO_DETAILS: Final = "This action has no details."
TEXT_OTHER_LETTERS: Final = (
    "A detail contains letters or symbols outside plain English. Some of these look "
    "identical to English letters, so check it carefully."
)
TEXT_FOOTER: Final = (
    "Return and Escape mean Deny. This request is denied automatically after one minute."
)
TEXT_NEEDS_REAL_PRESS: Final = "Approve needs a real click, or the space bar on the button."
TEXT_DENY: Final = "Deny"
TEXT_APPROVE: Final = "Approve"


@dataclass(frozen=True, slots=True)
class ActionText:
    """An action, and the exact text that describes it.

    Made only by ``describe_action``. Holding the request and its text
    together means the action approved is the action that was shown.
    """

    request: ApprovalRequest
    description: str
    details: tuple[str, ...]
    warnings: tuple[str, ...]


def _showable(text: str) -> bool:
    """Whether every character of ``text`` appears on screen as itself."""
    return all(
        character == " " or unicodedata.category(character) not in _UNSHOWABLE for character in text
    )


def describe_action(
    request: object, descriptions: Mapping[str, str] | None = None
) -> ActionText | None:
    """Build the dialog text for ``request``, or ``None`` if it cannot be shown exactly.

    Args:
        request: The gate's validated copy of the action.
        descriptions: Fixed sentences written by Potato's code, by tool name.
            Never model text.

    Returns:
        The text, or ``None``. ``None`` means the action must not be offered
        for approval: approving something that was not fully shown would
        defeat the dialog.
    """
    if type(request) is not ApprovalRequest:
        return None
    tool = request.tool
    arguments = request.arguments
    if type(tool) is not str or _NAME.fullmatch(tool) is None:
        return None
    if not isinstance(arguments, Mapping) or len(arguments) > MAX_DETAILS:
        return None

    details: list[str] = []
    other_letters = False
    for name, value in arguments.items():
        if type(name) is not str or _NAME.fullmatch(name) is None:
            return None
        # type(), not isinstance(): True and False are ints in Python.
        if type(value) is int:
            if abs(value) > MAX_NUMBER:
                return None
            details.append(f"{name}: {value}")
        elif type(value) is str:
            if len(value) > MAX_VALUE_CHARACTERS or not _showable(value):
                return None
            other_letters = other_letters or not value.isascii()
            # Quotation marks show where the text starts and ends, and tell
            # the text "3" from the number 3. A quotation mark or backslash
            # inside the text is written with a backslash before it.
            details.append(f"{name}: {json.dumps(value, ensure_ascii=False)}")
        else:
            return None

    description = (descriptions or {}).get(tool, "")
    if type(description) is not str or _PLAIN_SENTENCE.fullmatch(description) is None:
        description = ""
    warnings = (TEXT_OTHER_LETTERS,) if other_letters else ()
    return ActionText(request, description, tuple(details), warnings)


class _PhysicalButton(QPushButton):
    """A button that knows whether a real input event is pressing it.

    Qt marks an event as *spontaneous* when it came from the window system,
    which is how the mouse and keyboard arrive. Events made by code are not
    spontaneous. A button is clicked while a mouse or key release is being
    handled, so that is when the mark is checked.
    """

    _RELEASES: Final = frozenset({QEvent.Type.MouseButtonRelease, QEvent.Type.KeyRelease})

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self._physical = False

    @property
    def in_physical_event(self) -> bool:
        """Whether a real mouse or key release is being handled right now."""
        return self._physical

    def event(self, event: QEvent) -> bool:
        """Handle an event, noting whether it is a real release."""
        if event.type() not in self._RELEASES:
            return super().event(event)
        self._physical = event.spontaneous()
        try:
            return super().event(event)
        finally:
            self._physical = False


class ApprovalDialog(QDialog):
    """Asks the user to approve or deny one action."""

    def __init__(
        self,
        action: ActionText,
        parent: QWidget | None = None,
        *,
        approve_delay_ms: int = APPROVE_DELAY_MS,
        timeout_ms: int = DIALOG_TIMEOUT_MS,
    ) -> None:
        """Build the dialog. ``action`` must come from ``describe_action``."""
        super().__init__(parent)
        if type(action) is not ActionText:
            raise TypeError("the dialog shows only text made by describe_action")
        self.action = action
        self._approved = False
        self._armed = False
        self._approve_delay_ms = max(0, approve_delay_ms)

        self.setWindowTitle(TITLE)
        self.setModal(True)
        layout = QVBoxLayout()
        layout.addWidget(self._label(TEXT_HEADING))
        layout.addWidget(self._label(f"{TEXT_ACTION}: {action.request.tool}", fixed_width=True))
        if action.description:
            layout.addWidget(self._label(action.description))
        if action.details:
            layout.addWidget(self._label(TEXT_DETAILS))
            for detail in action.details:
                layout.addWidget(self._label(detail, fixed_width=True))
        else:
            layout.addWidget(self._label(TEXT_NO_DETAILS))
        for warning in action.warnings:
            layout.addWidget(self._label(warning))
        self.notice = self._label("")
        layout.addWidget(self.notice)
        layout.addWidget(self._label(TEXT_FOOTER))

        self.deny_button = QPushButton(TEXT_DENY)
        self.approve_button = _PhysicalButton(TEXT_APPROVE)
        self.deny_button.setDefault(True)
        self.deny_button.setAutoDefault(True)
        # Return never reaches Approve, even when Approve has the focus.
        self.approve_button.setDefault(False)
        self.approve_button.setAutoDefault(False)
        self.approve_button.setEnabled(False)
        self.deny_button.clicked.connect(self.reject)
        self.approve_button.clicked.connect(self._approve_pressed)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.approve_button)
        buttons.addWidget(self.deny_button)
        layout.addLayout(buttons)
        self.setLayout(layout)
        self.deny_button.setFocus()

        self._arm_timer = QTimer(self)
        self._arm_timer.setSingleShot(True)
        self._arm_timer.timeout.connect(self._arm)
        self._deadline = QTimer(self)
        self._deadline.setSingleShot(True)
        self._deadline.timeout.connect(self.reject)
        self._deadline.start(max(1, timeout_ms))

    @staticmethod
    def _label(text: str, *, fixed_width: bool = False) -> QLabel:
        label = QLabel(text)
        # A label guesses whether text is rich text unless told. Never guess.
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        label.setOpenExternalLinks(False)
        label.setWordWrap(True)
        if fixed_width:
            # Every character the same width, so l, I and 1 look different.
            label.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        return label

    # --- Arming -------------------------------------------------------------

    @property
    def armed(self) -> bool:
        """Whether Approve can be pressed yet."""
        return self._armed

    def _disarm_and_wait(self) -> None:
        self._armed = False
        self.approve_button.setEnabled(False)
        self._arm_timer.start(self._approve_delay_ms)

    def _arm(self) -> None:
        self._armed = True
        self.approve_button.setEnabled(True)

    def showEvent(self, event: QShowEvent) -> None:  # noqa: N802 - Qt's name
        """Start the wait before Approve can be pressed."""
        super().showEvent(event)
        self._disarm_and_wait()

    def changeEvent(self, event: QEvent) -> None:  # noqa: N802 - Qt's name
        """Start the wait again whenever the dialog comes back to the front."""
        super().changeEvent(event)
        if event.type() == QEvent.Type.ActivationChange and self.isActiveWindow():
            self._disarm_and_wait()

    # --- Deciding -----------------------------------------------------------

    @property
    def approved(self) -> bool:
        """``True`` only after a real press of Approve."""
        return self._approved

    def _approve_pressed(self) -> None:
        if not (self._armed and self.approve_button.in_physical_event):
            self.notice.setText(TEXT_NEEDS_REAL_PRESS)
            return
        self._approved = True
        self.accept()

    def done(self, result: int) -> None:
        """Close the dialog. Without a real press of Approve, the answer is Deny."""
        self._arm_timer.stop()
        self._deadline.stop()
        if not self._approved:
            result = int(QDialog.DialogCode.Rejected)
        super().done(result)
