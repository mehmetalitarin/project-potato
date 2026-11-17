"""Start-up: the one place where Potato's parts are put together.

``python -m potato`` calls ``run``, which reads the settings, builds every
part, shows the window and, when the window closes, shuts everything down.

What this module guarantees (``docs/architecture.md``, "Start-up"):

- **The approval maker goes to the window and nowhere else.** The pair is
  made once. The gate receives the half that can only check approvals; the
  window receives the half that makes them. Nothing else, including this
  module after that one hand-over, keeps a reference to the maker (R4). A
  test reads this file and fails if that changes.
- **The tools that are switched on are one fixed list**, ``enabled_tools``,
  written here in code (R7). Settings cannot add a tool.
- **Fail closed.** If the settings are invalid, or the logs or the audit log
  cannot be opened safely, or another copy of Potato is running, Potato does
  not start. It never runs without its audit log (R8).
- **The model leaves memory when Potato leaves the active state**: after the
  idle timeout, on Sleep, on an error and on quitting. Ollama is also told
  to drop the model by itself after the same time, in case Potato is killed.
- **Shutdown closes everything**: Potato is put to sleep, the model is
  unloaded and the audit log is closed.

Only ``potato.__main__`` may import this module.
"""

import logging
import math
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from potato.core.config import ConfigError, Settings, parse_settings
from potato.core.state import AssistantState, StateManager, StateTransitionError
from potato.core.turns import TurnEngine
from potato.integrations.ollama import (
    OllamaClient,
    OllamaResponseError,
    OllamaUnavailableError,
)
from potato.integrations.processes import start_speaking
from potato.modules.calendar import calendar_tools
from potato.modules.launcher import launcher_tools
from potato.modules.link_analysis import link_analysis_tools
from potato.modules.network_overview import network_overview_tools
from potato.modules.portfolio import portfolio_tools
from potato.modules.process_overview import process_overview_tools
from potato.modules.security_posture import security_posture_tools
from potato.modules.security_updates import security_update_tools
from potato.security.approvals import create_approval_pair
from potato.security.audit import AUDIT_FILE_NAME, AuditLog, AuditLogError
from potato.security.gate import Gate
from potato.security.logs import configure_logging, default_log_directory
from potato.security.private_files import PrivateFileError
from potato.security.redaction import Redactor
from potato.security.tools import ToolDefinition
from potato.storage.database import default_database_path
from potato.storage.settings_file import (
    SettingsFileError,
    default_settings_path,
    read_settings_file,
)
from potato.ui.mascot import potato_icon
from potato.ui.window import PotatoWindow
from potato.voice.speaker import Speaker

APPLICATION_NAME: Final = "Potato"
IDLE_CHECK_MS: Final = 5000
UNLOAD_TIMEOUT_SECONDS: Final = 5.0
SHUTDOWN_WAIT_SECONDS: Final = 6.0

EXIT_OK: Final = 0
EXIT_BAD_SETTINGS: Final = 2
EXIT_CANNOT_START: Final = 3

TEXT_CANNOT_START: Final = (
    "Potato did not start, because it could not open its logs safely. "
    "It never runs without its audit log."
)

_log = logging.getLogger(__name__)

Clock = Callable[[], float]
Starter = Callable[[Callable[[], None]], threading.Thread | None]


@dataclass(frozen=True, slots=True)
class Locations:
    """Where Potato keeps its files."""

    settings: Path
    logs: Path
    database: Path


def default_locations() -> Locations:
    """Return Potato's usual places in the user's Library folder."""
    return Locations(
        settings=default_settings_path(),
        logs=default_log_directory(),
        database=default_database_path(),
    )


def enabled_tools(database_path: Path) -> tuple[ToolDefinition, ...]:
    """Return every tool that is switched on. This list is the allowlist (R7).

    A tool not returned here cannot be proposed, approved or run. The gate
    is built from exactly this list and nothing can be added afterwards.
    """
    return (
        *calendar_tools(),
        *launcher_tools(),
        *link_analysis_tools(),
        *portfolio_tools(database_path),
        *security_posture_tools(),
        *process_overview_tools(),
        *network_overview_tools(),
        *security_update_tools(),
    )


def load_settings(path: Path) -> Settings:
    """Read and validate the settings file. No file means the built-in defaults.

    Raises:
        SettingsFileError: The file exists but cannot be used safely.
        ConfigError: A setting is invalid.
    """
    return parse_settings(read_settings_file(path) or "")


def _start_thread(work: Callable[[], None]) -> threading.Thread:
    thread = threading.Thread(target=work, name="potato-unload", daemon=True)
    thread.start()
    return thread


class ModelUnloader:
    """Frees the model's memory whenever Potato leaves the active state.

    It has its own client, so it never shares one with a turn in progress.
    """

    def __init__(self, client: OllamaClient, start: Starter = _start_thread) -> None:
        """Remember the client. Connects to nothing."""
        self._client = client
        self._start = start
        self._last: threading.Thread | None = None

    def __call__(self, old: AssistantState, new: AssistantState) -> None:
        """Follow a change of state. Never blocks and never raises."""
        if old is AssistantState.ACTIVE and new is not AssistantState.ACTIVE:
            self._last = self._start(self.unload_now)

    def unload_now(self) -> None:
        """Ask Ollama to drop the model. A failure is logged, not raised."""
        try:
            self._client.unload()
        except (OllamaUnavailableError, OllamaResponseError, ValueError):
            # Ollama drops the model by itself after the keep-alive time.
            _log.warning("The model could not be unloaded just now")

    def wait(self, seconds: float) -> None:
        """Give an unload that is under way a moment to finish."""
        if self._last is not None:
            self._last.join(seconds)


class Application:
    """Potato, put together. Owns everything that must be closed."""

    def __init__(
        self,
        window: PotatoWindow,
        state: StateManager,
        audit: AuditLog,
        unloader: ModelUnloader,
        log_handler: logging.Handler,
    ) -> None:
        """Keep the parts that shutdown needs. See ``build``."""
        self.window = window
        self.state = state
        self._audit = audit
        self._unloader = unloader
        self._log_handler = log_handler
        self._closed = False
        self._idle_timer = QTimer()
        self._idle_timer.setInterval(IDLE_CHECK_MS)
        self._idle_timer.timeout.connect(self.check_idle)
        self._idle_timer.start()

    def check_idle(self) -> bool:
        """Send Potato back to standby if it has been idle too long.

        Skipped while a request or an approval is in progress, so a slow
        reply is not cut off.
        """
        if self.window.busy:
            return False
        try:
            return self.state.check_idle()
        except StateTransitionError:
            return False

    def close(self) -> None:
        """Shut everything down. Safe to call twice."""
        if self._closed:
            return
        self._closed = True
        self._idle_timer.stop()
        # Closing the window denies anything waiting and puts Potato to
        # sleep, which starts the unload if the model was in use.
        self.window.close()
        self._unloader.wait(SHUTDOWN_WAIT_SECONDS)
        self._audit.close()
        logging.getLogger().removeHandler(self._log_handler)
        self._log_handler.close()


def build(
    settings: Settings,
    locations: Locations,
    *,
    tools: Sequence[ToolDefinition] | None = None,
    clock: Clock = time.monotonic,
) -> Application:
    """Put Potato together. Shows nothing and connects to nothing.

    Args:
        settings: Validated settings.
        locations: Where the logs and the database are.
        tools: For tests only, which need a sensitive tool that does not
            exist in Potato. ``run`` never passes it.
        clock: Returns seconds from a monotonic clock. Tests replace it.

    Raises:
        PrivateFileError: The log folder or a log file is not safe to use.
        AuditLogError: The audit log failed its integrity check, cannot be
            opened, or belongs to another running copy of Potato.
    """
    redactor = Redactor()
    # The audit log first: opening it is also what refuses a second copy of
    # Potato, before that copy touches anything else.
    audit = AuditLog(locations.logs / AUDIT_FILE_NAME, redactor)
    try:
        log_handler = configure_logging(locations.logs, redactor)
    except BaseException:
        audit.close()
        raise

    allowed = tuple(enabled_tools(locations.database) if tools is None else tools)
    # R4. The gate gets the half that checks. The half that makes approvals
    # is handed to the window below and is not used anywhere else.
    issuer, verifier = create_approval_pair(settings.security.approval_lifetime_seconds, audit)
    gate = Gate(allowed, audit, approvals=verifier)
    state = StateManager(settings.assistant.idle_timeout_seconds, audit, clock=clock)

    ollama = settings.ollama
    keep_alive = math.ceil(settings.assistant.idle_timeout_seconds)
    model = OllamaClient(
        ollama.host,
        ollama.port,
        ollama.model,
        timeout_seconds=ollama.request_timeout_seconds,
        context_length=ollama.context_length,
        keep_alive_seconds=keep_alive,
    )
    unloader = ModelUnloader(
        OllamaClient(
            ollama.host,
            ollama.port,
            ollama.model,
            timeout_seconds=UNLOAD_TIMEOUT_SECONDS,
            context_length=ollama.context_length,
            keep_alive_seconds=keep_alive,
        )
    )
    state.subscribe(unloader)

    # Reads replies aloud with macOS's own voice, only while active.
    speaker = Speaker(state, start_speaking)
    window = PotatoWindow(
        TurnEngine(model, gate, state),
        state,
        issuer=issuer,
        gate=gate,
        # Each tool's own fixed sentence, written in Potato's code.
        descriptions={tool.name: tool.description for tool in allowed},
        voice=speaker,
    )
    return Application(window, state, audit, unloader, log_handler)


def run(locations: Locations | None = None) -> int:
    """Start Potato, wait until the window closes, and shut down.

    Returns:
        The process exit code.
    """
    places = default_locations() if locations is None else locations
    try:
        settings = load_settings(places.settings)
    except (SettingsFileError, ConfigError) as error:
        # These messages name the setting and the rule, never the bad value.
        sys.stderr.write(f"Settings problem: {error}\n")
        return EXIT_BAD_SETTINGS

    existing = QApplication.instance()
    qt = existing if isinstance(existing, QApplication) else QApplication([APPLICATION_NAME])
    qt.setApplicationName(APPLICATION_NAME)
    qt.setWindowIcon(potato_icon())
    try:
        application = build(settings, places)
    except (PrivateFileError, AuditLogError) as error:
        # These messages are written in Potato's code.
        sys.stderr.write(f"{TEXT_CANNOT_START}\nReason: {error}\n")
        return EXIT_CANNOT_START
    try:
        application.window.show()
        return int(qt.exec())
    finally:
        application.close()
