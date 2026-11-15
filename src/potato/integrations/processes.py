"""The only code in Potato that may start another program (R3).

Everything that starts a process goes through this file, so there is one
place to review. Today it does one thing: ask macOS to open an application
that the launcher has already checked (T-TOOL-1, T-TOOL-3).

The rules every process follows here:

- **A fixed program at an absolute path.** Nothing is looked up through the
  ``PATH`` setting, so a planted program of the same name is never found.
- **Fixed arguments.** The only variable part is an application path, and
  this module re-checks that it lies inside a standard applications folder.
  No text from the model or from external data is passed on.
- **No shell.** Arguments go to the program as a list, so nothing in them is
  ever read as a command.
- **Nothing in, nothing out.** Input and output are discarded, and the
  environment holds only a search path for the system's own programs.
- **A time limit.** A program that does not finish in time is stopped.
"""

import os
import subprocess  # Allowed in this module only; see R3 in docs/architecture.md.
from pathlib import Path
from typing import Final

OPEN_PROGRAM: Final = "/usr/bin/open"
TIMEOUT_SECONDS: Final = 10.0

# The folders macOS installs applications into. Apple's own applications
# live in the first two; Safari lives in /Applications.
APPLICATION_FOLDERS: Final = (
    Path("/System/Applications"),
    Path("/System/Applications/Utilities"),
    Path("/Applications"),
)

# The whole environment a started program receives.
_ENVIRONMENT: Final = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}


def _is_application_path(path: Path) -> bool:
    """Whether ``path`` names an application directly inside a standard folder."""
    if not path.is_absolute() or path.suffix != ".app":
        return False
    text = str(path)
    if "\x00" in text or text.startswith("-") or ".." in path.parts:
        return False
    return path.parent in APPLICATION_FOLDERS


def open_application(path: Path) -> bool:
    """Ask macOS to open the application at ``path``. Passes it nothing.

    The caller must already have checked that ``path`` is the genuine
    application it expects. This function checks again that the path lies
    in a standard applications folder, and refuses anything else.

    Returns:
        ``True`` if macOS reported that it opened the application.

    Raises:
        ValueError: ``path`` is not an application in a standard folder.
            Nothing was started.
    """
    if not isinstance(path, Path) or not _is_application_path(path):
        raise ValueError("only an application in a standard folder can be opened")
    try:
        finished = subprocess.run(  # noqa: S603 - fixed program, checked path, no shell
            [OPEN_PROGRAM, "-a", os.fspath(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_ENVIRONMENT,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        # Covers a missing program and the time limit. The error's own text
        # is not kept.
        return False
    return finished.returncode == 0
