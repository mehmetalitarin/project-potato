"""The only code in Potato that may start another program (R3).

Everything that starts a process goes through this file, so there is one
place to review (T-TOOL-1, T-TOOL-3). It does two things:

- asks macOS to open an application that the launcher has already checked;
- runs one of a fixed list of read-only system commands, the *probes*, and
  returns what it printed.

The rules every process follows here:

- **A fixed program at an absolute path.** Nothing is looked up through the
  ``PATH`` setting, so a planted program of the same name is never found.
- **Fixed arguments.** The only variable part anywhere is an application
  path, and this module re-checks that it lies inside a standard
  applications folder. A probe is chosen by name from the list below; a
  caller cannot supply a program or an argument. No text from the model or
  from external data is passed on.
- **No shell.** Arguments go to the program as a list, so nothing in them is
  ever read as a command.
- **Nothing in.** A program gets no input, and the environment holds only a
  search path for the system's own programs. Error output is discarded,
  except for the update check, whose answer arrives there.
- **A time limit.** A program that does not finish in time is stopped.
- **An output cap.** A probe that prints more than its limit (a few
  kilobytes for a setting, more for the list of processes) is stopped, and
  what it printed is thrown away.
- **No lookups.** The network probe prints numbers only, so running it
  never contacts a name server.

The probes only read. None can change anything, and none is given
administrator rights by Potato. The process list asks ``ps`` for each
program's short name only, never its command line, which can hold secrets
(T-TOOL-4).
"""

import contextlib
import os
import select
import subprocess  # Allowed in this module only; see R3 in docs/architecture.md.
import time
from collections.abc import Mapping, Sequence
from enum import Enum
from pathlib import Path
from types import MappingProxyType
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

# The whole environment a started program receives. With no language set,
# Apple's tools answer in their default wording, which the callers rely on.
_ENVIRONMENT: Final = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}

PROBE_TIMEOUT_SECONDS: Final = 5.0
MAX_PROBE_OUTPUT_BYTES: Final = 4096
MAX_LISTING_OUTPUT_BYTES: Final = 256 * 1024
MAX_NETWORK_OUTPUT_BYTES: Final = 1024 * 1024
SOFTWARE_UPDATE_TIMEOUT_SECONDS: Final = 90.0


class Probe(Enum):
    """The read-only status commands Potato may run. Nothing else can be run.

    Each value is the complete command: an absolute path and fixed arguments.
    """

    FILEVAULT = ("/usr/bin/fdesetup", "status")
    FIREWALL = ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
    GATEKEEPER = ("/usr/sbin/spctl", "--status")
    SYSTEM_INTEGRITY = ("/usr/bin/csrutil", "status")
    # One line for each running process: its number, processor share, memory
    # in kilobytes, owner's number and short name. The short name ("ucomm")
    # never includes the command line. Each "=" removes a column heading.
    PROCESSES = (
        "/bin/ps", "-ax", "-o", "pid=", "-o", "pcpu=", "-o", "rss=", "-o", "uid=",
        "-o", "ucomm=",
    )  # fmt: skip
    # This Mac's network sockets, one field per line: process number (p),
    # short name (c), socket number (f), protocol (P), addresses (n) and TCP
    # state (T). "-n" and "-P" print numbers only, so nothing is looked up
    # on the network. Without administrator rights, only the user's own
    # programs are shown.
    NETWORK = ("/usr/sbin/lsof", "-nP", "-i", "-F", "pcfPnT")
    # Asks Apple's update service which updates exist. "--list" only lists:
    # it never downloads or installs anything. This is the one probe that
    # contacts the internet, through Apple's own tool, and the slowest.
    SOFTWARE_UPDATES = ("/usr/sbin/softwareupdate", "--list")


# Probes that print a list rather than one line may print more.
_OUTPUT_LIMITS: Final[Mapping[Probe, int]] = MappingProxyType(
    {Probe.PROCESSES: MAX_LISTING_OUTPUT_BYTES, Probe.NETWORK: MAX_NETWORK_OUTPUT_BYTES}
)
# The update check waits for Apple's servers.
_TIME_LIMITS: Final[Mapping[Probe, float]] = MappingProxyType(
    {Probe.SOFTWARE_UPDATES: SOFTWARE_UPDATE_TIMEOUT_SECONDS}
)
# softwareupdate writes "No new software available." to its error output, so
# for that probe the error output is read too, mixed into the same capped
# stream. Every other probe's error output is thrown away.
_READS_ERROR_OUTPUT: Final = frozenset({Probe.SOFTWARE_UPDATES})


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


def run_probe(probe: Probe) -> str | None:
    """Run one probe and return what it printed, or ``None`` if it could not be read.

    The exit code is not used: some of these tools exit with an error code
    simply to say a setting is off. Callers decide from the text, which they
    must treat as untrusted and match against exact expected patterns.

    A byte that is not plain ASCII becomes the replacement character
    U+FFFD, which no caller's pattern accepts. The rest of the output stays
    readable, so one odd name cannot hide the whole list of processes.

    Raises:
        ValueError: ``probe`` is not a member of ``Probe``. Nothing was
            started.
    """
    if not isinstance(probe, Probe):
        raise ValueError("only a listed probe can be run")
    output = _run_bounded(
        probe.value,
        timeout=_TIME_LIMITS.get(probe, PROBE_TIMEOUT_SECONDS),
        max_bytes=_OUTPUT_LIMITS.get(probe, MAX_PROBE_OUTPUT_BYTES),
        read_errors=probe in _READS_ERROR_OUTPUT,
    )
    if output is None:
        return None
    return output.decode("ascii", errors="replace")


def _run_bounded(
    command: Sequence[str],
    *,
    timeout: float = PROBE_TIMEOUT_SECONDS,
    max_bytes: int = MAX_PROBE_OUTPUT_BYTES,
    read_errors: bool = False,
) -> bytes | None:
    """Run ``command`` and return its output, or ``None`` if it broke a limit.

    Private to this module: the only caller is ``run_probe``, which passes a
    fixed command from ``Probe``. The limits are enforced while the program
    runs. A program that prints too much, takes too long, or keeps running
    after closing its output is killed.
    """
    if not command:
        return None
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed command from Probe, no shell
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if read_errors else subprocess.DEVNULL,
            env=_ENVIRONMENT,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None

    deadline = time.monotonic() + timeout
    chunks: list[bytes] = []
    total = 0
    complete = False
    try:
        if process.stdout is None:
            return None
        descriptor = process.stdout.fileno()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            ready, _, _ = select.select([descriptor], [], [], remaining)
            if not ready:
                return None
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                return None
            chunks.append(chunk)
        # The output is closed. The program must also end in time.
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
        complete = True
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    finally:
        if not complete:
            process.kill()
        if process.stdout is not None:
            process.stdout.close()
        # Collect the ended program so that it does not linger.
        with contextlib.suppress(subprocess.SubprocessError):
            process.wait(timeout=5.0)
    return b"".join(chunks)
