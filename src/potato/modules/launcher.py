"""The application launcher: opens one of a fixed list of Apple's applications.

One tool, ``open_app`` (low risk, so voice may use it). Its defences follow
T-TOOL-1 in ``docs/threat_model.md``:

- **A fixed list.** The model chooses a name from the list below; the gate
  refuses any other. Code, not the model, maps the name to a location and an
  Apple bundle identifier.
- **Only a system-installed copy.** Before opening, the launcher checks that
  the location is a real folder in a standard place, that it and its
  description belong to the system's administrator account (``root``), that
  nobody else can change them, and that its bundle identifier is the
  expected one. Apple's applications are installed this way; a lookalike
  copied in by a user or by malware is not, so it is refused.
- **Nothing passed on.** No file, link or argument goes to the application.
- **One place starts it.** The actual start happens in
  ``potato.integrations.processes``, the only code allowed to start a program.

The list holds Apple's applications only. Terminal and System Settings are
left out on purpose: opening them by voice is not something Potato needs.

What is not checked: Apple's code signature, and the files inside the bundle
other than its description. Root ownership shows the system installed it,
not that Apple made it. Changing a root-owned application needs root, and
Apple's own are on a sealed, read-only volume, so this is out of scope; a
signature check may be added with the system probes.

The checks run on the application's real location after links are followed,
while macOS is asked to open the path in the list. Swapping a link between
the two also needs root.
"""

import os
import plistlib
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final

from potato.integrations.processes import open_application
from potato.security.tools import ArgumentValue, ChoiceField, RiskLevel, ToolDefinition

MAX_INFO_BYTES: Final = 1024 * 1024
ROOT_ACCOUNT: Final = 0


@dataclass(frozen=True, slots=True)
class Application:
    """Where an approved application lives and what it must call itself."""

    path: Path
    bundle_id: str


_SYSTEM = Path("/System/Applications")

APPLICATIONS: Final[Mapping[str, Application]] = MappingProxyType(
    {
        "Safari": Application(Path("/Applications/Safari.app"), "com.apple.Safari"),
        "Notes": Application(_SYSTEM / "Notes.app", "com.apple.Notes"),
        "Calendar": Application(_SYSTEM / "Calendar.app", "com.apple.iCal"),
        "Mail": Application(_SYSTEM / "Mail.app", "com.apple.mail"),
        "Music": Application(_SYSTEM / "Music.app", "com.apple.Music"),
        "Calculator": Application(_SYSTEM / "Calculator.app", "com.apple.calculator"),
        "Reminders": Application(_SYSTEM / "Reminders.app", "com.apple.reminders"),
        "Maps": Application(_SYSTEM / "Maps.app", "com.apple.Maps"),
        "Photos": Application(_SYSTEM / "Photos.app", "com.apple.Photos"),
        "Weather": Application(_SYSTEM / "Weather.app", "com.apple.weather"),
        "Activity Monitor": Application(
            _SYSTEM / "Utilities" / "Activity Monitor.app", "com.apple.ActivityMonitor"
        ),
    }
)

# Where a genuine application may really be, once any links are followed.
# Recent macOS versions keep Safari in a separate, sealed system volume:
# /Applications/Safari.app links to /System/Cryptexes/..., which itself links
# to the folder below. Only the final, real folder is trusted.
TRUSTED_FOLDERS: Final = frozenset(
    {
        Path("/System/Applications"),
        Path("/System/Applications/Utilities"),
        Path("/Applications"),
        Path("/System/Volumes/Preboot/Cryptexes/App/System/Applications"),
    }
)

# Every outcome the tool can report, with a fixed sentence for each.
OUTCOMES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "opened": "The application was opened.",
        "not_installed": "That application is not installed on this Mac.",
        "not_genuine": (
            "That application is not where Potato expects it, or is not the "
            "system-installed copy, so it was not opened."
        ),
        "did_not_open": "macOS did not open the application.",
    }
)


def _owned_safely(status: os.stat_result, trusted_owner: int) -> bool:
    """Whether the trusted account owns it and no one else can change it."""
    return status.st_uid == trusted_owner and not stat.S_IMODE(status.st_mode) & 0o022


def check_application(
    application: Application,
    *,
    trusted_owner: int = ROOT_ACCOUNT,
    trusted_folders: frozenset[Path] = TRUSTED_FOLDERS,
) -> str | None:
    """Return why ``application`` must not be opened, or ``None`` if it is genuine."""
    try:
        os.lstat(application.path)
    except FileNotFoundError:
        return "not_installed"
    except OSError:
        return "not_genuine"

    # Follow any links, then check where they lead.
    real = Path(os.path.realpath(application.path))
    try:
        bundle = real.lstat()
    except OSError:
        return "not_genuine"
    if not stat.S_ISDIR(bundle.st_mode) or not _owned_safely(bundle, trusted_owner):
        return "not_genuine"
    if real.parent not in trusted_folders or real.suffix != ".app":
        return "not_genuine"

    info_path = real / "Contents" / "Info.plist"
    if Path(os.path.realpath(info_path)) != info_path:
        # The description must be inside the bundle, not reached through a link.
        return "not_genuine"
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = os.open(info_path, flags)
    except OSError:
        return "not_genuine"
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not _owned_safely(info, trusted_owner):
            return "not_genuine"
        if info.st_size > MAX_INFO_BYTES:
            return "not_genuine"
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 64 * 1024):
            total += len(chunk)
            if total > MAX_INFO_BYTES:
                return "not_genuine"
            chunks.append(chunk)
        data = b"".join(chunks)
    except OSError:
        return "not_genuine"
    finally:
        os.close(descriptor)
    try:
        described = plistlib.loads(data)
    except Exception:
        # Any description that cannot be read means "not genuine".
        return "not_genuine"
    if type(described) is not dict:
        return "not_genuine"
    if described.get("CFBundleIdentifier") != application.bundle_id:
        return "not_genuine"
    return None


def launcher_tools(
    applications: Mapping[str, Application] = APPLICATIONS,
    *,
    trusted_owner: int = ROOT_ACCOUNT,
    trusted_folders: frozenset[Path] = TRUSTED_FOLDERS,
    opener: Callable[[Path], bool] = open_application,
) -> tuple[ToolDefinition, ...]:
    """Return the launcher tool.

    The keyword arguments exist for tests, which cannot use Apple's real
    applications. Potato itself always uses the defaults.
    """
    fixed = MappingProxyType(dict(applications))

    def handle(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        name = str(arguments["name"])
        application = fixed[name]
        problem = check_application(
            application, trusted_owner=trusted_owner, trusted_folders=trusted_folders
        )
        if problem is None:
            problem = None if opener(application.path) else "did_not_open"
        outcome = problem or "opened"
        return {"application": name, "opened": problem is None, "message": OUTCOMES[outcome]}

    return (
        ToolDefinition(
            name="open_app",
            risk=RiskLevel.LOW,
            arguments={"name": ChoiceField(frozenset(fixed))},
            handler=handle,
            description="Open one of the user's Apple applications by name.",
            max_calls=5,
        ),
    )
