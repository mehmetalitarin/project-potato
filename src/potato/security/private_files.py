"""Creates log folders and files that only their owner can use.

Logs can reveal what the user does, so they are kept private to the user's
account (T-DATA-2 in ``docs/threat_model.md``). This stops other accounts on
the same Mac. It does not stop software running as the same user, which the
threat model places out of scope.
"""

import os
import stat
from pathlib import Path


class PrivateFileError(Exception):
    """A log folder or file exists but is not safe to use."""


def ensure_private_directory(path: Path) -> None:
    """Create ``path`` if needed and make sure only the owner can enter it.

    Args:
        path: The folder to create or check.

    Raises:
        PrivateFileError: The path is a link, is not a folder or belongs to
            another user.
    """
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    # lstat, not stat: a link here could point the logs somewhere unexpected.
    status = path.lstat()
    if not stat.S_ISDIR(status.st_mode):
        raise PrivateFileError("the log folder path is not a real folder")
    if status.st_uid != os.getuid():
        raise PrivateFileError("the log folder belongs to another user")
    if stat.S_IMODE(status.st_mode) != 0o700:
        path.chmod(0o700)


def open_private_append(path: Path) -> int:
    """Open ``path`` for appending, creating it readable by its owner only.

    The checks are made on the open file, not on the path, so the file cannot
    be swapped for another between the check and the first write.

    Args:
        path: The file to open or create.

    Returns:
        An open file descriptor. The caller must close it.

    Raises:
        PrivateFileError: The path is a link, is not a regular file or
            belongs to another user.
    """
    # O_NOFOLLOW refuses a link. O_NONBLOCK stops a named pipe from making the
    # open wait forever; it has no effect on a regular file.
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise PrivateFileError("the log file could not be opened safely") from error

    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise PrivateFileError("the log path is not a regular file")
        if status.st_uid != os.getuid():
            raise PrivateFileError("the log file belongs to another user")
        if stat.S_IMODE(status.st_mode) != 0o600:
            os.fchmod(descriptor, 0o600)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor
