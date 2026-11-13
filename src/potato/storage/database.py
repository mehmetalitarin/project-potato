"""The local SQLite database, which holds the user's portfolio holdings.

Three rules shape this module:

- **Parameterised queries only** (T-DATA-5 in ``docs/threat_model.md``).
  Every SQL statement is a fixed string written in this file. Values are
  passed separately as parameters, so crafted text is stored as text and can
  never change a query. A test reads this file and fails if any statement is
  built at run time.
- **Owner-only files** (T-DATA-2). The folder and the database file can be
  used by their owner only. SQLite creates its journal file with the same
  permissions as the database file, so it is owner-only too.
- **No secrets** (R9). The database holds ticker symbols and quantities.
  Credentials live in the macOS Keychain.

The database is not encrypted. Disk encryption protects it while the Mac is
off. Software running as the same user can read it, which the threat model
accepts.
"""

import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import TracebackType
from typing import Final, Self

from potato.security.private_files import PrivateFileError, ensure_private_directory

DATABASE_FILE_NAME: Final = "potato.db"

# Written into the file header so that Potato never mistakes another
# program's database for its own. The bytes spell "Pota".
APPLICATION_ID: Final = 0x506F7461

# The longest text or blob SQLite will accept. Potato stores short values
# only, so anything bigger is a mistake or an attack.
MAX_VALUE_BYTES: Final = 64 * 1024

MAX_SYMBOL_CHARACTERS: Final = 10
MAX_QUANTITY: Final = Decimal(1_000_000_000)
MAX_QUANTITY_DECIMAL_PLACES: Final = 8

# A letter first, then letters, digits, dots or hyphens: "AAPL", "BRK.B".
_SYMBOL: Final = re.compile(rf"[A-Z][A-Z0-9.\-]{{0,{MAX_SYMBOL_CHARACTERS - 1}}}")

# --- SQL ------------------------------------------------------------------
# Every statement Potato runs is one of the constants below.

# Schema changes, one tuple of statements per version. Version N is reached
# by running entries 1 to N in order. An entry is never edited once
# released: a change to the schema is a new entry. Each entry ends by
# recording its own version number, so the two cannot drift apart.
_MIGRATIONS: Final = (
    (
        "PRAGMA application_id = 1349481569",
        """
        CREATE TABLE holding (
            symbol   TEXT NOT NULL PRIMARY KEY
                     CHECK (length(symbol) BETWEEN 1 AND 10)
                     CHECK (symbol GLOB '[A-Z]*')
                     CHECK (symbol NOT GLOB '*[^A-Z0-9.-]*'),
            quantity TEXT NOT NULL
                     CHECK (length(quantity) BETWEEN 1 AND 32)
        ) STRICT
        """,
        "PRAGMA user_version = 1",
    ),
)

SCHEMA_VERSION: Final = len(_MIGRATIONS)

_SETTINGS: Final = (
    # Use the rollback journal, which exists only during a write. WAL mode
    # would keep two extra files next to the database at all times.
    "PRAGMA journal_mode = DELETE",
    # Overwrite deleted content instead of leaving it in free pages.
    "PRAGMA secure_delete = ON",
    "PRAGMA foreign_keys = ON",
    # Do not run functions named inside the schema, so a tampered file
    # cannot make queries call code.
    "PRAGMA trusted_schema = OFF",
    "PRAGMA cell_size_check = ON",
)

_READ_APPLICATION_ID: Final = "PRAGMA application_id"
_READ_USER_VERSION: Final = "PRAGMA user_version"
_COUNT_SCHEMA_OBJECTS: Final = "SELECT count(*) FROM sqlite_schema"
_QUICK_CHECK: Final = "PRAGMA quick_check"
_BEGIN: Final = "BEGIN IMMEDIATE"
_COMMIT: Final = "COMMIT"
_ROLLBACK: Final = "ROLLBACK"

_UPSERT_HOLDING: Final = (
    "INSERT INTO holding (symbol, quantity) VALUES (?, ?) "
    "ON CONFLICT (symbol) DO UPDATE SET quantity = excluded.quantity"
)
_DELETE_HOLDING: Final = "DELETE FROM holding WHERE symbol = ?"
_SELECT_HOLDINGS: Final = "SELECT symbol, quantity FROM holding ORDER BY symbol"


class DatabaseError(Exception):
    """The database cannot be used safely, or a database operation failed."""


@dataclass(frozen=True, slots=True)
class Holding:
    """How many units of one stock or fund the user holds.

    Quantities are ``Decimal``, not ``float``, so that 0.1 + 0.2 is exactly
    0.3. They are stored as text for the same reason.
    """

    symbol: str
    quantity: Decimal

    def __post_init__(self) -> None:
        """Refuse a symbol or quantity outside the fixed rules."""
        _require_symbol(self.symbol)
        _require_quantity(self.quantity)


def _require_symbol(symbol: object) -> str:
    """Return ``symbol`` if it is a valid ticker symbol, else raise."""
    if not isinstance(symbol, str) or _SYMBOL.fullmatch(symbol) is None:
        raise ValueError(
            "a symbol must be 1 to 10 capital letters, digits, dots or hyphens, "
            "starting with a letter"
        )
    return symbol


def _require_quantity(quantity: object) -> Decimal:
    """Return ``quantity`` if it is a valid holding size, else raise."""
    # Only Decimal is accepted: a float such as 0.1 is already inexact.
    if not isinstance(quantity, Decimal) or not quantity.is_finite():
        raise ValueError("a quantity must be a finite Decimal")
    if not Decimal(0) < quantity <= MAX_QUANTITY:
        raise ValueError(f"a quantity must be above 0 and at most {MAX_QUANTITY}")
    exponent = quantity.as_tuple().exponent
    if isinstance(exponent, int) and exponent < -MAX_QUANTITY_DECIMAL_PLACES:
        raise ValueError(
            f"a quantity can have at most {MAX_QUANTITY_DECIMAL_PLACES} decimal places"
        )
    return quantity


def _quantity_to_text(quantity: Decimal) -> str:
    """Write a quantity as plain digits, never in scientific notation."""
    return format(quantity.normalize(), "f")


def _quantity_from_text(text: object) -> Decimal:
    """Read a stored quantity back, refusing anything that is not valid."""
    if not isinstance(text, str):
        raise DatabaseError("the database holds a quantity that is not text")
    try:
        return _require_quantity(Decimal(text))
    except (InvalidOperation, ValueError):
        pass
    raise DatabaseError("the database holds an invalid quantity")


def default_database_path() -> Path:
    """Return where Potato keeps its database on macOS."""
    return Path.home() / "Library" / "Application Support" / "Potato" / DATABASE_FILE_NAME


class Database:
    """An open connection to Potato's database.

    Opening the database checks the folder and file, applies any missing
    schema changes and checks the file for damage. A database that fails any
    check is refused, never repaired or replaced, so nothing is lost.

    Use it as a context manager so the connection is always closed::

        with Database(default_database_path()) as database:
            database.set_holding(Holding("AAPL", Decimal("2.5")))

    Not safe to share between threads.
    """

    def __init__(self, path: Path) -> None:
        """Open, check and if needed upgrade the database at ``path``.

        Args:
            path: An absolute path to the database file. The file is created
                if it does not exist.

        Raises:
            ValueError: ``path`` is not absolute.
            DatabaseError: The folder or file is not safe to use, the file is
                not Potato's database, it was made by a newer version of
                Potato or it is damaged.
        """
        if not path.is_absolute():
            raise ValueError("the database path must be absolute")
        try:
            ensure_private_directory(path.parent)
        except (OSError, PrivateFileError) as error:
            raise DatabaseError("the database folder is not safe to use") from error

        identity = _create_private_file(path)
        self._connection = _connect(path)
        try:
            _require_same_file(path, identity)
            self._prepare()
        except BaseException:
            self._connection.close()
            raise

    def __enter__(self) -> Self:
        """Return the open database."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the database."""
        self.close()

    def close(self) -> None:
        """Close the connection. Closing twice is harmless."""
        self._connection.close()

    @property
    def schema_version(self) -> int:
        """The schema version recorded in the file."""
        return self._read_integer(_READ_USER_VERSION)

    def set_holding(self, holding: Holding) -> None:
        """Record a holding, replacing any earlier quantity for its symbol."""
        self._write(_UPSERT_HOLDING, (holding.symbol, _quantity_to_text(holding.quantity)))

    def remove_holding(self, symbol: str) -> bool:
        """Remove the holding for ``symbol``.

        Returns:
            ``True`` if a holding was removed, ``False`` if there was none.

        Raises:
            ValueError: ``symbol`` is not a valid ticker symbol.
        """
        return self._write(_DELETE_HOLDING, (_require_symbol(symbol),)) > 0

    def holdings(self) -> list[Holding]:
        """Return every holding, sorted by symbol.

        Raises:
            DatabaseError: A stored row breaks the rules, which means the file
                was changed outside Potato.
        """
        try:
            rows = self._connection.execute(_SELECT_HOLDINGS).fetchall()
        except sqlite3.Error as error:
            raise DatabaseError("the holdings could not be read") from error
        result = []
        for symbol, quantity in rows:
            try:
                symbol = _require_symbol(symbol)
            except ValueError:
                raise DatabaseError("the database holds an invalid symbol") from None
            result.append(Holding(symbol, _quantity_from_text(quantity)))
        return result

    def _prepare(self) -> None:
        """Apply settings, confirm the file is Potato's, migrate and check it."""
        connection = self._connection
        try:
            # Applies to this connection only; nothing in Potato needs more.
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_VALUE_BYTES)
            connection.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
            for statement in _SETTINGS:
                connection.execute(statement)

            application_id = self._read_integer(_READ_APPLICATION_ID)
            is_empty = self._read_integer(_COUNT_SCHEMA_OBJECTS) == 0
            if application_id != APPLICATION_ID and not (application_id == 0 and is_empty):
                raise DatabaseError("the file is not a Potato database")

            version = self.schema_version
            if version > SCHEMA_VERSION:
                raise DatabaseError("the database was made by a newer version of Potato")
            if version < SCHEMA_VERSION:
                self._migrate(version)

            result = connection.execute(_QUICK_CHECK).fetchall()
            if result != [("ok",)]:
                raise DatabaseError("the database file is damaged")
        except sqlite3.DatabaseError as error:
            # Raised by SQLite when the file is not a database at all.
            raise DatabaseError("the database file cannot be read") from error

    def _migrate(self, current: int) -> None:
        """Run each missing schema change, all in one transaction."""
        connection = self._connection
        connection.execute(_BEGIN)
        try:
            for migration in _MIGRATIONS[current:]:
                for statement in migration:
                    connection.execute(statement)
            connection.execute(_COMMIT)
        except BaseException:
            connection.execute(_ROLLBACK)
            raise

    def _read_integer(self, statement: str) -> int:
        """Run a statement that returns one integer and return it."""
        (value,) = self._connection.execute(statement).fetchone()
        if not isinstance(value, int):
            raise DatabaseError("the database returned an unexpected value")
        return value

    def _write(self, statement: str, parameters: tuple[str, ...]) -> int:
        """Run one change in its own transaction and return the rows changed."""
        connection = self._connection
        try:
            connection.execute(_BEGIN)
            try:
                cursor = connection.execute(statement, parameters)
                connection.execute(_COMMIT)
            except BaseException:
                connection.execute(_ROLLBACK)
                raise
        except sqlite3.Error as error:
            raise DatabaseError("the database could not be changed") from error
        return cursor.rowcount


def _create_private_file(path: Path) -> tuple[int, int]:
    """Create the database file if needed, check it and return its identity.

    The checks are made on the open file, as in ``private_files``. The
    identity (device and inode numbers) lets the caller confirm that SQLite
    later opens this same file.
    """
    # O_NOFOLLOW refuses a link. O_NONBLOCK stops a named pipe from making
    # the open wait forever.
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise DatabaseError("the database file could not be opened safely") from error
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise DatabaseError("the database path is not a regular file")
        if status.st_uid != os.getuid():
            raise DatabaseError("the database file belongs to another user")
        if stat.S_IMODE(status.st_mode) != 0o600:
            os.fchmod(descriptor, 0o600)
        return status.st_dev, status.st_ino
    finally:
        os.close(descriptor)


def _connect(path: Path) -> sqlite3.Connection:
    """Open the existing file with SQLite, without letting SQLite create one."""
    # mode=rw: if the file vanished since it was checked, fail instead of
    # creating a new one with default permissions.
    uri = f"{path.as_uri()}?mode=rw"
    try:
        # isolation_level=None: no hidden transactions. Each write starts and
        # ends its own transaction explicitly.
        return sqlite3.connect(uri, uri=True, isolation_level=None)
    except sqlite3.Error as error:
        raise DatabaseError("the database file could not be opened") from error


def _require_same_file(path: Path, identity: tuple[int, int]) -> None:
    """Refuse to go on if the file at ``path`` was swapped after it was checked."""
    try:
        status = path.lstat()
    except OSError as error:
        raise DatabaseError("the database file disappeared while opening") from error
    if (status.st_dev, status.st_ino) != identity or not stat.S_ISREG(status.st_mode):
        raise DatabaseError("the database file was replaced while opening")
