"""Local storage: the settings file and the SQLite database.

Boundary: parameterised queries only, and no secrets. Credentials belong in
the macOS Keychain, never in the database or the settings file.

So far: ``settings_file``, which reads the optional settings file safely,
and ``database``, which holds the portfolio holdings.
"""
