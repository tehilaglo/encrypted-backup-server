"""
Filesystem path constants for the encrypted backup server.

This module centralizes file names and path locations used by the server,
including the shared server configuration file and the SQLite database file.

@author Tehila Cahnaman
"""

from pathlib import Path


#: Name of the JSON configuration file used to share server connection details.
SRV_CONFIG_FILE: str = "server_config.json"

#: Absolute path to the server configuration file.
# The file is stored one directory above the current working directory so it can
# be shared with the client-side project layout.
CONFIG_FILE_PATH: Path = Path.cwd().parent / SRV_CONFIG_FILE

#: Name of the SQLite database file used to store registered clients and files.
DB_FILE: str = "clients.db"
