# Encrypted Backup Server

A multi-threaded TCP backup server in Python designed to receive, decrypt, verify, and store client files securely using hybrid RSA/AES encryption and CRC32 integrity validation.

---

## Table of Contents

- [Overview](#overview)
- [Tech Stack](#tech-stack)
- [Requirements](#requirements)
- [Setup & Installation](#setup--installation)
- [Usage & Entry Points](#usage--entry-points)
- [Configuration & Environment Variables](#configuration--environment-variables)
- [Scripts](#scripts)
- [Protocol Specification](#protocol-specification)
- [Database Schema](#database-schema)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [License](#license)

---

## Overview

The Encrypted Backup Server provides a secure storage backend for client backup clients. It uses a custom binary network protocol over TCP to handle:
- **Client Registration & Re-registration:** User validation and registration state tracking.
- **Hybrid Cryptography:** Client sends an RSA public key; server generates a 256-bit AES session key, encrypts it with RSA-OAEP, and returns it to the client.
- **Encrypted Chunk Assembly:** In-memory thread-safe buffering and re-ordering of uploaded file chunks.
- **Decryption & Versioning:** Decrypts file contents using AES-CBC, stores files in dedicated user directories, and creates versioned file copies (`<filename>_v<version>.<ext>`).
- **Integrity Validation:** Computes CRC32 checksums on decrypted files and handles client confirmation or retry flows.
- **SQLite Persistence:** Tracks clients, public keys, session keys, last-seen timestamps, and uploaded file metadata.

---

## Tech Stack

- **Language:** Python 3.10+ (tested on Python 3.14)
- **Networking & Concurrency:** Python Standard Library (`socket`, `threading`, `struct`)
- **Cryptography:** [PyCryptodome](https://www.pycryptodome.org/) (AES-CBC, RSA-OAEP / PKCS#1 OAEP)
- **Database:** SQLite 3 (`sqlite3`)
- **Package Manager:** `pip` / `venv`
- **Testing Framework:** `pytest`

---

## Requirements

- Python 3.10 or higher
- `pip` package manager
- Operating System: Linux, macOS, or Windows

---

## Setup & Installation

1. **Clone or Navigate to the Server Directory:**
   ```bash
   cd server
   ```

2. **Create and Activate a Virtual Environment:**
   - On macOS/Linux:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
   - On Windows:
     ```powershell
     python -m venv .venv
     .venv\Scripts\activate
     ```

3. **Install Dependencies:**
   ```bash
   pip install pycryptodome pytest
   ```

---

## Usage & Entry Points

### Starting the Server

The main server application entry point is `main.py`:

```bash
python3 main.py
```

When started, the server:
1. Binds to `127.0.0.1:1234` (default).
2. Initializes the SQLite database (`clients.db`) if not already created.
3. Listens for incoming client TCP connections and spawns a worker thread per connected client.

---

## Configuration & Environment Variables

Currently, server configuration is defined via constants in the codebase:

| Setting | Constant / Location | Default Value | Description |
| :--- | :--- | :--- | :--- |
| **Host IP** | `ServerHandler.HOST_IP` (`handlers/server_handler.py`) | `127.0.0.1` | Network interface address to bind |
| **Host Port** | `ServerHandler.HOST_PORT` (`handlers/server_handler.py`) | `1234` | TCP port for client connections |
| **Database File** | `DB_FILE` (`storage/database.py`) | `clients.db` | SQLite database file location |
| **Max File Size** | `MAX_FILE_SIZE` (`protocol/constants.py`) | `20 MB` | Maximum allowed payload size per upload |
| **Re-registration Window** | `RE_REGISTRATION_WINDOW_DAYS` (`services/registration_service.py`) | `7 days` | Allowed duration to re-register without re-initialization |

> **TODO:** Support environment variables (e.g. `SERVER_HOST`, `SERVER_PORT`, `DATABASE_PATH`) to dynamically override default binding parameters without modifying source code.

---

## Scripts

- **`cleanup.sh`**: Helper script to remove generated server database and runtime info files.
  ```bash
  chmod +x cleanup.sh
  ./cleanup.sh
  ```
  Removes:
  - `clients.db` (SQLite database)

---

## Protocol Specification

The server communicates using a custom binary protocol with little-endian byte ordering.

### Request Format
- **User ID:** 16 bytes (Client UUID)
- **Header:**
  - `version` (uint8): Server protocol version (current: `3`)
  - `request_code` (uint16): Action requested (see Client Codes below)
  - `payload_size` (uint32): Length of the subsequent payload in bytes
- **Payload:** Variable length depending on request code (null-padded username, RSA public key, chunk metadata, file name, encrypted chunk bytes).

### Client Request Codes (`ClientCode`)
| Code | Name | Description |
| :--- | :--- | :--- |
| `100` | `REGISTRATION` | Register a new username |
| `101` | `PUBLIC_KEY_SEND` | Send RSA public key and request an encrypted AES session key |
| `102` | `RE_REGISTRATION` | Request re-registration with existing user credentials |
| `103` | `CREATE_BACKUP` | Upload an encrypted file chunk |
| `120` | `CRC_SUCCESS` | Confirm CRC32 checksum match |
| `121` | `CRC_ERROR` | Notify CRC mismatch and request/prepare retry |
| `122` | `CRC_FAILURE` | Notify persistent CRC failure and abort upload |
| `130` | `DISCONNECT` | Close client connection |

### Server Response Codes (`ServerCode`)
| Code | Name | Description |
| :--- | :--- | :--- |
| `200` | `REGISTRATION_SUCCESS` | Client registered successfully (returns assigned User ID) |
| `201` | `REGISTRATION_FAILED` | Registration failed (e.g., invalid username format) |
| `202` | `USERNAME_TAKEN` | Requested username already exists |
| `205` | `RE_REGISTRATION_SUCCESS` | Re-registration approved (returns encrypted AES session key) |
| `206` | `RE_REGISTRATION_FAILED` | Re-registration rejected or expired |
| `210` | `KEY_SEND_SUCCESS` | Public key accepted; returns RSA-encrypted AES session key |
| `220` | `UPLOAD_RECEIVED` | Chunk / file received; returns CRC32 checksum |
| `221` | `UPLOAD_REJECTED_TOO_LARGE` | Upload exceeds maximum permitted size (`20MB`) |
| `230` | `ACK` | Confirmation acknowledgement |
| `231` | `FAILED` | Generic server failure |

---

## Database Schema

The SQLite database (`clients.db`) maintains two main tables:

### `clients`
| Column | Type | Description |
| :--- | :--- | :--- |
| `user_id` | `TEXT PRIMARY KEY` | 32-character hexadecimal UUID |
| `username` | `TEXT` | Client username |
| `public_key` | `TEXT` | Base64-encoded client RSA public key (PEM format) |
| `last_seen` | `TEXT` | Last activity timestamp (UTC) |
| `aes_key` | `TEXT` | Base64-encoded AES symmetric key |

### `files`
| Column | Type | Description |
| :--- | :--- | :--- |
| `user_id` | `TEXT` | Foreign key referencing `clients(user_id)` |
| `file_name` | `TEXT` | Sanitized original file name |
| `path_name` | `TEXT` | Relative path where file is saved on disk |
| `version` | `INTEGER` | Monotonically incrementing file version number |
| `last_modified` | `TEXT` | Timestamp when file was saved |
| `verified` | `BOOLEAN` | Whether client confirmed CRC32 match (`1` = verified, `0` = pending/unverified) |

---

## Testing

The project contains a comprehensive unit and integration test suite using `pytest`.

### Running Tests

Run the test suite with:

```bash
# Run all tests
pytest

# Run tests with verbose output
pytest -v

# Run a specific test module
pytest tests/services/test_crypto.py
```

### Test Organization
- `tests/handlers/`: Tests for request dispatching, socket server handling, and backup/CRC flow logic.
- `tests/protocol/`: Tests for request decoding, response encoding, response transmission, and protocol constants.
- `tests/services/`: Tests for AES/RSA cryptography, CRC calculation, chunk assembly, registration, and session key provisioning.
- `tests/storage/`: Tests for SQLite queries, database initialization, and record updates.
- `tests/utils/`: Tests for low-level socket I/O helpers.

---

## Project Structure

```
server/
├── handlers/                     # Request dispatching & transport handlers
│   ├── __init__.py
│   ├── backup_handlers.py        # Handlers for chunk upload and CRC events
│   └── server_handler.py         # Socket listener and client thread management
├── protocol/                     # Network protocol definitions and codecs
│   ├── __init__.py
│   ├── constants.py              # Protocol opcodes, sizes, and constants
│   ├── request.py                # Request data models
│   ├── request_decoder.py        # Binary stream deserializer
│   ├── response.py               # Response data models
│   ├── response_encoder.py       # Binary response serializer
│   └── response_sender.py        # Response transmission helper
├── services/                     # Business logic and crypto layer
│   ├── __init__.py
│   ├── backup_service.py         # Chunk assembly, file persistence, versioning
│   ├── crypto.py                 # AES-CBC, RSA-OAEP, CRC32, UUID generation
│   ├── registration_service.py   # Client registration & re-registration logic
│   └── session_key_service.py    # AES key generation & RSA encryption
├── storage/                      # Persistence layer
│   ├── __init__.py
│   └── database.py               # SQLite database setup and queries
├── tests/                        # Comprehensive pytest test suite
│   ├── conftest.py               # Fixtures (temp db, temp workdir, socket pairs)
│   ├── handlers/
│   ├── protocol/
│   ├── services/
│   ├── storage/
│   └── utils/
├── utils/                        # Shared utilities
│   ├── __init__.py
│   ├── console_ui.py             # Terminal color helpers
│   └── socket_io.py              # Exact byte reading socket helper
├── cleanup.sh                    # Cleanup script for database and runtime files
├── LICENSE                       # MIT License
├── main.py                       # Server entry point
└── README.md                     # Project documentation
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
