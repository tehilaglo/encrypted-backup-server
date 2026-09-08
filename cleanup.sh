#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

FILES_DIR="$PROJECT_ROOT/server"

# Define the file to be removed
DB_FILE="$FILES_DIR/clients.db"
SRV_INFO="$FILES_DIR/server.info"
PORT_INFO="$FILES_DIR/port.info"

# Check if the file exists in the current directory and remove it
if [ -f "$DB_FILE" ]; then
    rm "$DB_FILE"
    echo "$DB_FILE removed."
else
    echo "$DB_FILE not found."
fi

if [ -f "$SRV_INFO" ]; then
    rm "$SRV_INFO"
    echo "$SRV_INFO removed."
else
    echo "$SRV_INFO not found."
fi

if [ -f "$PORT_INFO" ]; then
    rm "$PORT_INFO"
    echo "$PORT_INFO removed."
else
    echo "$PORT_INFO not found."
fi

echo "Cleanup complete."
