#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

FILES_DIR="$PROJECT_ROOT/server"

# Define the file to be removed
DB_FILE="$FILES_DIR/clients.db"

# Check if the file exists in the current directory and remove it
if [ -f "$DB_FILE" ]; then
    rm "$DB_FILE"
    echo "$DB_FILE removed."
else
    echo "$DB_FILE not found."
fi

echo "Cleanup complete."
