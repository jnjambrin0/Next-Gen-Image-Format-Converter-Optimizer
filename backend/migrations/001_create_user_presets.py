"""Create user_presets table migration."""

import sqlite3
import os
from datetime import datetime


def up(db_path: str = "./data/presets.db"):
    """Create the user_presets table."""
    # Ensure data directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create the user_presets table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS user_presets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            settings TEXT NOT NULL,
            is_builtin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )

    # Create unique index on name
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_preset_name ON user_presets(name)
    """
    )

    # Create index on is_builtin
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_presets_builtin ON user_presets(is_builtin)
    """
    )

    conn.commit()
    conn.close()
    print(f"Created user_presets table in {db_path}")


def down(db_path: str = "./data/presets.db"):
    """Drop the user_presets table."""
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS user_presets")

    conn.commit()
    conn.close()
    print(f"Dropped user_presets table from {db_path}")


if __name__ == "__main__":
    # Run the migration
    up()
