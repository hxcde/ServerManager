import json
import sqlite3
import time
from pathlib import Path

from argon2 import PasswordHasher


class Database:
    def __init__(
        self,
        path: str,
        password_hasher: PasswordHasher,
        bootstrap_username: str,
        bootstrap_password: str,
    ) -> None:
        database_path = Path(path)
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(database_path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.password_hasher = password_hasher
        self._create_schema()
        self._bootstrap_admin(bootstrap_username, bootstrap_password)

    def close(self) -> None:
        self.connection.close()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                totp_secret TEXT,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS passkeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                credential_id BLOB NOT NULL UNIQUE,
                public_key BLOB NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                transports TEXT NOT NULL DEFAULT '[]',
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS connection_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                host TEXT NOT NULL COLLATE NOCASE,
                port INTEGER NOT NULL,
                username TEXT NOT NULL COLLATE NOCASE,
                domain TEXT NOT NULL COLLATE NOCASE DEFAULT '',
                resolution TEXT NOT NULL,
                admin INTEGER NOT NULL DEFAULT 0,
                clipboard INTEGER NOT NULL DEFAULT 1,
                ignore_certificate INTEGER NOT NULL DEFAULT 0,
                last_used INTEGER NOT NULL,
                UNIQUE(user_id, host, port, username, domain)
            );
            """
        )
        self.connection.commit()

    def _bootstrap_admin(self, username: str, password: str) -> None:
        count = self.connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count:
            return
        self.create_user(
            username=username,
            display_name=username,
            password=password,
            is_admin=True,
        )

    @staticmethod
    def _public_user(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "username": row["username"],
            "displayName": row["display_name"],
            "isAdmin": bool(row["is_admin"]),
            "enabled": bool(row["enabled"]),
            "totpEnabled": bool(row["totp_enabled"]),
            "createdAt": row["created_at"],
        }

    def get_user_by_username(self, username: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()

    def get_user(self, user_id: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    def public_user(self, user_id: int) -> dict | None:
        row = self.get_user(user_id)
        return self._public_user(row) if row else None

    def list_users(self) -> list[dict]:
        rows = self.connection.execute(
            """
            SELECT users.*, COUNT(passkeys.id) AS passkey_count
            FROM users
            LEFT JOIN passkeys ON passkeys.user_id = users.id
            GROUP BY users.id
            ORDER BY users.username COLLATE NOCASE
            """
        ).fetchall()
        users = []
        for row in rows:
            user = self._public_user(row)
            user["passkeyCount"] = row["passkey_count"]
            users.append(user)
        return users

    def create_user(
        self,
        username: str,
        display_name: str,
        password: str,
        is_admin: bool,
    ) -> dict:
        now = int(time.time())
        cursor = self.connection.execute(
            """
            INSERT INTO users (
                username, display_name, password_hash, is_admin, enabled, created_at
            ) VALUES (?, ?, ?, ?, 1, ?)
            """,
            (
                username,
                display_name,
                self.password_hasher.hash(password),
                int(is_admin),
                now,
            ),
        )
        self.connection.commit()
        return self.public_user(cursor.lastrowid)

    def update_user(
        self,
        user_id: int,
        display_name: str,
        enabled: bool,
        is_admin: bool,
        password: str | None = None,
    ) -> dict | None:
        if password:
            self.connection.execute(
                """
                UPDATE users
                SET display_name = ?, enabled = ?, is_admin = ?, password_hash = ?
                WHERE id = ?
                """,
                (
                    display_name,
                    int(enabled),
                    int(is_admin),
                    self.password_hasher.hash(password),
                    user_id,
                ),
            )
        else:
            self.connection.execute(
                """
                UPDATE users
                SET display_name = ?, enabled = ?, is_admin = ?
                WHERE id = ?
                """,
                (display_name, int(enabled), int(is_admin), user_id),
            )
        self.connection.commit()
        return self.public_user(user_id)

    def update_password(self, user_id: int, password: str) -> None:
        self.connection.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (self.password_hasher.hash(password), user_id),
        )
        self.connection.commit()

    def delete_user(self, user_id: int) -> bool:
        cursor = self.connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
        self.connection.commit()
        return bool(cursor.rowcount)

    def enabled_admin_count(self) -> int:
        return self.connection.execute(
            "SELECT COUNT(*) FROM users WHERE enabled = 1 AND is_admin = 1"
        ).fetchone()[0]

    def set_totp(self, user_id: int, secret: str | None, enabled: bool) -> None:
        self.connection.execute(
            "UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE id = ?",
            (secret, int(enabled), user_id),
        )
        self.connection.commit()

    def list_passkeys(self, user_id: int) -> list[dict]:
        rows = self.connection.execute(
            """
            SELECT id, name, transports, created_at
            FROM passkeys
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (user_id,),
        ).fetchall()
        return [
            {
                "id": row["id"],
                "name": row["name"],
                "transports": json.loads(row["transports"]),
                "createdAt": row["created_at"],
            }
            for row in rows
        ]

    def passkey_descriptors(self, user_id: int) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT credential_id, transports FROM passkeys WHERE user_id = ?",
            (user_id,),
        ).fetchall()

    def add_passkey(
        self,
        user_id: int,
        name: str,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: list[str],
    ) -> dict:
        cursor = self.connection.execute(
            """
            INSERT INTO passkeys (
                user_id, name, credential_id, public_key, sign_count, transports, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                name,
                credential_id,
                public_key,
                sign_count,
                json.dumps(transports),
                int(time.time()),
            ),
        )
        self.connection.commit()
        return next(
            passkey
            for passkey in self.list_passkeys(user_id)
            if passkey["id"] == cursor.lastrowid
        )

    def get_passkey(self, user_id: int, credential_id: bytes) -> sqlite3.Row | None:
        return self.connection.execute(
            """
            SELECT * FROM passkeys
            WHERE user_id = ? AND credential_id = ?
            """,
            (user_id, credential_id),
        ).fetchone()

    def delete_passkey(self, user_id: int, passkey_id: int) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM passkeys WHERE id = ? AND user_id = ?",
            (passkey_id, user_id),
        )
        self.connection.commit()
        return bool(cursor.rowcount)

    def update_passkey_counter(self, passkey_id: int, sign_count: int) -> None:
        self.connection.execute(
            "UPDATE passkeys SET sign_count = ? WHERE id = ?",
            (sign_count, passkey_id),
        )
        self.connection.commit()

    def list_domains(self) -> list[dict]:
        rows = self.connection.execute(
            "SELECT id, name, created_at FROM domains ORDER BY name COLLATE NOCASE"
        ).fetchall()
        return [
            {"id": row["id"], "name": row["name"], "createdAt": row["created_at"]}
            for row in rows
        ]

    def add_domain(self, name: str) -> dict:
        cursor = self.connection.execute(
            "INSERT INTO domains (name, created_at) VALUES (?, ?)",
            (name, int(time.time())),
        )
        self.connection.commit()
        row = self.connection.execute(
            "SELECT id, name, created_at FROM domains WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        return {"id": row["id"], "name": row["name"], "createdAt": row["created_at"]}

    def delete_domain(self, domain_id: int) -> bool:
        cursor = self.connection.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
        self.connection.commit()
        return bool(cursor.rowcount)

    def domain_exists(self, name: str) -> bool:
        if not name:
            return True
        return bool(
            self.connection.execute(
                "SELECT 1 FROM domains WHERE name = ? COLLATE NOCASE",
                (name,),
            ).fetchone()
        )

    def list_history(self, user_id: int, limit: int = 12) -> list[dict]:
        rows = self.connection.execute(
            """
            SELECT * FROM connection_history
            WHERE user_id = ?
            ORDER BY last_used DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
        return [self._history_entry(row) for row in rows]

    def save_history(self, user_id: int, connection: dict) -> None:
        self.connection.execute(
            """
            INSERT INTO connection_history (
                user_id, host, port, username, domain, resolution,
                admin, clipboard, ignore_certificate, last_used
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, host, port, username, domain) DO UPDATE SET
                resolution = excluded.resolution,
                admin = excluded.admin,
                clipboard = excluded.clipboard,
                ignore_certificate = excluded.ignore_certificate,
                last_used = excluded.last_used
            """,
            (
                user_id,
                connection["host"],
                connection["port"],
                connection["username"],
                connection["domain"],
                f"{connection['resolution'][0]}x{connection['resolution'][1]}",
                int(connection["admin"]),
                int(connection["clipboard"]),
                int(connection["ignore_certificate"]),
                int(time.time()),
            ),
        )
        self.connection.commit()

    def delete_history(self, user_id: int, history_id: int) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM connection_history WHERE id = ? AND user_id = ?",
            (history_id, user_id),
        )
        self.connection.commit()
        return bool(cursor.rowcount)

    @staticmethod
    def _history_entry(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "host": row["host"],
            "port": row["port"],
            "username": row["username"],
            "domain": row["domain"],
            "resolution": row["resolution"],
            "admin": bool(row["admin"]),
            "clipboard": bool(row["clipboard"]),
            "ignoreCertificate": bool(row["ignore_certificate"]),
            "lastUsed": row["last_used"],
        }
