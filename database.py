import sqlite3
from typing import List, Dict, Optional, Tuple


class Database:
    def __init__(self, path: str = "data/passwords.db"):
        self.path = path
        self._ensure_schema()

    def _connect(self):
        return sqlite3.connect(self.path)

    def _ensure_schema(self):
        with self._connect() as conn:
            cur = conn.cursor()
            # Таблица мастер-пароля
            cur.execute("""
                CREATE TABLE IF NOT EXISTS master (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    password_hash TEXT NOT NULL,
                    salt BLOB NOT NULL
                );
            """)
            # Таблица паролей
            cur.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    login TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL
                );
            """)
            # Таблица настроек (для 2FA и других опций)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
            """)
            conn.commit()

    # ---- Мастер-пароль ----
    def master_password_exists(self) -> bool:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM master WHERE id=1;")
            count = cur.fetchone()[0]
        return count == 1

    def set_master_password(self, password_hash: str, salt: bytes):
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM master;")
            cur.execute(
                "INSERT INTO master (id, password_hash, salt) VALUES (1, ?, ?);",
                (password_hash, sqlite3.Binary(salt)),
            )
            conn.commit()

    def get_master_record(self) -> Optional[Tuple[str, bytes]]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT password_hash, salt FROM master WHERE id=1;")
            row = cur.fetchone()
            if row is None:
                return None
            password_hash, salt = row
            return password_hash, salt

    # ---- Пароли ----
    def add_entry(self, service: str, login: str, encrypted_password: str):
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO passwords (service, login, encrypted_password) VALUES (?, ?, ?);",
                (service, login, encrypted_password),
            )
            conn.commit()

    def get_entries(self) -> List[Dict]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, service, login, encrypted_password FROM passwords ORDER BY id DESC;")
            rows = cur.fetchall()
        return [
            {"id": r[0], "service": r[1], "login": r[2], "password": r[3]}
            for r in rows
        ]

    def get_entry(self, entry_id: int) -> Optional[Dict]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, service, login, encrypted_password FROM passwords WHERE id=?;", (entry_id,))
            row = cur.fetchone()
        if row:
            return {"id": row[0], "service": row[1], "login": row[2], "password": row[3]}
        return None

    def delete_entry(self, entry_id: int):
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM passwords WHERE id=?;", (entry_id,))
            conn.commit()

    def update_entry(self, entry_id: int, service: str, login: str, encrypted_password: str):
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE passwords SET service=?, login=?, encrypted_password=? WHERE id=?;",
                (service, login, encrypted_password, entry_id),
            )
            conn.commit()

    # ---- Поиск ----
    def search_entries(self, query: str) -> List[Dict]:
        q = f"%{query.lower()}%"
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, service, login, encrypted_password
                FROM passwords
                WHERE LOWER(service) LIKE ? OR LOWER(login) LIKE ?
                ORDER BY id DESC;
            """, (q, q))
            rows = cur.fetchall()
        return [
            {"id": r[0], "service": r[1], "login": r[2], "password": r[3]}
            for r in rows
        ]

    # ---- Статистика ----
    def get_stats(self) -> Dict:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM passwords;")
            total = cur.fetchone()[0]

            cur.execute("SELECT MAX(id) FROM passwords;")
            last_id = cur.fetchone()[0]

            cur.execute("""
                SELECT service, COUNT(*) as cnt
                FROM passwords
                GROUP BY service
                ORDER BY cnt DESC
                LIMIT 1;
            """)
            top = cur.fetchone()
        return {
            "total": total,
            "last_id": last_id or 0,
            "top_service": top[0] if top else None,
            "top_count": top[1] if top else 0
        }

    # ---- 2FA ----
    def save_2fa_secret(self, secret: str):
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("2fa_secret", secret))
            conn.commit()

    def get_2fa_secret(self) -> Optional[str]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT value FROM settings WHERE key=?", ("2fa_secret",))
            row = cur.fetchone()
            return row[0] if row else None
