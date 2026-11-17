import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vault.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)
    c.execute("""
        CREATE TABLE vault_secrets (
            id INTEGER PRIMARY KEY,
            label TEXT NOT NULL,
            value TEXT NOT NULL
        )
    """)

    c.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("alice", "sunshine123", "user"),
            ("bob", "footballfan22", "user"),
            ("administrator", "n0t_th3_fl4g_7h1s_1s_j7st_th3_p4ssw0rd", "admin"),
        ],
    )

    c.execute(
        "INSERT INTO vault_secrets (label, value) VALUES (?, ?)",
        ("root_flag", "FLAG{bl1nd_b00l34n_sq1i_wh15p3rs_tru7h}"),
    )

    conn.commit()
    conn.close()
