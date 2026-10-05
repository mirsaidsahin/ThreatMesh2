import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "data" / "threatmesh.db"
SCHEMA_PATH = Path(__file__).with_name("schema.sql")

_MIGRATIONS = {
    "scans":   {"has_service_data": "INTEGER DEFAULT 0",
                "analyzed_at":      "TEXT"},
    "devices": {"role":             "TEXT"},
    "events":  {"finding_key":      "TEXT",
                "expectation":      "TEXT",
                "risk_points":      "INTEGER DEFAULT 0",
                "finding_json":     "TEXT"},
}


def connect(path=DB_PATH):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _migrate(conn):
    for table, cols in _MIGRATIONS.items():
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in cols.items():
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    # V1 verisi: servis taramasi olan scan'leri isaretle
    conn.execute(
        "UPDATE scans SET has_service_data = 1 "
        "WHERE has_service_data = 0 AND nmap_args LIKE '% -sV%'"
    )


def init_db(conn):
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    _migrate(conn)
    conn.commit()