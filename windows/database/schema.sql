CREATE TABLE IF NOT EXISTS scans (
    scan_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    duration      REAL,
    target_scope  TEXT,
    mode          TEXT,
    sensor_id     TEXT,
    profile       TEXT,
    raw_file      TEXT,
    file_hash     TEXT UNIQUE NOT NULL,
    nmap_args     TEXT,
    device_count  INTEGER DEFAULT 0,
    service_count INTEGER DEFAULT 0,
    port_count    INTEGER DEFAULT 0
);

-- Cihaz kimligi: scan'ler arasi kalici
CREATE TABLE IF NOT EXISTS devices (
    device_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    mac        TEXT UNIQUE,
    identity   TEXT NOT NULL CHECK (identity IN ('mac_confirmed','ip_only')),
    vendor     TEXT,
    hostname   TEXT,
    last_ip    TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);

-- Snapshot: her scan'de cihazin gozlemi (change detection ve replay icin)
CREATE TABLE IF NOT EXISTS scan_devices (
    scan_id   INTEGER NOT NULL REFERENCES scans(scan_id),
    device_id INTEGER NOT NULL REFERENCES devices(device_id),
    ip        TEXT NOT NULL,
    hostname  TEXT,
    status    TEXT,
    PRIMARY KEY (scan_id, device_id)
);

CREATE TABLE IF NOT EXISTS scan_services (
    scan_id      INTEGER NOT NULL REFERENCES scans(scan_id),
    device_id    INTEGER NOT NULL REFERENCES devices(device_id),
    port         INTEGER NOT NULL,
    protocol     TEXT NOT NULL,
    state        TEXT,
    service_name TEXT,
    product      TEXT,
    version      TEXT,
    PRIMARY KEY (scan_id, device_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS events (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    scan_id     INTEGER REFERENCES scans(scan_id),
    device_id   INTEGER REFERENCES devices(device_id),
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    description TEXT,
    evidence    TEXT,
    status      TEXT NOT NULL DEFAULT 'NEW'
                CHECK (status IN ('NEW','INVESTIGATING','RESOLVED','IGNORED'))
);

CREATE TABLE IF NOT EXISTS risk_scores (
    scan_id   INTEGER NOT NULL REFERENCES scans(scan_id),
    device_id INTEGER NOT NULL REFERENCES devices(device_id),
    score     INTEGER NOT NULL,
    level     TEXT    NOT NULL,
    factors   TEXT,
    timestamp TEXT    NOT NULL,
    PRIMARY KEY (scan_id, device_id)
);