PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL UNIQUE,
    target_type TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,
    FOREIGN KEY (target_id)
        REFERENCES targets(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    address_type TEXT,
    hostname TEXT,
    status TEXT,
    FOREIGN KEY (scan_id)
        REFERENCES scans(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER,
    protocol TEXT,
    state TEXT,
    service TEXT,
    product TEXT,
    version TEXT,
    FOREIGN KEY (host_id)
        REFERENCES hosts(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    confidence TEXT,
    host TEXT,
    port INTEGER,
    service TEXT,
    product TEXT,
    version TEXT,
    evidence TEXT,
    recommendation TEXT,
    FOREIGN KEY (scan_id)
        REFERENCES scans(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    score REAL NOT NULL,
    priority TEXT NOT NULL,
    exposure TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id)
        REFERENCES findings(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_target_id
    ON scans(target_id);

CREATE INDEX IF NOT EXISTS idx_hosts_scan_id
    ON hosts(scan_id);

CREATE INDEX IF NOT EXISTS idx_services_host_id
    ON services(host_id);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id
    ON findings(scan_id);

CREATE INDEX IF NOT EXISTS idx_risk_scores_finding_id
    ON risk_scores(finding_id);
