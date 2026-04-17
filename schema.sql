-- RepoScan scans.db schema
-- Source of truth for reposcan_ui.py init_db bootstrap.
-- Edit here and restart --ui to apply; existing DBs are NOT auto-migrated.

CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target         TEXT    NOT NULL,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    score          INTEGER NOT NULL,
    verdict        TEXT    NOT NULL,
    verdict_class  TEXT    NOT NULL,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count     INTEGER NOT NULL DEFAULT 0,
    medium_count   INTEGER NOT NULL DEFAULT 0,
    low_count      INTEGER NOT NULL DEFAULT 0,
    info_count     INTEGER NOT NULL DEFAULT 0,
    pass_count     INTEGER NOT NULL DEFAULT 0,
    findings_json  TEXT    NOT NULL,
    full_output    TEXT    NOT NULL,
    rate_limit_hit INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dismissed_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT    NOT NULL,
    finding_hash  TEXT    NOT NULL,
    reason        TEXT,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(target, finding_hash)
);

CREATE INDEX IF NOT EXISTS idx_scans_target     ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_created    ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dismissed_target ON dismissed_findings(target);
