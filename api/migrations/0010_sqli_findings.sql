-- SQL injection findings produced by the ad-hoc "sqli" (sqlmap) tool.
-- Keyed by (scope target, url, parameter, technique) so re-running refreshes
-- rather than duplicates an injection point.
CREATE TABLE IF NOT EXISTS sqli_findings (
    id              BIGSERIAL PRIMARY KEY,
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    scan_job_id     UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    url             TEXT NOT NULL,
    parameter       TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT '',
    technique       TEXT NOT NULL DEFAULT '',
    title           TEXT,
    payload         TEXT,
    dbms            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_target_id, url, parameter, technique)
);

CREATE INDEX IF NOT EXISTS sqli_findings_scope_target_idx ON sqli_findings (scope_target_id);
CREATE INDEX IF NOT EXISTS sqli_findings_url_idx ON sqli_findings (url);
