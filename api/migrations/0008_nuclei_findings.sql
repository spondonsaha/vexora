-- Nuclei vulnerability findings.
-- The nuclei ad-hoc tool runs template categories (xss, cve, takeover,
-- misconfig) against the target's live hosts / subdomains and stores one row
-- per matched (template, host). Re-running a category refreshes severity and
-- details rather than creating duplicates.

CREATE TABLE IF NOT EXISTS nuclei_findings (
    id              BIGSERIAL PRIMARY KEY,
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    scan_job_id     UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    category        TEXT NOT NULL,
    template_id     TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT 'unknown',
    type            TEXT,
    host            TEXT,
    matched_at      TEXT NOT NULL,
    description     TEXT,
    reference       JSONB NOT NULL DEFAULT '[]',
    tags            JSONB NOT NULL DEFAULT '[]',
    extracted       JSONB NOT NULL DEFAULT '[]',
    cvss_score      REAL,
    curl_command    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_target_id, template_id, matched_at)
);

CREATE INDEX IF NOT EXISTS idx_nuclei_findings_scope
    ON nuclei_findings (scope_target_id);
CREATE INDEX IF NOT EXISTS idx_nuclei_findings_severity
    ON nuclei_findings (scope_target_id, severity);
CREATE INDEX IF NOT EXISTS idx_nuclei_findings_category
    ON nuclei_findings (scope_target_id, category);
