-- SSRF findings produced by the ad-hoc "ssrf" tool. Each row is one tested
-- parameter: a pre-filtered candidate (finding_type = 'candidate'), a parameter
-- confirmed exploitable via an out-of-band interaction (finding_type =
-- 'ssrf_oob') or an in-band cloud-metadata read (finding_type = 'metadata_read').
-- Keyed by (scope target, url, parameter, payload, finding type) so re-running
-- refreshes rather than duplicates a result.
CREATE TABLE IF NOT EXISTS ssrf_findings (
    id              BIGSERIAL PRIMARY KEY,
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    scan_job_id     UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    url             TEXT NOT NULL,
    parameter       TEXT NOT NULL DEFAULT '',
    payload         TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT 'GET',
    finding_type    TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'info',
    confirmed       BOOLEAN NOT NULL DEFAULT false,
    protocol        TEXT,
    remote_address  TEXT,
    evidence        TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_target_id, url, parameter, payload, finding_type)
);

CREATE INDEX IF NOT EXISTS ssrf_findings_scope_target_idx ON ssrf_findings (scope_target_id);
CREATE INDEX IF NOT EXISTS ssrf_findings_type_idx ON ssrf_findings (finding_type);
