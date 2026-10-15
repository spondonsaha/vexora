-- Open redirect findings produced by the ad-hoc "openredirect" tool. Each row is
-- one parameter/payload combination that caused (or strongly indicated) a
-- redirect to the scanner's canary host, a client-side redirect sink, a CRLF
-- header injection or a reflected redirect payload.
-- Keyed by (scope target, url, parameter, finding type, payload) so re-running
-- refreshes rather than duplicates a finding.
CREATE TABLE IF NOT EXISTS open_redirect_findings (
    id              BIGSERIAL PRIMARY KEY,
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    scan_job_id     UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    url             TEXT NOT NULL,
    parameter       TEXT NOT NULL DEFAULT '',
    payload         TEXT NOT NULL DEFAULT '',
    finding_type    TEXT NOT NULL,
    status_code     INTEGER,
    location        TEXT,
    evidence        TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_target_id, url, parameter, finding_type, payload)
);

CREATE INDEX IF NOT EXISTS open_redirect_findings_scope_target_idx ON open_redirect_findings (scope_target_id);
CREATE INDEX IF NOT EXISTS open_redirect_findings_type_idx ON open_redirect_findings (finding_type);
