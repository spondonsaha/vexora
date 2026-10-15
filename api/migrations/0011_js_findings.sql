-- JavaScript reconnaissance findings extracted from JS assets collected during
-- URL discovery (katana -jc / gau / waybackurls) for the ad-hoc "jsrecon" tool.
-- Keyed by (scope target, js url, finding type, value) so re-running refreshes
-- rather than duplicates a finding.
CREATE TABLE IF NOT EXISTS js_findings (
    id              BIGSERIAL PRIMARY KEY,
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    scan_job_id     UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    js_url          TEXT NOT NULL,
    host            TEXT,
    finding_type    TEXT NOT NULL,
    value           TEXT NOT NULL,
    context         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_target_id, js_url, finding_type, value)
);

CREATE INDEX IF NOT EXISTS js_findings_scope_target_idx ON js_findings (scope_target_id);
CREATE INDEX IF NOT EXISTS js_findings_type_idx ON js_findings (finding_type);
