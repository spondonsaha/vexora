-- Milestone 3: wildcard workflow (enum -> scrape -> consolidate/live-probe).
-- Adds a workflow run + per-step status model (§7, §10, §11) and links the
-- existing scan_jobs rows to the workflow step / tool invocation that produced them.

CREATE TABLE IF NOT EXISTS workflows (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    workflow_type   TEXT NOT NULL CHECK (workflow_type IN ('company', 'wildcard', 'url')),
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'done', 'failed', 'cancelled')),
    current_step    INTEGER NOT NULL DEFAULT 0,
    error           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_workflows_scope ON workflows (scope_target_id);
CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows (status);

CREATE TABLE IF NOT EXISTS workflow_steps (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id  UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    step_number  INTEGER NOT NULL,
    step_key     TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT,
    status       TEXT NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued', 'running', 'done', 'failed', 'cancelled')),
    summary      JSONB DEFAULT '{}'::jsonb,
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workflow_id, step_number)
);
CREATE INDEX IF NOT EXISTS idx_workflow_steps_workflow ON workflow_steps (workflow_id);

ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS workflow_id UUID REFERENCES workflows(id) ON DELETE SET NULL;
ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS workflow_step_id UUID REFERENCES workflow_steps(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_scan_jobs_workflow ON scan_jobs (workflow_id);
