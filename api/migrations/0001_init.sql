-- Vexora initial schema (§4, §16).
-- Runs automatically on API startup via the embedded migration runner.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Scope (§3, §5, §14)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scope_targets (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type           TEXT NOT NULL CHECK (type IN ('company', 'wildcard', 'url')),
    value          TEXT NOT NULL,
    description    TEXT,
    auth_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    active         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_scope_targets_type_value
    ON scope_targets (type, lower(value));

CREATE TABLE IF NOT EXISTS companies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_companies_scope_target ON companies (scope_target_id);

CREATE TABLE IF NOT EXISTS network_ranges (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    asn        TEXT,
    cidr       TEXT,
    source_tool TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_network_ranges_company ON network_ranges (company_id);

CREATE TABLE IF NOT EXISTS root_domains (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    domain     TEXT NOT NULL,
    source     TEXT CHECK (source IN ('dork', 'crt', 'whois', 'securitytrails', 'shodan', 'censys', 'github', 'other')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (company_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_root_domains_company ON root_domains (company_id);

CREATE TABLE IF NOT EXISTS wildcard_targets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    root_domain     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_target_id, root_domain)
);
CREATE INDEX IF NOT EXISTS idx_wildcard_targets_scope ON wildcard_targets (scope_target_id);

CREATE TABLE IF NOT EXISTS subdomains (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wildcard_target_id UUID NOT NULL REFERENCES wildcard_targets(id) ON DELETE CASCADE,
    subdomain          TEXT NOT NULL,
    source_tool        TEXT,
    first_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (wildcard_target_id, subdomain)
);
CREATE INDEX IF NOT EXISTS idx_subdomains_wildcard ON subdomains (wildcard_target_id);

CREATE TABLE IF NOT EXISTS dns_records (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subdomain_id UUID NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    record_type  TEXT NOT NULL,
    value        TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_dns_records_subdomain ON dns_records (subdomain_id);

-- ---------------------------------------------------------------------------
-- Live surface
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS live_web_servers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subdomain_id    UUID REFERENCES subdomains(id) ON DELETE CASCADE,
    ip              INET,
    url             TEXT NOT NULL,
    status_code     INTEGER,
    title           TEXT,
    content_length  BIGINT,
    tech_stack      JSONB DEFAULT '[]'::jsonb,
    headers         JSONB DEFAULT '{}'::jsonb,
    tls             JSONB DEFAULT '{}'::jsonb,
    screenshot_path TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (url)
);
CREATE INDEX IF NOT EXISTS idx_live_web_servers_subdomain ON live_web_servers (subdomain_id);

CREATE TABLE IF NOT EXISTS dorks_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
    dork_type       TEXT NOT NULL CHECK (dork_type IN ('google', 'github')),
    query           TEXT NOT NULL,
    result_url      TEXT,
    snippet         TEXT,
    reviewed        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_dorks_results_scope ON dorks_results (scope_target_id);

-- ---------------------------------------------------------------------------
-- Endpoints / parameters
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS endpoints (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    live_web_server_id UUID NOT NULL REFERENCES live_web_servers(id) ON DELETE CASCADE,
    path               TEXT NOT NULL,
    status_code        INTEGER,
    content_length     BIGINT,
    source_tool        TEXT CHECK (source_tool IN ('ffuf', 'feroxbuster', 'katana', 'gospider', 'gau', 'waybackurls', 'other')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (live_web_server_id, path)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_lws ON endpoints (live_web_server_id);

CREATE TABLE IF NOT EXISTS parameters (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    source_tool TEXT CHECK (source_tool IN ('arjun', 'x8', 'other')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_parameters_endpoint ON parameters (endpoint_id);

-- ---------------------------------------------------------------------------
-- Findings / ROI / jobs
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    vuln_class      TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    tool            TEXT,
    title           TEXT,
    raw_output      TEXT,
    status          TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'triaged', 'reported', 'fp')),
    evidence        JSONB DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_scope ON findings (scope_target_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (status);

CREATE TABLE IF NOT EXISTS roi_scores (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    live_web_server_id UUID NOT NULL REFERENCES live_web_servers(id) ON DELETE CASCADE,
    score              INTEGER NOT NULL DEFAULT 0,
    breakdown          JSONB DEFAULT '[]'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (live_web_server_id)
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    tool            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed', 'cancelled')),
    options         JSONB DEFAULT '{}'::jsonb,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    stdout_path     TEXT,
    stderr_path     TEXT,
    exit_code       INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_scope ON scan_jobs (scope_target_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs (status);

-- ---------------------------------------------------------------------------
-- Settings / knowledge base / audit
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service       TEXT NOT NULL UNIQUE,
    encrypted_key TEXT,
    value         JSONB DEFAULT '{}'::jsonb,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS knowledge_base (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source    TEXT NOT NULL,
    category  TEXT NOT NULL,
    content   TEXT NOT NULL,
    tags      TEXT[] DEFAULT '{}',
    synced_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_knowledge_base_category ON knowledge_base (category);
CREATE INDEX IF NOT EXISTS idx_knowledge_base_tags ON knowledge_base USING GIN (tags);

CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    scope_target_id UUID REFERENCES scope_targets(id) ON DELETE SET NULL,
    scan_job_id     UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    target          TEXT,
    tool            TEXT,
    action          TEXT NOT NULL,
    detail          JSONB DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_log_scope ON audit_log (scope_target_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log (created_at);
