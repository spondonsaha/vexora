-- Technology Stack Fingerprinting & WHOIS/OSINT (spec §4/§6/§9).
--
-- technologies: one normalized row per (live web server, technology, version,
-- detecting tool). The raw per-tool dump stays in live_web_servers.tech_stack,
-- while this table makes the data queryable and dedupable across tools
-- (httpx today; WhatWeb/Wappalyzer/CMSeeK/WPScan/retire.js in a later pass).
--
-- whois_records: registration/ownership data for a target's root domain. The
-- root_domain_id column links to the company-scoped root_domains table when the
-- company workflow has populated it; scope_target_id + domain make the record
-- usable for wildcard/url targets too.
CREATE TABLE IF NOT EXISTS technologies (
    id                 BIGSERIAL PRIMARY KEY,
    scope_target_id    UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    live_web_server_id UUID NOT NULL REFERENCES live_web_servers(id) ON DELETE CASCADE,
    scan_job_id        UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    name               TEXT NOT NULL,
    version            TEXT NOT NULL DEFAULT '',
    category           TEXT NOT NULL DEFAULT 'other',
    detected_by        TEXT NOT NULL,
    cve_refs           JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_target_id, live_web_server_id, name, version, detected_by)
);

CREATE INDEX IF NOT EXISTS technologies_scope_target_idx ON technologies (scope_target_id);
CREATE INDEX IF NOT EXISTS technologies_live_server_idx ON technologies (live_web_server_id);
CREATE INDEX IF NOT EXISTS technologies_category_idx ON technologies (category);

CREATE TABLE IF NOT EXISTS whois_records (
    id              BIGSERIAL PRIMARY KEY,
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    root_domain_id  UUID REFERENCES root_domains(id) ON DELETE SET NULL,
    scan_job_id     UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    domain          TEXT NOT NULL,
    registrant_org  TEXT,
    registrar       TEXT,
    registered_at   TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    nameservers     JSONB NOT NULL DEFAULT '[]'::jsonb,
    statuses        JSONB NOT NULL DEFAULT '[]'::jsonb,
    source          TEXT NOT NULL DEFAULT 'rdap',
    raw             JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_target_id, domain, source)
);

CREATE INDEX IF NOT EXISTS whois_records_scope_target_idx ON whois_records (scope_target_id);
CREATE INDEX IF NOT EXISTS whois_records_domain_idx ON whois_records (domain);
