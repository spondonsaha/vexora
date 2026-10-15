-- Network reconnaissance: open ports and detected services.
-- The netscan ad-hoc tool resolves every discovered subdomain (dnsx), port
-- scans the unique IPs (naabu) and fingerprints the open services (nmap -sV).
-- One row per (ip, port, protocol); re-running refreshes the service details
-- and the set of hostnames that currently resolve to the IP.
--
-- IP inventory (which subdomain resolves to which IP, plus reverse DNS) is kept
-- on the subdomains table (a_records / reverse_dns) so both views stay in sync.

CREATE TABLE IF NOT EXISTS network_services (
    id              BIGSERIAL PRIMARY KEY,
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    scan_job_id     UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    ip              TEXT NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT NOT NULL DEFAULT 'tcp',
    state           TEXT NOT NULL DEFAULT 'open',
    tls             BOOLEAN NOT NULL DEFAULT FALSE,
    service         TEXT,
    product         TEXT,
    version         TEXT,
    banner          TEXT,
    hosts           TEXT[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_target_id, ip, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_network_services_scope
    ON network_services (scope_target_id);
CREATE INDEX IF NOT EXISTS idx_network_services_ip
    ON network_services (scope_target_id, ip);
CREATE INDEX IF NOT EXISTS idx_network_services_port
    ON network_services (scope_target_id, port);
