-- Milestone 4: URL discovery (gau, waybackurls, katana).
-- Historical/crawled URLs are stored in `endpoints`. Those that map to a live
-- web server stay linked; domain-wide URLs (host not currently serving HTTP)
-- are still kept with a nullable live_web_server_id plus the owning wildcard
-- target, their host and the full URL. An `interesting` flag highlights URLs
-- worth manual review (backups, configs, secrets, parameterised endpoints).

ALTER TABLE endpoints ALTER COLUMN live_web_server_id DROP NOT NULL;
ALTER TABLE endpoints
    ADD COLUMN IF NOT EXISTS wildcard_target_id UUID REFERENCES wildcard_targets(id) ON DELETE CASCADE;
ALTER TABLE endpoints
    ADD COLUMN IF NOT EXISTS host TEXT;
ALTER TABLE endpoints
    ADD COLUMN IF NOT EXISTS url TEXT;
ALTER TABLE endpoints
    ADD COLUMN IF NOT EXISTS interesting BOOLEAN NOT NULL DEFAULT FALSE;

CREATE UNIQUE INDEX IF NOT EXISTS uq_endpoints_url ON endpoints (url) WHERE url IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_endpoints_wildcard ON endpoints (wildcard_target_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_interesting ON endpoints (wildcard_target_id) WHERE interesting;

-- Allow the new URL sources in source_tool.
ALTER TABLE endpoints DROP CONSTRAINT IF EXISTS endpoints_source_tool_check;
ALTER TABLE endpoints ADD CONSTRAINT endpoints_source_tool_check
    CHECK (source_tool IN ('ffuf', 'feroxbuster', 'katana', 'gospider', 'gau', 'waybackurls', 'other'));
