-- Milestone 4 follow-up: endpoints are now keyed by full URL (uq_endpoints_url).
-- The legacy UNIQUE (live_web_server_id, path) blocks domain-level URLs that
-- share a path on the same live server, so drop it.
ALTER TABLE endpoints DROP CONSTRAINT IF EXISTS endpoints_live_web_server_id_path_key;
