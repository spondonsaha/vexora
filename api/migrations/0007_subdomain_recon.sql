-- Subdomain CNAME resolution, reverse-DNS (PTR) and subdomain-takeover checks.
-- The takeover workflow step resolves each already-discovered subdomain's CNAME
-- chain, records A/AAAA addresses and the reverse-DNS (PTR) names for those
-- addresses, then matches the chain against a fingerprint database of
-- known-vulnerable SaaS services. Results are cached back onto the subdomain so
-- the UI can render them without re-running DNS.

ALTER TABLE subdomains
    ADD COLUMN IF NOT EXISTS cname TEXT;
ALTER TABLE subdomains
    ADD COLUMN IF NOT EXISTS cname_chain TEXT[] DEFAULT '{}';
ALTER TABLE subdomains
    ADD COLUMN IF NOT EXISTS a_records TEXT[] DEFAULT '{}';
ALTER TABLE subdomains
    ADD COLUMN IF NOT EXISTS reverse_dns TEXT[] DEFAULT '{}';
ALTER TABLE subdomains
    ADD COLUMN IF NOT EXISTS takeover_status TEXT;
ALTER TABLE subdomains
    ADD COLUMN IF NOT EXISTS takeover_service TEXT;
ALTER TABLE subdomains
    ADD COLUMN IF NOT EXISTS takeover_detail TEXT;
ALTER TABLE subdomains
    ADD COLUMN IF NOT EXISTS dns_checked_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_subdomains_takeover_status
    ON subdomains (takeover_status)
    WHERE takeover_status IS NOT NULL AND takeover_status <> 'safe';
