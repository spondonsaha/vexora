-- Domain & DNS security audit workflow (§7-style section). Adds a new workflow
-- type alongside company/wildcard/url.
ALTER TABLE workflows DROP CONSTRAINT IF EXISTS workflows_workflow_type_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_workflow_type_check
    CHECK (workflow_type IN ('company', 'wildcard', 'url', 'domain'));
