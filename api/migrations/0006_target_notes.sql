-- Per-target analyst notes. A single free-text field the operator can edit from
-- the target detail page to keep context, hypotheses and follow-ups.
ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS notes TEXT;
