package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
)

// JSFindingRow is a single JavaScript artifact to persist.
type JSFindingRow struct {
	JSURL       string
	Host        string
	FindingType string
	Value       string
	Context     string
}

// UpsertJSFindings stores jsrecon findings for a scope target keyed by
// (js url, finding type, value) so re-running refreshes rather than duplicates
// a finding.
func (s *PGStore) UpsertJSFindings(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []JSFindingRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	// Collapse duplicate (js_url, finding_type, value) rows within a single
	// batch so one INSERT ... ON CONFLICT statement never touches the same row
	// twice (SQLSTATE 21000).
	index := make(map[string]int, len(rows))
	deduped := make([]JSFindingRow, 0, len(rows))
	for _, r := range rows {
		key := r.JSURL + "\x00" + r.FindingType + "\x00" + r.Value
		if i, ok := index[key]; ok {
			if deduped[i].Context == "" {
				deduped[i].Context = r.Context
			}
			continue
		}
		index[key] = len(deduped)
		deduped = append(deduped, r)
	}

	payload := make([]map[string]any, 0, len(deduped))
	for _, r := range deduped {
		payload = append(payload, map[string]any{
			"js_url":       r.JSURL,
			"host":         nullIfEmpty(r.Host),
			"finding_type": r.FindingType,
			"value":        r.Value,
			"context":      nullIfEmpty(r.Context),
		})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	tag, err := s.pool.Exec(ctx,
		`INSERT INTO js_findings
		     (scope_target_id, scan_job_id, js_url, host, finding_type, value, context)
		 SELECT $2, $3, v.js_url, v.host, v.finding_type, v.value, v.context
		 FROM jsonb_to_recordset($1::jsonb) AS v(
		     js_url text, host text, finding_type text, value text, context text
		 )
		 ON CONFLICT (scope_target_id, js_url, finding_type, value) DO UPDATE SET
		     scan_job_id = EXCLUDED.scan_job_id,
		     host        = EXCLUDED.host,
		     context     = EXCLUDED.context,
		     updated_at  = now()`,
		string(encoded), scopeTargetID, scanJobID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *PGStore) ListJSFindingsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.JSFinding, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, scope_target_id, scan_job_id, js_url, COALESCE(host, ''),
		        finding_type, value, COALESCE(context, ''), created_at, updated_at
		 FROM js_findings
		 WHERE scope_target_id = $1
		 ORDER BY finding_type, value`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	findings := make([]models.JSFinding, 0)
	for rows.Next() {
		var f models.JSFinding
		if err := rows.Scan(&f.ID, &f.ScopeTargetID, &f.ScanJobID, &f.JSURL, &f.Host,
			&f.FindingType, &f.Value, &f.Context, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}
