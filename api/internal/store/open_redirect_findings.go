package store

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
)

// stripNul removes NUL bytes (\x00), which Postgres text/jsonb columns reject
// with "unsupported Unicode escape sequence" (SQLSTATE 22P05). Redirect probes
// can legitimately surface NUL from %00 payloads.
func stripNul(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

// OpenRedirectFindingRow is a single open-redirect issue to persist.
type OpenRedirectFindingRow struct {
	URL         string
	Parameter   string
	Payload     string
	FindingType string
	StatusCode  int
	Location    string
	Evidence    string
}

// UpsertOpenRedirectFindings stores openredirect findings for a scope target
// keyed by (url, parameter, finding type, payload) so re-running refreshes
// rather than duplicates a finding.
func (s *PGStore) UpsertOpenRedirectFindings(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []OpenRedirectFindingRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	// Collapse duplicate keys within a single batch so one INSERT ... ON
	// CONFLICT statement never touches the same row twice (SQLSTATE 21000).
	index := make(map[string]int, len(rows))
	deduped := make([]OpenRedirectFindingRow, 0, len(rows))
	for _, r := range rows {
		key := r.URL + "\x00" + r.Parameter + "\x00" + r.FindingType + "\x00" + r.Payload
		if i, ok := index[key]; ok {
			if deduped[i].Evidence == "" {
				deduped[i].Evidence = r.Evidence
			}
			continue
		}
		index[key] = len(deduped)
		deduped = append(deduped, r)
	}

	payload := make([]map[string]any, 0, len(deduped))
	for _, r := range deduped {
		var status any
		if r.StatusCode > 0 {
			status = r.StatusCode
		}
		payload = append(payload, map[string]any{
			"url":          stripNul(r.URL),
			"parameter":    stripNul(r.Parameter),
			"payload":      stripNul(r.Payload),
			"finding_type": stripNul(r.FindingType),
			"status_code":  status,
			"location":     nullIfEmpty(stripNul(r.Location)),
			"evidence":     nullIfEmpty(stripNul(r.Evidence)),
		})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	tag, err := s.pool.Exec(ctx,
		`INSERT INTO open_redirect_findings
		     (scope_target_id, scan_job_id, url, parameter, payload, finding_type, status_code, location, evidence)
		 SELECT $2, $3, v.url, v.parameter, v.payload, v.finding_type, v.status_code, v.location, v.evidence
		 FROM jsonb_to_recordset($1::jsonb) AS v(
		     url text, parameter text, payload text, finding_type text,
		     status_code integer, location text, evidence text
		 )
		 ON CONFLICT (scope_target_id, url, parameter, finding_type, payload) DO UPDATE SET
		     scan_job_id = EXCLUDED.scan_job_id,
		     status_code = EXCLUDED.status_code,
		     location    = EXCLUDED.location,
		     evidence    = EXCLUDED.evidence,
		     updated_at  = now()`,
		string(encoded), scopeTargetID, scanJobID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *PGStore) ListOpenRedirectFindingsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.OpenRedirectFinding, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, scope_target_id, scan_job_id, url, parameter, payload, finding_type,
		        status_code, COALESCE(location, ''), COALESCE(evidence, ''), created_at, updated_at
		 FROM open_redirect_findings
		 WHERE scope_target_id = $1
		 ORDER BY finding_type, url, parameter, payload`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	findings := make([]models.OpenRedirectFinding, 0)
	for rows.Next() {
		var f models.OpenRedirectFinding
		if err := rows.Scan(&f.ID, &f.ScopeTargetID, &f.ScanJobID, &f.URL, &f.Parameter, &f.Payload,
			&f.FindingType, &f.StatusCode, &f.Location, &f.Evidence, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}
