package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
)

// SSRFFindingRow is a single SSRF candidate or confirmed finding to persist.
type SSRFFindingRow struct {
	URL           string
	Parameter     string
	Payload       string
	Method        string
	FindingType   string
	Severity      string
	Confirmed     bool
	Protocol      string
	RemoteAddress string
	Evidence      string
}

// UpsertSSRFFindings stores SSRF findings for a scope target keyed by
// (url, parameter, payload, finding type) so re-running refreshes rather than
// duplicates a finding.
func (s *PGStore) UpsertSSRFFindings(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []SSRFFindingRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	// Collapse duplicate keys within a single batch so one INSERT ... ON
	// CONFLICT statement never touches the same row twice (SQLSTATE 21000).
	index := make(map[string]int, len(rows))
	deduped := make([]SSRFFindingRow, 0, len(rows))
	for _, r := range rows {
		key := r.URL + "\x00" + r.Parameter + "\x00" + r.Payload + "\x00" + r.FindingType
		if i, ok := index[key]; ok {
			// Prefer a confirmed/severity-bearing duplicate over a bare candidate.
			if deduped[i].Severity == "info" && r.Severity != "" && r.Severity != "info" {
				deduped[i] = r
			}
			continue
		}
		index[key] = len(deduped)
		deduped = append(deduped, r)
	}

	payload := make([]map[string]any, 0, len(deduped))
	for _, r := range deduped {
		method := r.Method
		if method == "" {
			method = "GET"
		}
		severity := r.Severity
		if severity == "" {
			severity = "info"
		}
		payload = append(payload, map[string]any{
			"url":            stripNul(r.URL),
			"parameter":      stripNul(r.Parameter),
			"payload":        stripNul(r.Payload),
			"method":         stripNul(method),
			"finding_type":   stripNul(r.FindingType),
			"severity":       stripNul(severity),
			"confirmed":      r.Confirmed,
			"protocol":       nullIfEmpty(stripNul(r.Protocol)),
			"remote_address": nullIfEmpty(stripNul(r.RemoteAddress)),
			"evidence":       nullIfEmpty(stripNul(r.Evidence)),
		})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	tag, err := s.pool.Exec(ctx,
		`INSERT INTO ssrf_findings
		     (scope_target_id, scan_job_id, url, parameter, payload, method, finding_type,
		      severity, confirmed, protocol, remote_address, evidence)
		 SELECT $2, $3, v.url, v.parameter, v.payload, v.method, v.finding_type,
		        v.severity, v.confirmed, v.protocol, v.remote_address, v.evidence
		 FROM jsonb_to_recordset($1::jsonb) AS v(
		     url text, parameter text, payload text, method text, finding_type text,
		     severity text, confirmed boolean, protocol text, remote_address text, evidence text
		 )
		 ON CONFLICT (scope_target_id, url, parameter, payload, finding_type) DO UPDATE SET
		     scan_job_id    = EXCLUDED.scan_job_id,
		     method         = EXCLUDED.method,
		     severity       = EXCLUDED.severity,
		     confirmed      = EXCLUDED.confirmed,
		     protocol       = EXCLUDED.protocol,
		     remote_address = EXCLUDED.remote_address,
		     evidence       = EXCLUDED.evidence,
		     updated_at     = now()`,
		string(encoded), scopeTargetID, scanJobID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *PGStore) ListSSRFFindingsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.SSRFFinding, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, scope_target_id, scan_job_id, url, parameter, payload, method, finding_type,
		        severity, confirmed, COALESCE(protocol, ''), COALESCE(remote_address, ''),
		        COALESCE(evidence, ''), created_at, updated_at
		 FROM ssrf_findings
		 WHERE scope_target_id = $1
		 ORDER BY confirmed DESC, finding_type, url, parameter`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	findings := make([]models.SSRFFinding, 0)
	for rows.Next() {
		var f models.SSRFFinding
		if err := rows.Scan(&f.ID, &f.ScopeTargetID, &f.ScanJobID, &f.URL, &f.Parameter, &f.Payload,
			&f.Method, &f.FindingType, &f.Severity, &f.Confirmed, &f.Protocol, &f.RemoteAddress,
			&f.Evidence, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}
