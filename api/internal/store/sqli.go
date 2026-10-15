package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
)

// SQLiFindingRow is a single SQL injection finding to persist.
type SQLiFindingRow struct {
	URL       string
	Parameter string
	Method    string
	Technique string
	Title     string
	Payload   string
	DBMS      string
}

// UpsertSQLiFindings stores sqlmap findings for a scope target keyed by
// (url, parameter, technique) so re-running refreshes rather than duplicates an
// injection point.
func (s *PGStore) UpsertSQLiFindings(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []SQLiFindingRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	// Collapse duplicate (url, parameter, technique) rows within a single batch
	// so one INSERT ... ON CONFLICT statement never touches the same row twice
	// (SQLSTATE 21000).
	index := make(map[string]int, len(rows))
	deduped := make([]SQLiFindingRow, 0, len(rows))
	for _, r := range rows {
		key := r.URL + "\x00" + r.Parameter + "\x00" + r.Technique
		if i, ok := index[key]; ok {
			if deduped[i].Title == "" {
				deduped[i].Title = r.Title
			}
			if deduped[i].Payload == "" {
				deduped[i].Payload = r.Payload
			}
			if deduped[i].DBMS == "" {
				deduped[i].DBMS = r.DBMS
			}
			continue
		}
		index[key] = len(deduped)
		deduped = append(deduped, r)
	}

	payload := make([]map[string]any, 0, len(deduped))
	for _, r := range deduped {
		payload = append(payload, map[string]any{
			"url":       r.URL,
			"parameter": r.Parameter,
			"method":    r.Method,
			"technique": r.Technique,
			"title":     nullIfEmpty(r.Title),
			"payload":   nullIfEmpty(r.Payload),
			"dbms":      nullIfEmpty(r.DBMS),
		})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	tag, err := s.pool.Exec(ctx,
		`INSERT INTO sqli_findings
		     (scope_target_id, scan_job_id, url, parameter, method, technique, title, payload, dbms)
		 SELECT $2, $3, v.url, v.parameter, v.method, v.technique, v.title, v.payload, v.dbms
		 FROM jsonb_to_recordset($1::jsonb) AS v(
		     url text, parameter text, method text, technique text,
		     title text, payload text, dbms text
		 )
		 ON CONFLICT (scope_target_id, url, parameter, technique) DO UPDATE SET
		     scan_job_id = EXCLUDED.scan_job_id,
		     method      = EXCLUDED.method,
		     title       = EXCLUDED.title,
		     payload     = EXCLUDED.payload,
		     dbms        = EXCLUDED.dbms,
		     updated_at  = now()`,
		string(encoded), scopeTargetID, scanJobID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *PGStore) ListSQLiFindingsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.SQLiFinding, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, scope_target_id, scan_job_id, url, parameter, method, technique,
		        COALESCE(title, ''), COALESCE(payload, ''), COALESCE(dbms, ''),
		        created_at, updated_at
		 FROM sqli_findings
		 WHERE scope_target_id = $1
		 ORDER BY url, parameter, technique`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	findings := make([]models.SQLiFinding, 0)
	for rows.Next() {
		var f models.SQLiFinding
		if err := rows.Scan(&f.ID, &f.ScopeTargetID, &f.ScanJobID, &f.URL, &f.Parameter,
			&f.Method, &f.Technique, &f.Title, &f.Payload, &f.DBMS,
			&f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}
