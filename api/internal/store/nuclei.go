package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
)

// NucleiFindingRow is a single nuclei template match to persist.
type NucleiFindingRow struct {
	Category    string
	TemplateID  string
	Name        string
	Severity    string
	Type        string
	Host        string
	MatchedAt   string
	Description string
	Reference   []string
	Tags        []string
	Extracted   []string
	CVSSScore   *float64
	CurlCommand string
}

// UpsertNucleiFindings stores nuclei matches for a scope target keyed by
// (template, matched-at) so re-running a category refreshes rather than
// duplicates findings.
func (s *PGStore) UpsertNucleiFindings(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []NucleiFindingRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	// nuclei can emit several events for the same (template, matched-at) pair
	// (one per matcher/extractor, e.g. each missing security header). Collapse
	// them into a single row - merging extracted results so the detail is kept -
	// so a single INSERT ... ON CONFLICT never updates the same row twice
	// (SQLSTATE 21000).
	index := make(map[string]int, len(rows))
	deduped := make([]NucleiFindingRow, 0, len(rows))
	for _, r := range rows {
		key := r.TemplateID + "\x00" + r.MatchedAt
		if i, ok := index[key]; ok {
			deduped[i].Extracted = mergeUnique(deduped[i].Extracted, r.Extracted)
			if deduped[i].CurlCommand == "" {
				deduped[i].CurlCommand = r.CurlCommand
			}
			continue
		}
		index[key] = len(deduped)
		deduped = append(deduped, r)
	}

	payload := make([]map[string]any, 0, len(deduped))
	for _, r := range deduped {
		payload = append(payload, map[string]any{
			"category":     r.Category,
			"template_id":  r.TemplateID,
			"name":         r.Name,
			"severity":     r.Severity,
			"type":         nullIfEmpty(r.Type),
			"host":         nullIfEmpty(r.Host),
			"matched_at":   r.MatchedAt,
			"description":  nullIfEmpty(r.Description),
			"reference":    emptyIfNil(r.Reference),
			"tags":         emptyIfNil(r.Tags),
			"extracted":    emptyIfNil(r.Extracted),
			"cvss_score":   r.CVSSScore,
			"curl_command": nullIfEmpty(r.CurlCommand),
		})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	tag, err := s.pool.Exec(ctx,
		`INSERT INTO nuclei_findings
		     (scope_target_id, scan_job_id, category, template_id, name, severity,
		      type, host, matched_at, description, reference, tags, extracted,
		      cvss_score, curl_command)
		 SELECT $2, $3, v.category, v.template_id, v.name, v.severity,
		        v.type, v.host, v.matched_at, v.description,
		        v.reference, v.tags, v.extracted, v.cvss_score, v.curl_command
		 FROM jsonb_to_recordset($1::jsonb) AS v(
		     category text, template_id text, name text, severity text, type text,
		     host text, matched_at text, description text, reference jsonb,
		     tags jsonb, extracted jsonb, cvss_score real, curl_command text
		 )
		 ON CONFLICT (scope_target_id, template_id, matched_at) DO UPDATE SET
		     scan_job_id  = EXCLUDED.scan_job_id,
		     category     = EXCLUDED.category,
		     name         = EXCLUDED.name,
		     severity     = EXCLUDED.severity,
		     type         = EXCLUDED.type,
		     host         = EXCLUDED.host,
		     description  = EXCLUDED.description,
		     reference    = EXCLUDED.reference,
		     tags         = EXCLUDED.tags,
		     extracted    = EXCLUDED.extracted,
		     cvss_score   = EXCLUDED.cvss_score,
		     curl_command = EXCLUDED.curl_command,
		     updated_at   = now()`,
		string(encoded), scopeTargetID, scanJobID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *PGStore) ListNucleiFindingsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.NucleiFinding, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, scope_target_id, scan_job_id, category, template_id, name, severity,
		        type, host, matched_at, description, reference, tags, extracted,
		        cvss_score, curl_command, created_at, updated_at
		 FROM nuclei_findings
		 WHERE scope_target_id = $1
		 ORDER BY CASE severity
		              WHEN 'critical' THEN 0
		              WHEN 'high'     THEN 1
		              WHEN 'medium'   THEN 2
		              WHEN 'low'      THEN 3
		              WHEN 'info'     THEN 4
		              ELSE 5
		          END,
		          name, matched_at`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	findings := make([]models.NucleiFinding, 0)
	for rows.Next() {
		var (
			f     models.NucleiFinding
			ref   []byte
			tags  []byte
			extra []byte
		)
		if err := rows.Scan(&f.ID, &f.ScopeTargetID, &f.ScanJobID, &f.Category, &f.TemplateID,
			&f.Name, &f.Severity, &f.Type, &f.Host, &f.MatchedAt, &f.Description,
			&ref, &tags, &extra, &f.CVSSScore, &f.CurlCommand, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		f.Reference = jsonOr(ref, "[]")
		f.Tags = jsonOr(tags, "[]")
		f.Extracted = jsonOr(extra, "[]")
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// mergeUnique appends the values from extra that are not already in base,
// preserving first-seen order.
func mergeUnique(base, extra []string) []string {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]struct{}, len(base)+len(extra))
	for _, v := range base {
		seen[v] = struct{}{}
	}
	for _, v := range extra {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		base = append(base, v)
	}
	return base
}
