package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
)

// TechnologyRow is one fingerprinted technology to persist. CVERefs is optional
// (populated by template-driven detectors in a later pass).
type TechnologyRow struct {
	LiveWebServerID uuid.UUID
	Name            string
	Version         string
	Category        string
	DetectedBy      string
	CVERefs         []string
}

// UpsertTechnologies stores fingerprinted technologies for a scope target,
// keyed by (scope target, live web server, name, version, detecting tool) so
// re-running a detector refreshes the row rather than duplicating it.
func (s *PGStore) UpsertTechnologies(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []TechnologyRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	// Collapse duplicate keys within a single batch so one INSERT ... ON
	// CONFLICT statement never touches the same row twice (SQLSTATE 21000).
	index := make(map[string]int, len(rows))
	deduped := make([]TechnologyRow, 0, len(rows))
	for _, r := range rows {
		key := r.LiveWebServerID.String() + "\x00" + r.Name + "\x00" + r.Version + "\x00" + r.DetectedBy
		if _, ok := index[key]; ok {
			continue
		}
		index[key] = len(deduped)
		deduped = append(deduped, r)
	}

	payload := make([]map[string]any, 0, len(deduped))
	for _, r := range deduped {
		cves := r.CVERefs
		if cves == nil {
			cves = []string{}
		}
		category := r.Category
		if category == "" {
			category = "other"
		}
		payload = append(payload, map[string]any{
			"live_web_server_id": r.LiveWebServerID.String(),
			"name":               stripNul(r.Name),
			"version":            stripNul(r.Version),
			"category":           stripNul(category),
			"detected_by":        stripNul(r.DetectedBy),
			"cve_refs":           cves,
		})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	tag, err := s.pool.Exec(ctx,
		`INSERT INTO technologies
		     (scope_target_id, scan_job_id, live_web_server_id, name, version, category, detected_by, cve_refs)
		 SELECT $2, $3, v.live_web_server_id, v.name, v.version, v.category, v.detected_by, v.cve_refs
		 FROM jsonb_to_recordset($1::jsonb) AS v(
		     live_web_server_id uuid, name text, version text, category text, detected_by text, cve_refs jsonb
		 )
		 ON CONFLICT (scope_target_id, live_web_server_id, name, version, detected_by) DO UPDATE SET
		     scan_job_id = EXCLUDED.scan_job_id,
		     category    = EXCLUDED.category,
		     cve_refs    = EXCLUDED.cve_refs,
		     updated_at  = now()`,
		string(encoded), scopeTargetID, scanJobID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ListTechnologiesByScopeTarget returns every fingerprinted technology for a
// scope target, ordered for stable UI rendering.
func (s *PGStore) ListTechnologiesByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.Technology, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, scope_target_id, live_web_server_id, scan_job_id, name, version,
		        category, detected_by, cve_refs, created_at, updated_at
		 FROM technologies
		 WHERE scope_target_id = $1
		 ORDER BY category, name, version, detected_by`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.Technology, 0)
	for rows.Next() {
		var (
			t    models.Technology
			cves []byte
		)
		if err := rows.Scan(&t.ID, &t.ScopeTargetID, &t.LiveWebServerID, &t.ScanJobID, &t.Name,
			&t.Version, &t.Category, &t.DetectedBy, &cves, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.CVERefs = jsonOr(cves, "[]")
		items = append(items, t)
	}
	return items, rows.Err()
}
