package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
)

// WhoisRecordRow is one domain's registration/ownership data to persist.
type WhoisRecordRow struct {
	Domain        string
	RegistrantOrg string
	Registrar     string
	RegisteredAt  *time.Time
	ExpiresAt     *time.Time
	Nameservers   []string
	Statuses      []string
	Source        string
}

// UpsertWhoisRecords stores WHOIS/RDAP records for a scope target, keyed by
// (scope target, domain, source) so re-running refreshes rather than duplicates
// a record.
func (s *PGStore) UpsertWhoisRecords(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []WhoisRecordRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	index := make(map[string]int, len(rows))
	deduped := make([]WhoisRecordRow, 0, len(rows))
	for _, r := range rows {
		key := r.Domain + "\x00" + r.Source
		if _, ok := index[key]; ok {
			continue
		}
		index[key] = len(deduped)
		deduped = append(deduped, r)
	}

	payload := make([]map[string]any, 0, len(deduped))
	for _, r := range deduped {
		ns := r.Nameservers
		if ns == nil {
			ns = []string{}
		}
		st := r.Statuses
		if st == nil {
			st = []string{}
		}
		source := r.Source
		if source == "" {
			source = "rdap"
		}
		payload = append(payload, map[string]any{
			"domain":         stripNul(r.Domain),
			"registrant_org": nullIfEmpty(stripNul(r.RegistrantOrg)),
			"registrar":      nullIfEmpty(stripNul(r.Registrar)),
			"registered_at":  rfc3339OrNil(r.RegisteredAt),
			"expires_at":     rfc3339OrNil(r.ExpiresAt),
			"nameservers":    ns,
			"statuses":       st,
			"source":         stripNul(source),
		})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	tag, err := s.pool.Exec(ctx,
		`INSERT INTO whois_records
		     (scope_target_id, scan_job_id, domain, registrant_org, registrar,
		      registered_at, expires_at, nameservers, statuses, source)
		 SELECT $2, $3, v.domain, v.registrant_org, v.registrar,
		        v.registered_at, v.expires_at, v.nameservers, v.statuses, v.source
		 FROM jsonb_to_recordset($1::jsonb) AS v(
		     domain text, registrant_org text, registrar text,
		     registered_at timestamptz, expires_at timestamptz,
		     nameservers jsonb, statuses jsonb, source text
		 )
		 ON CONFLICT (scope_target_id, domain, source) DO UPDATE SET
		     scan_job_id    = EXCLUDED.scan_job_id,
		     registrant_org = EXCLUDED.registrant_org,
		     registrar      = EXCLUDED.registrar,
		     registered_at  = EXCLUDED.registered_at,
		     expires_at     = EXCLUDED.expires_at,
		     nameservers    = EXCLUDED.nameservers,
		     statuses       = EXCLUDED.statuses,
		     updated_at     = now()`,
		string(encoded), scopeTargetID, scanJobID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ListWhoisRecordsByScopeTarget returns every WHOIS/RDAP record for a scope
// target, earliest expiry first so at-risk domains surface at the top.
func (s *PGStore) ListWhoisRecordsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.WhoisRecord, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, scope_target_id, root_domain_id, scan_job_id, domain,
		        COALESCE(registrant_org, ''), COALESCE(registrar, ''),
		        registered_at, expires_at, nameservers, statuses, source,
		        created_at, updated_at
		 FROM whois_records
		 WHERE scope_target_id = $1
		 ORDER BY expires_at NULLS LAST, domain`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.WhoisRecord, 0)
	for rows.Next() {
		var (
			w        models.WhoisRecord
			ns       []byte
			statuses []byte
		)
		if err := rows.Scan(&w.ID, &w.ScopeTargetID, &w.RootDomainID, &w.ScanJobID, &w.Domain,
			&w.RegistrantOrg, &w.Registrar, &w.RegisteredAt, &w.ExpiresAt, &ns, &statuses,
			&w.Source, &w.CreatedAt, &w.UpdatedAt); err != nil {
			return nil, err
		}
		w.Nameservers = jsonOr(ns, "[]")
		w.Statuses = jsonOr(statuses, "[]")
		items = append(items, w)
	}
	return items, rows.Err()
}

// rfc3339OrNil renders a time as RFC 3339 for jsonb_to_recordset, or nil when
// the time is absent.
func rfc3339OrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}
