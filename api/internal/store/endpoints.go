package store

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
)

// EndpointRow is a single discovered URL to persist.
type EndpointRow struct {
	LiveWebServerID  *uuid.UUID
	WildcardTargetID *uuid.UUID
	Host             string
	URL              string
	Path             string
	SourceTool       string
	Interesting      bool
}

// UpsertEndpoints inserts discovered URLs, refreshing the source tool and
// interesting flag on conflict. Keyed by the full URL.
func (s *PGStore) UpsertEndpoints(ctx context.Context, rows []EndpointRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	affected := 0
	for _, r := range rows {
		tag, err := tx.Exec(ctx,
			`INSERT INTO endpoints
			     (live_web_server_id, wildcard_target_id, host, url, path, source_tool, interesting)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT (url) WHERE url IS NOT NULL DO UPDATE SET
			     live_web_server_id = COALESCE(EXCLUDED.live_web_server_id, endpoints.live_web_server_id),
			     wildcard_target_id = EXCLUDED.wildcard_target_id,
			     host               = EXCLUDED.host,
			     path               = EXCLUDED.path,
			     interesting        = endpoints.interesting OR EXCLUDED.interesting`,
			r.LiveWebServerID, r.WildcardTargetID, r.Host, r.URL, r.Path, r.SourceTool, r.Interesting)
		if err != nil {
			return 0, err
		}
		affected += int(tag.RowsAffected())
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return affected, nil
}

func (s *PGStore) ListEndpointsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.Endpoint, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT e.id, e.live_web_server_id, e.wildcard_target_id, e.host, e.url, e.path,
		        e.status_code, e.content_length, e.source_tool, e.interesting, e.created_at
		 FROM endpoints e
		 JOIN wildcard_targets w ON w.id = e.wildcard_target_id
		 WHERE w.scope_target_id = $1
		 ORDER BY e.interesting DESC, e.url`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	endpoints := make([]models.Endpoint, 0)
	for rows.Next() {
		var e models.Endpoint
		if err := rows.Scan(&e.ID, &e.LiveWebServerID, &e.WildcardTargetID, &e.Host, &e.URL,
			&e.Path, &e.StatusCode, &e.ContentLength, &e.SourceTool, &e.Interesting,
			&e.CreatedAt); err != nil {
			return nil, err
		}
		endpoints = append(endpoints, e)
	}
	return endpoints, rows.Err()
}

// InterestingURL reports whether a URL deserves manual attention (§16): a
// parameterised (query-string) path, or a backup/config/secret extension.
func InterestingURL(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	if strings.Contains(lower, "?") {
		return true
	}
	for _, ext := range interestingExtensions {
		if strings.Contains(lower, ext) {
			return true
		}
	}
	return false
}

var interestingExtensions = []string{
	".json", ".env", ".sql", ".bak", ".git", ".yml", ".yaml", ".config",
	".xml", ".log", ".zip", ".tar", ".gz", ".tgz", ".old", ".swp", ".db",
	".key", ".pem", ".csv", ".xls", ".xlsx", ".pdf", ".txt",
}
