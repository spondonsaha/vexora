package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/spondonsaha/vexora/api/internal/models"
)

type LiveWebServerRow struct {
	SubdomainID    *uuid.UUID
	IP             *string
	URL            string
	StatusCode     *int
	Title          *string
	ContentLength  *int64
	TechStack      json.RawMessage
	Headers        json.RawMessage
	TLS            json.RawMessage
	ScreenshotPath *string
}

func (s *PGStore) UpsertLiveWebServers(ctx context.Context, rows []LiveWebServerRow) (int, error) {
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
			`INSERT INTO live_web_servers
			     (subdomain_id, ip, url, status_code, title, content_length, tech_stack, headers, tls, screenshot_path)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			 ON CONFLICT (url) DO UPDATE SET
			     subdomain_id    = EXCLUDED.subdomain_id,
			     ip              = EXCLUDED.ip,
			     status_code     = EXCLUDED.status_code,
			     title           = EXCLUDED.title,
			     content_length  = EXCLUDED.content_length,
			     tech_stack      = EXCLUDED.tech_stack,
			     headers         = EXCLUDED.headers,
			     tls             = EXCLUDED.tls,
			     screenshot_path = COALESCE(EXCLUDED.screenshot_path, live_web_servers.screenshot_path),
			     updated_at      = now()`,
			r.SubdomainID, r.IP, r.URL, r.StatusCode, r.Title, r.ContentLength,
			jsonOr(r.TechStack, "[]"), jsonOr(r.Headers, "{}"), jsonOr(r.TLS, "{}"), r.ScreenshotPath)
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

func (s *PGStore) ListLiveWebServersByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.LiveWebServer, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT l.id, l.subdomain_id, host(l.ip)::text, l.url, l.status_code, l.title,
		        l.content_length, l.tech_stack, l.headers, l.tls, l.screenshot_path,
		        l.created_at, l.updated_at
		 FROM live_web_servers l
		 JOIN subdomains s ON s.id = l.subdomain_id
		 JOIN wildcard_targets w ON w.id = s.wildcard_target_id
		 WHERE w.scope_target_id = $1
		 ORDER BY l.url`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	servers := make([]models.LiveWebServer, 0)
	for rows.Next() {
		var (
			srv    models.LiveWebServer
			ip     *string
			tech   []byte
			hdrs   []byte
			tlsRaw []byte
		)
		if err := rows.Scan(&srv.ID, &srv.SubdomainID, &ip, &srv.URL, &srv.StatusCode,
			&srv.Title, &srv.ContentLength, &tech, &hdrs, &tlsRaw, &srv.ScreenshotPath,
			&srv.CreatedAt, &srv.UpdatedAt); err != nil {
			return nil, err
		}
		srv.IP = ip
		srv.TechStack = jsonOr(tech, "[]")
		srv.Headers = jsonOr(hdrs, "{}")
		srv.TLS = jsonOr(tlsRaw, "{}")
		servers = append(servers, srv)
	}
	return servers, rows.Err()
}

// GetLiveWebServer loads a single live web server by id.
func (s *PGStore) GetLiveWebServer(ctx context.Context, id uuid.UUID) (*models.LiveWebServer, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, subdomain_id, host(ip)::text, url, status_code, title, content_length, tech_stack, headers, tls, screenshot_path, created_at, updated_at
		 FROM live_web_servers
		 WHERE id = $1`,
		id)

	var (
		srv    models.LiveWebServer
		ip     *string
		tech   []byte
		hdrs   []byte
		tlsRaw []byte
	)
	if err := row.Scan(&srv.ID, &srv.SubdomainID, &ip, &srv.URL, &srv.StatusCode, &srv.Title,
		&srv.ContentLength, &tech, &hdrs, &tlsRaw, &srv.ScreenshotPath,
		&srv.CreatedAt, &srv.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	srv.IP = ip
	srv.TechStack = jsonOr(tech, "[]")
	srv.Headers = jsonOr(hdrs, "{}")
	srv.TLS = jsonOr(tlsRaw, "{}")
	return &srv, nil
}

// UpdateLiveWebServerScreenshots sets the screenshot path for the given live
// web servers, keyed by id.
func (s *PGStore) UpdateLiveWebServerScreenshots(ctx context.Context, shots map[uuid.UUID]string) (int, error) {
	if len(shots) == 0 {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	affected := 0
	for id, path := range shots {
		tag, err := tx.Exec(ctx,
			`UPDATE live_web_servers
			 SET screenshot_path = $2, updated_at = now()
			 WHERE id = $1`,
			id, path)
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

func jsonOr(raw json.RawMessage, fallback string) []byte {
	if len(raw) == 0 {
		return []byte(fallback)
	}
	return raw
}
