package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/spondonsaha/vexora/api/internal/models"
)

const scopeTargetCols = `id, type, value, COALESCE(description, ''), COALESCE(notes, ''), auth_confirmed, active, created_at, updated_at`

type PGStore struct {
	pool *pgxpool.Pool
}

func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

func (s *PGStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *PGStore) CreateScopeTarget(ctx context.Context, in CreateScopeTargetInput) (*models.ScopeTarget, error) {
	var description any
	if strings.TrimSpace(in.Description) != "" {
		description = strings.TrimSpace(in.Description)
	}

	row := s.pool.QueryRow(ctx,
		`INSERT INTO scope_targets (type, value, description, auth_confirmed)
		 VALUES ($1, $2, $3, $4)
		 RETURNING `+scopeTargetCols,
		string(in.Type), strings.TrimSpace(in.Value), description, in.AuthConfirmed,
	)

	st, err := scanScopeTarget(row)
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	return st, err
}

func (s *PGStore) ListScopeTargets(ctx context.Context, targetType string) ([]models.ScopeTarget, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if targetType != "" {
		rows, err = s.pool.Query(ctx,
			`SELECT `+scopeTargetCols+` FROM scope_targets WHERE type = $1 ORDER BY created_at DESC`,
			targetType)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT `+scopeTargetCols+` FROM scope_targets ORDER BY created_at DESC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	targets := make([]models.ScopeTarget, 0)
	for rows.Next() {
		st, err := scanScopeTarget(rows)
		if err != nil {
			return nil, err
		}
		targets = append(targets, *st)
	}
	return targets, rows.Err()
}

func (s *PGStore) GetScopeTarget(ctx context.Context, id uuid.UUID) (*models.ScopeTarget, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+scopeTargetCols+` FROM scope_targets WHERE id = $1`, id)
	return scanScopeTarget(row)
}

func (s *PGStore) DeleteScopeTarget(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scope_targets WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PGStore) SetScopeTargetActive(ctx context.Context, id uuid.UUID, active bool) (*models.ScopeTarget, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE scope_targets SET active = $2, updated_at = now() WHERE id = $1 RETURNING `+scopeTargetCols,
		id, active)
	return scanScopeTarget(row)
}

func (s *PGStore) SetScopeTargetAuthConfirmed(ctx context.Context, id uuid.UUID, confirmed bool) (*models.ScopeTarget, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE scope_targets SET auth_confirmed = $2, updated_at = now() WHERE id = $1 RETURNING `+scopeTargetCols,
		id, confirmed)
	return scanScopeTarget(row)
}

func (s *PGStore) SetScopeTargetNotes(ctx context.Context, id uuid.UUID, notes string) (*models.ScopeTarget, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE scope_targets SET notes = $2, updated_at = now() WHERE id = $1 RETURNING `+scopeTargetCols,
		id, notes)
	return scanScopeTarget(row)
}

func (s *PGStore) RecordAudit(ctx context.Context, e AuditEntry) error {
	var detail []byte
	if e.Detail != nil {
		encoded, err := json.Marshal(e.Detail)
		if err != nil {
			return err
		}
		detail = encoded
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_log (scope_target_id, scan_job_id, target, tool, action, detail)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		e.ScopeTargetID, e.ScanJobID, e.Target, e.Tool, e.Action, detail)
	return err
}

func scanScopeTarget(row pgx.Row) (*models.ScopeTarget, error) {
	var (
		st       models.ScopeTarget
		typeName string
	)
	err := row.Scan(
		&st.ID, &typeName, &st.Value, &st.Description, &st.Notes,
		&st.AuthConfirmed, &st.Active, &st.CreatedAt, &st.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	st.Type = models.ScopeTargetType(typeName)
	return &st, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
