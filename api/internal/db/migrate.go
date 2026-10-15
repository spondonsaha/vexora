package db

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/spondonsaha/vexora/api/migrations"
)

const migrationLockKey = int64(0x70746672)

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockKey)
	}()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}

	names, err := migrationFiles()
	if err != nil {
		return err
	}

	for _, name := range names {
		var applied bool
		if err := conn.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)", name,
		).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}

		sqlBytes, err := migrations.FS.ReadFile(name)
		if err != nil {
			return err
		}

		if _, err := conn.Conn().PgConn().Exec(ctx, string(sqlBytes)).ReadAll(); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}

		if _, err := conn.Exec(ctx,
			"INSERT INTO schema_migrations (version) VALUES ($1)", name,
		); err != nil {
			return err
		}
		fmt.Printf("migration applied: %s\n", name)
	}

	return nil
}

func migrationFiles() ([]string, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
