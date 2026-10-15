package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spondonsaha/vexora/api/internal/api"
	"github.com/spondonsaha/vexora/api/internal/config"
	"github.com/spondonsaha/vexora/api/internal/db"
	"github.com/spondonsaha/vexora/api/internal/store"
)

func main() {
	cfg := config.Load()

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(rootCtx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer pool.Close()

	if err := db.Migrate(rootCtx, pool); err != nil {
		log.Fatalf("migration failed: %v", err)
	}

	st := store.NewPGStore(pool)
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           api.NewRouter(st, cfg),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("api listening on :%s (env=%s)", cfg.Port, cfg.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-rootCtx.Done()
	log.Println("shutting down api")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}
