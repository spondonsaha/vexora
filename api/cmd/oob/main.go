// Command oob runs the framework's out-of-band interaction service. It
// registers a long-lived session with a public (or self-hosted) Interactsh
// server and exposes a small HTTP API the scanner worker uses to mint OOB
// hostnames and collect DNS/HTTP/SMTP callbacks.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spondonsaha/vexora/api/internal/oob"
)

func main() {
	port := env("OOB_PORT", "8090")
	servers := splitCSV(env("OOB_SERVERS", "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"))
	token := os.Getenv("OOB_TOKEN")
	pollInterval := time.Duration(envInt("OOB_POLL_SECONDS", 2)) * time.Second

	if len(servers) == 0 {
		log.Fatal("oob: no interactsh servers configured (set OOB_SERVERS)")
	}

	service := oob.NewService(servers, token, pollInterval)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go service.Run(ctx)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           service.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("oob service listening on :%s (servers=%s, poll=%s)", port, strings.Join(servers, ","), pollInterval)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("oob server: %v", err)
	}
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
