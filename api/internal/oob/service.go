package oob

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Token is a unique OOB hostname vended to the scanner for one test case.
type Token struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`

	label string
}

// InteractionView is an interaction annotated with the token it matched (if any).
type InteractionView struct {
	TokenID       string `json:"token_id"`
	Protocol      string `json:"protocol"`
	RemoteAddress string `json:"remote_address"`
	FullID        string `json:"full_id"`
	Timestamp     string `json:"timestamp"`
	RawRequest    string `json:"raw_request"`
}

// Service maintains a single long-lived Interactsh session, vends unique OOB
// hostnames and continuously buffers the interactions the server reports.
type Service struct {
	servers      []string
	token        string
	pollInterval time.Duration

	mu            sync.Mutex
	client        *Client
	activeServer  string
	registered    bool
	lastErr       string
	tokensByLabel map[string]*Token
	tokensByID    map[string]*Token
	inbox         []Interaction
	seen          map[string]struct{}
}

// NewService builds a service that rotates through the given public (or
// self-hosted) Interactsh servers.
func NewService(servers []string, token string, pollInterval time.Duration) *Service {
	cleaned := make([]string, 0, len(servers))
	for _, s := range servers {
		if s = strings.TrimSpace(s); s != "" {
			cleaned = append(cleaned, s)
		}
	}
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	return &Service{
		servers:       cleaned,
		token:         token,
		pollInterval:  pollInterval,
		tokensByLabel: make(map[string]*Token),
		tokensByID:    make(map[string]*Token),
		seen:          make(map[string]struct{}),
	}
}

// Run registers a session and polls for interactions until the context ends.
func (s *Service) Run(ctx context.Context) {
	if !s.connect() {
		log.Printf("oob: initial registration failed, will retry: %s", s.errString())
	}

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pollOnce()
		}
	}
}

func (s *Service) connect() bool {
	for _, server := range s.servers {
		client, err := NewClient(server, s.token)
		if err != nil {
			s.setErr(err.Error())
			continue
		}
		if err := client.Register(); err != nil {
			s.setErr(err.Error())
			continue
		}
		s.mu.Lock()
		s.client = client
		s.activeServer = server
		s.registered = true
		s.lastErr = ""
		s.mu.Unlock()
		log.Printf("oob: registered session with %s (correlation-id=%s)", server, client.CorrelationID())
		return true
	}
	return false
}

func (s *Service) pollOnce() {
	s.mu.Lock()
	client := s.client
	registered := s.registered
	s.mu.Unlock()

	if client == nil || !registered {
		s.connect()
		return
	}

	interactions, err := client.Poll()
	if err != nil {
		if errors.Is(err, ErrNotRegistered) {
			log.Printf("oob: session expired, re-registering")
			s.mu.Lock()
			s.registered = false
			s.mu.Unlock()
			s.connect()
			return
		}
		s.setErr(err.Error())
		return
	}

	if len(interactions) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, interaction := range interactions {
		if interaction.UniqueID != "" {
			if _, ok := s.seen[interaction.UniqueID]; ok {
				continue
			}
			s.seen[interaction.UniqueID] = struct{}{}
		}
		s.inbox = append(s.inbox, interaction)
		log.Printf("oob: interaction %s from %s (%s)", interaction.Protocol, interaction.RemoteAddress, interaction.FullID)
	}
}

// NewTokens vends count fresh OOB hostnames.
func (s *Service) NewTokens(count int) ([]Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client == nil || !s.registered {
		return nil, errors.New("oob session is not registered yet")
	}

	out := make([]Token, 0, count)
	for i := 0; i < count; i++ {
		label, err := s.client.GenerateLabel()
		if err != nil {
			return nil, err
		}
		id, err := randomString(16)
		if err != nil {
			return nil, err
		}
		token := &Token{ID: id, Hostname: s.client.Hostname(label), label: label}
		s.tokensByLabel[label] = token
		s.tokensByID[id] = token
		out = append(out, *token)
	}
	return out, nil
}

func (s *Service) interactions() []InteractionView {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]InteractionView, 0, len(s.inbox))
	for _, interaction := range s.inbox {
		out = append(out, InteractionView{
			TokenID:       s.matchToken(interaction.FullID),
			Protocol:      interaction.Protocol,
			RemoteAddress: interaction.RemoteAddress,
			FullID:        interaction.FullID,
			Timestamp:     interaction.Timestamp,
			RawRequest:    interaction.RawRequest,
		})
	}
	return out
}

func (s *Service) matchToken(fullID string) string {
	if fullID == "" {
		return ""
	}
	lower := strings.ToLower(fullID)
	for label, token := range s.tokensByLabel {
		if strings.HasPrefix(lower, strings.ToLower(label)) {
			return token.ID
		}
	}
	return ""
}

func (s *Service) status() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	domain := ""
	if s.client != nil {
		domain = s.client.Domain()
	}
	status := "ok"
	if !s.registered {
		status = "degraded"
	}
	return map[string]any{
		"status":     status,
		"registered": s.registered,
		"server":     s.activeServer,
		"domain":     domain,
		"error":      s.lastErr,
		"interactions": len(s.inbox),
		"tokens":       len(s.tokensByID),
	}
}

func (s *Service) setErr(msg string) {
	s.mu.Lock()
	s.lastErr = msg
	s.registered = false
	s.mu.Unlock()
}

func (s *Service) errString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// Handler exposes the service over HTTP for the scanner worker.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/tokens", s.handleTokens)
	mux.HandleFunc("/interactions", s.handleInteractions)
	return mux
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.status())
}

func (s *Service) handleTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		Count int `json:"count"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Count < 1 {
		req.Count = 1
	}
	if req.Count > 1000 {
		req.Count = 1000
	}

	tokens, err := s.NewTokens(req.Count)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	s.mu.Lock()
	domain := ""
	if s.client != nil {
		domain = s.client.Domain()
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"domain": domain, "tokens": tokens})
}

func (s *Service) handleInteractions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"interactions": s.interactions()})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
