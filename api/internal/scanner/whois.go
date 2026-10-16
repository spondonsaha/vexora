package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spondonsaha/vexora/api/internal/models"
	"github.com/spondonsaha/vexora/api/internal/store"
)

// WhoisTool is the ad-hoc tool name for WHOIS/RDAP lookups.
const WhoisTool = "whois"

// rdapResponse is the subset of an RDAP domain response used for ownership and
// lifecycle extraction. RDAP is preferred over classic WHOIS because it returns
// clean JSON rather than scraped free text.
type rdapResponse struct {
	LDHName     string           `json:"ldhName"`
	Handle      string           `json:"handle"`
	Status      []string         `json:"status"`
	Events      []rdapEvent      `json:"events"`
	Entities    []rdapEntity     `json:"entities"`
	Nameservers []rdapNameserver `json:"nameservers"`
}

type rdapEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type rdapNameserver struct {
	LDHName string `json:"ldhName"`
}

type rdapEntity struct {
	Roles      []string        `json:"roles"`
	VCardArray json.RawMessage `json:"vcardArray"`
}

// runWhoisAdHoc looks up registration/ownership data for the target's root
// domain over RDAP and stores it in the `whois_records` table.
func (r *Runner) runWhoisAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, root string) Result {
	if !r.cfg.WhoisEnabled {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("whois lookups are disabled")}
	}

	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")

	domain := strings.ToLower(strings.TrimSpace(root))
	if domain == "" {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("no domain to look up")}
	}

	row, raw, err := r.fetchWhoisRDAP(ctx, domain)
	writeRawFile(stdoutPath, raw)
	if err != nil {
		writeRawFile(stderrPath, err.Error()+"\n")
		return Result{Status: models.ScanFailed, ExitCode: -1, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("whois %s: %w", domain, err)}
	}
	writeRawFile(stderrPath, "")

	stored, err := r.store.UpsertWhoisRecords(ctx, target.ID, job.ID, []store.WhoisRecordRow{row})
	if err != nil {
		return Result{Status: models.ScanFailed, ExitCode: -1, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("store whois record: %w", err)}
	}

	log.Printf("job %s: whois %s registrar=%q registrant=%q expires=%v (%d stored)",
		job.ID, domain, row.Registrar, row.RegistrantOrg, row.ExpiresAt, stored)

	return Result{Status: models.ScanDone, ExitCode: 0, StdoutPath: stdoutPath, StderrPath: stderrPath}
}

// fetchWhoisRDAP queries the configured RDAP bootstrap (rdap.org redirects to
// the authoritative registry) and normalizes the response into a store row.
func (r *Runner) fetchWhoisRDAP(ctx context.Context, domain string) (store.WhoisRecordRow, string, error) {
	base := strings.TrimRight(strings.TrimSpace(r.cfg.WhoisRDAPBase), "/")
	if base == "" {
		base = "https://rdap.org"
	}
	endpoint := base + "/domain/" + url.PathEscape(domain)

	timeout := time.Duration(r.cfg.WhoisTimeout) * time.Second
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return store.WhoisRecordRow{}, "", err
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Vexora/1.0; +https://github.com/spondonsaha/vexora)")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return store.WhoisRecordRow{}, "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		return store.WhoisRecordRow{}, string(body), fmt.Errorf("rdap returned HTTP %d: %s", resp.StatusCode, snippet)
	}

	var parsed rdapResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return store.WhoisRecordRow{}, string(body), fmt.Errorf("decode rdap: %w", err)
	}

	outDomain := domain
	if parsed.LDHName != "" {
		outDomain = strings.ToLower(parsed.LDHName)
	}

	row := store.WhoisRecordRow{
		Domain:      outDomain,
		Nameservers: rdapNameservers(parsed.Nameservers),
		Statuses:    parsed.Status,
		Source:      "rdap",
	}
	for _, ev := range parsed.Events {
		switch strings.ToLower(ev.EventAction) {
		case "registration":
			row.RegisteredAt = parseRDAPTime(ev.EventDate)
		case "expiration":
			row.ExpiresAt = parseRDAPTime(ev.EventDate)
		}
	}
	for _, ent := range parsed.Entities {
		for _, role := range ent.Roles {
			switch strings.ToLower(role) {
			case "registrant":
				if v := entityName(ent); v != "" {
					row.RegistrantOrg = v
				}
			case "registrar":
				if v := entityName(ent); v != "" {
					row.Registrar = v
				}
			}
		}
	}

	pretty := body
	if formatted, err := json.MarshalIndent(parsed, "", "  "); err == nil {
		pretty = formatted
	}
	return row, string(pretty) + "\n", nil
}

func rdapNameservers(ns []rdapNameserver) []string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		name := strings.ToLower(strings.TrimSpace(n.LDHName))
		if name == "" {
			continue
		}
		if !strings.HasSuffix(name, ".") {
			name += "."
		}
		out = append(out, name)
	}
	return out
}

// entityName extracts an organization or formatted name from an RDAP entity's
// jCard ("vcardArray"). Registrant entries are frequently redacted, in which
// case an empty string is returned.
func entityName(ent rdapEntity) string {
	if org := vcardField(ent.VCardArray, "org"); org != "" {
		return org
	}
	return vcardField(ent.VCardArray, "fn")
}

// vcardField reads a property value (e.g. "fn", "org") from a jCard array.
func vcardField(raw json.RawMessage, field string) string {
	if len(raw) == 0 {
		return ""
	}
	var top []json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || len(top) < 2 {
		return ""
	}
	var props []json.RawMessage
	if err := json.Unmarshal(top[1], &props); err != nil {
		return ""
	}
	for _, p := range props {
		var parts []json.RawMessage
		if err := json.Unmarshal(p, &parts); err != nil || len(parts) < 4 {
			continue
		}
		var name string
		if err := json.Unmarshal(parts[0], &name); err != nil || !strings.EqualFold(name, field) {
			continue
		}
		var s string
		if err := json.Unmarshal(parts[3], &s); err == nil && s != "" {
			return strings.TrimSpace(s)
		}
		var list []string
		if err := json.Unmarshal(parts[3], &list); err == nil {
			return strings.TrimSpace(strings.Join(list, " "))
		}
	}
	return ""
}

func parseRDAPTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	layouts := []string{time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02"}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			utc := t.UTC()
			return &utc
		}
	}
	return nil
}
