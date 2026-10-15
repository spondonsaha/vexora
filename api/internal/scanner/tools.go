package scanner

import (
	"bufio"
	"net/url"
	"regexp"
	"strings"
)

// toolSource describes a single external discovery tool invocation. Tools are
// registered here (rather than hardcoded per workflow) so additional sources
// from §7 (Assetfinder, Sublist3r, CT, ...) can be added without touching the
// workflow engine.
type toolSource struct {
	Name  string
	Image string
	Args  func(root string) []string
	// Parse extracts hostnames/subdomains from stdout.
	Parse func(stdout, root string) []string
	// ParseURLs extracts full URLs from stdout (URL-discovery tools only).
	ParseURLs func(stdout, root string) []string
}

// enumSources are the passive enumeration tools (§7.1).
func (r *Runner) enumSources(root string) []toolSource {
	sources := make([]toolSource, 0, 1)
	if r.cfg.AmassEnabled {
		sources = append(sources, toolSource{
			Name:  "amass",
			Image: r.cfg.AmassImage,
			Args: func(root string) []string {
				args := []string{"enum", "-d", root, "-timeout", "3"}
				if r.cfg.AmassActive {
					args = append(args, "-active")
				}
				return args
			},
			Parse: parseAmass,
		})
	}
	return sources
}

// scrapeSources are the subdomain-scraping tools that run in parallel (§7.2).
// Each queries a different public dataset, so overlapping coverage is expected.
func (r *Runner) scrapeSources(root string) []toolSource {
	sources := make([]toolSource, 0, 5)
	if r.cfg.SubfinderEnabled {
		sources = append(sources, toolSource{
			Name:  "subfinder",
			Image: r.cfg.SubfinderImage,
			Args: func(root string) []string {
				return []string{"-d", root, "-silent", "-nc", "-all", "-recursive", "-t", "200"}
			},
			Parse: parseHostLines,
		})
	}
	if r.cfg.AssetfinderEnabled {
		sources = append(sources, toolSource{
			Name:  "assetfinder",
			Image: r.cfg.AssetfinderImage,
			Args: func(root string) []string {
				return []string{"-subs-only", root}
			},
			Parse: parseHostLines,
		})
	}
	if r.cfg.Sublist3rEnabled {
		sources = append(sources, toolSource{
			Name:  "sublist3r",
			Image: r.cfg.Sublist3rImage,
			Args: func(root string) []string {
				return []string{"-d", root, "-t", "50"}
			},
			Parse: parseHostLines,
		})
	}
	if r.cfg.FindomainEnabled {
		sources = append(sources, toolSource{
			Name:  "findomain",
			Image: r.cfg.FindomainImage,
			Args: func(root string) []string {
				return []string{"-t", root, "--quiet"}
			},
			Parse: parseHostLines,
		})
	}
	if r.cfg.CTEnabled {
		sources = append(sources, toolSource{
			Name:  "ct",
			Image: r.cfg.CTImage,
			Args: func(root string) []string {
				return []string{root}
			},
			Parse: parseHostLines,
		})
	}
	return sources
}

// urlSources are the URL-discovery tools (§8): historical archives and a
// JS-aware crawler. They feed both the endpoint store and the subdomain list.
func (r *Runner) urlSources(root string) []toolSource {
	sources := make([]toolSource, 0, 3)
	if r.cfg.GauEnabled {
		sources = append(sources, toolSource{
			Name:  "gau",
			Image: r.cfg.GauImage,
			Args: func(root string) []string {
				// Skip the "wayback" provider: its http endpoint is frequently
				// unreachable/throttled and makes gau hang until the deadline.
				// OTX + URLScan are fast and cover a large URL corpus.
				return []string{root, "--providers", "otx,urlscan,commoncrawl", "--threads", "5", "--timeout", "20", "--subs"}
			},
			Parse:     parseURLHosts,
			ParseURLs: parseURLs,
		})
	}
	if r.cfg.WaybackurlsEnabled {
		sources = append(sources, toolSource{
			Name:  "waybackurls",
			Image: r.cfg.WaybackurlsImage,
			Args: func(root string) []string {
				return []string{root, "--limit", "5000", "--timeout", "90", "--deadline", "240"}
			},
			Parse:     parseURLHosts,
			ParseURLs: parseURLs,
		})
	}
	if r.cfg.KatanaEnabled {
		sources = append(sources, toolSource{
			Name:  "katana",
			Image: r.cfg.KatanaImage,
			Args: func(root string) []string {
				return []string{"-u", "https://" + root, "-silent", "-jc", "-kf", "all", "-d", "3", "-c", "10", "-timeout", "10", "-ct", "180s"}
			},
			Parse:     parseURLHosts,
			ParseURLs: parseURLs,
		})
	}
	return sources
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func stripANSI(s string) string {
	return ansiPattern.ReplaceAllString(s, "")
}

func parseHostLines(stdout, root string) []string {
	out := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(stripANSI(scanner.Text())))
		if isSubdomainOf(line, root) {
			out = append(out, line)
		}
	}
	return out
}

// parseURLHosts extracts hostnames from newline-delimited URLs (gau/GAU output).
func parseURLHosts(stdout, root string) []string {
	out := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(stripANSI(scanner.Text()))
		if line == "" {
			continue
		}
		host := line
		if u, err := url.Parse(line); err == nil && u.Host != "" {
			host = u.Hostname()
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if isSubdomainOf(host, root) {
			out = append(out, host)
		}
	}
	return out
}

// parseURLs keeps full URLs whose host belongs to the target root.
func parseURLs(stdout, root string) []string {
	out := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(stripANSI(scanner.Text()))
		low := strings.ToLower(line)
		if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.Host == "" {
			continue
		}
		if isSubdomainOf(u.Hostname(), root) {
			out = append(out, line)
		}
	}
	return out
}

// parseAmass extracts FQDN tokens from amass graph output, e.g.
//
//	sub.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)
func parseAmass(stdout, root string) []string {
	out := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(stripANSI(scanner.Text()))
		for i := 1; i < len(fields); i++ {
			if fields[i] != "(FQDN)" {
				continue
			}
			candidate := strings.ToLower(strings.TrimRight(fields[i-1], "."))
			if isSubdomainOf(candidate, root) {
				out = append(out, candidate)
			}
		}
	}
	return out
}

func isSubdomainOf(host, root string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	root = strings.ToLower(strings.TrimSpace(root))
	if host == "" || root == "" {
		return false
	}
	return host == root || strings.HasSuffix(host, "."+root)
}
