package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
	"github.com/spondonsaha/vexora/api/internal/store"
)

// NetworkTool is the ad-hoc tool name for the network recon scan. It resolves
// every discovered subdomain to its IPs (dnsx), port scans the unique IPs
// (naabu) and fingerprints the open services (nmap -sV).
const NetworkTool = "netscan"

// networkMaxIPs caps how many unique IPs a single run will port scan so a wide
// wildcard cannot run away with the tool timeout.
const networkMaxIPs = 256

// NetworkProfiles maps a UI port profile to the naabu port-selection arguments.
var NetworkProfiles = map[string][]string{
	"top100":  {"-top-ports", "100"},
	"top1000": {"-top-ports", "1000"},
	"full":    {"-p", "1-65535"},
}

type networkOptions struct {
	Profile string `json:"profile"`
}

// runNetworkAdHoc executes a standalone network scan for an ad-hoc job.
func (r *Runner) runNetworkAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, root string) Result {
	if !r.cfg.NetworkScanEnabled {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("network scanning is disabled")}
	}

	profile := "top100"
	var opts networkOptions
	if len(job.Options) > 0 {
		if err := json.Unmarshal(job.Options, &opts); err == nil && opts.Profile != "" {
			profile = strings.ToLower(strings.TrimSpace(opts.Profile))
		}
	}
	if _, ok := NetworkProfiles[profile]; !ok {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: fmt.Errorf("unsupported port profile %q", profile)}
	}

	summary, stdout, stderr, exitCode, runErr := r.runNetwork(ctx, target, root, profile, job.ID)

	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")
	writeRawFile(stdoutPath, stdout)
	writeRawFile(stderrPath, stderr)

	if runErr != nil {
		return Result{Status: models.ScanFailed, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: runErr}
	}

	log.Printf("job %s: netscan [%s] resolved %v host(s) -> %v ip(s), %v open port(s), %v service(s)",
		job.ID, profile, summary["resolved"], summary["ips"], summary["ports"], summary["services"])
	return Result{Status: models.ScanDone, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath}
}

// runNetwork performs the dnsx -> naabu -> nmap pipeline and persists the open
// ports / services. Raw text from every stage is concatenated and returned so
// the UI can show it, along with a summary for logging.
func (r *Runner) runNetwork(ctx context.Context, target *models.ScopeTarget, root, profile string, jobID uuid.UUID) (map[string]any, string, string, int, error) {
	summary := map[string]any{"resolved": 0, "ips": 0, "ports": 0, "services": 0}
	var out, errOut strings.Builder

	wildcardID, err := r.store.EnsureWildcardTarget(ctx, target.ID, root)
	if err != nil {
		return summary, "", "", -1, fmt.Errorf("ensure wildcard target: %w", err)
	}

	subs, err := r.store.ListSubdomainsByScopeTarget(ctx, target.ID)
	if err != nil {
		return summary, "", "", -1, fmt.Errorf("list subdomains: %w", err)
	}

	hosts := make([]string, 0, len(subs))
	seen := map[string]struct{}{}
	for _, s := range subs {
		host := strings.ToLower(strings.TrimSpace(s.Subdomain))
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	if len(hosts) == 0 {
		return summary, "", "", -1, errors.New("no subdomains to scan: run the wildcard workflow (or an ad-hoc subdomain tool) first")
	}
	if len(hosts) > r.cfg.NetworkMaxHosts {
		log.Printf("netscan: %d hosts truncated to %d", len(hosts), r.cfg.NetworkMaxHosts)
		hosts = hosts[:r.cfg.NetworkMaxHosts]
	}

	// 1. Resolve every subdomain to its A/AAAA records and CNAME.
	out.WriteString("=== dnsx (resolve A/AAAA/CNAME) ===\n")
	resolveOut, resolveErr, exitCode, runErr := r.runContainerInput(ctx, jobID, r.cfg.DnsxImage,
		strings.Join(hosts, "\n"),
		"-silent", "-a", "-aaaa", "-cname", "-json", "-l", "-", "-retry", "2")
	out.WriteString(resolveOut)
	if runErr != nil {
		errOut.WriteString(resolveErr)
		return summary, out.String(), errOut.String(), exitCode, fmt.Errorf("dnsx resolve: %w", runErr)
	}

	records := parseDnsx(resolveOut)
	if len(records) == 0 {
		return summary, out.String(), errOut.String(), exitCode, errors.New("no subdomains resolved to an IP address")
	}

	ipHosts := map[string][]string{}
	dnsRows := make([]store.SubdomainDNSRow, 0, len(records))
	ipSet := map[string]struct{}{}
	for _, rec := range records {
		ips := append(append([]string{}, rec.A...), rec.AAAA...)
		cname := ""
		if len(rec.CNAME) > 0 {
			cname = rec.CNAME[0]
		}
		rows := store.SubdomainDNSRow{Subdomain: rec.Host, CNAME: cname, ARecords: ips}
		for _, ip := range ips {
			ipHosts[ip] = append(ipHosts[ip], rec.Host)
			if v4 := net.ParseIP(ip).To4(); v4 != nil {
				ipSet[v4.String()] = struct{}{}
			}
		}
		dnsRows = append(dnsRows, rows)
	}
	summary["resolved"] = len(records)

	// 2. Reverse DNS for every unique IPv4.
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	if len(ips) > networkMaxIPs {
		log.Printf("netscan: %d ip(s) truncated to %d", len(ips), networkMaxIPs)
		ips = ips[:networkMaxIPs]
	}
	summary["ips"] = len(ips)

	ptrByIP := map[string][]string{}
	if len(ips) > 0 {
		out.WriteString("\n=== dnsx (reverse DNS) ===\n")
		ptrOut, _, _, ptrErr := r.runContainerInput(ctx, jobID, r.cfg.DnsxImage,
			strings.Join(ips, "\n"),
			"-silent", "-ptr", "-json", "-l", "-", "-retry", "2")
		out.WriteString(ptrOut)
		if ptrErr != nil {
			log.Printf("netscan: reverse DNS lookup failed: %v", ptrErr)
		} else {
			ptrByIP = parseDnsxPTR(ptrOut)
		}
	}
	for i := range dnsRows {
		var ptrs []string
		for _, ip := range dnsRows[i].ARecords {
			ptrs = append(ptrs, ptrByIP[ip]...)
		}
		if len(ptrs) > 0 {
			dnsRows[i].ReverseDNS = dedupe(ptrs)
		}
	}
	if _, err := r.store.UpdateSubdomainDNS(ctx, wildcardID, dnsRows); err != nil {
		return summary, out.String(), errOut.String(), exitCode, fmt.Errorf("store resolved DNS: %w", err)
	}

	if len(ips) == 0 {
		return summary, out.String(), errOut.String(), exitCode, errors.New("no IPv4 addresses to port scan")
	}

	// 3. Port scan every unique IPv4 with naabu.
	out.WriteString("\n=== naabu (port scan) ===\n")
	naabuArgs := []string{"-silent", "-json", "-rate", "2000", "-c", "50", "-timeout", "1000", "-warm-up-time", "1"}
	naabuArgs = append(naabuArgs, NetworkProfiles[profile]...)
	naabuOut, naabuErr, exitCode, runErr := r.runContainerInput(ctx, jobID, r.cfg.NaabuImage, strings.Join(ips, "\n"), naabuArgs...)
	out.WriteString(naabuOut)
	if runErr != nil {
		errOut.WriteString(naabuErr)
		return summary, out.String(), errOut.String(), exitCode, fmt.Errorf("naabu: %w", runErr)
	}

	openPorts := parseNaabu(naabuOut)
	summary["ports"] = len(openPorts)
	if len(openPorts) == 0 {
		return summary, out.String(), errOut.String(), exitCode, nil
	}

	// 4. Fingerprint the open services with nmap -sV (best effort: a timeout
	// here still keeps the port results we already have).
	portSet := map[int]struct{}{}
	for _, p := range openPorts {
		portSet[p.port] = struct{}{}
	}
	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	portList := make([]string, len(ports))
	for i, p := range ports {
		portList[i] = strconv.Itoa(p)
	}

	out.WriteString("\n=== nmap (service detection) ===\n")
	nmapArgs := []string{
		"-sV", "-Pn", "-n", "-T4", "--open",
		"--host-timeout", "45s", "--max-retries", "2",
		"-p", strings.Join(portList, ","), "-iL", "-", "-oG", "-",
	}
	nmapOut, nmapErr, nmapExit, nmapRunErr := r.runContainerInput(ctx, jobID, r.cfg.NmapImage, strings.Join(ips, "\n"), nmapArgs...)
	out.WriteString(nmapOut)
	if nmapRunErr != nil {
		errOut.WriteString(nmapErr)
		log.Printf("netscan: nmap service detection failed (keeping open ports): %v", nmapRunErr)
	} else {
		exitCode = nmapExit
	}
	services := parseNmap(nmapOut)

	// 5. Persist one row per (ip, port, protocol).
	rows := make([]store.NetworkServiceRow, 0, len(openPorts))
	for _, p := range openPorts {
		hostsForIP := ipHosts[p.ip]
		sort.Strings(hostsForIP)
		svc := services[fmt.Sprintf("%s:%d", p.ip, p.port)]
		rows = append(rows, store.NetworkServiceRow{
			IP:       p.ip,
			Port:     p.port,
			Protocol: p.proto,
			State:    "open",
			TLS:      p.tls,
			Service:  svc.Service,
			Product:  svc.Product,
			Version:  svc.Version,
			Hosts:    dedupe(hostsForIP),
		})
	}
	stored, err := r.store.UpsertNetworkServices(ctx, target.ID, jobID, rows)
	if err != nil {
		return summary, out.String(), errOut.String(), exitCode, fmt.Errorf("store network services: %w", err)
	}
	summary["services"] = stored

	return summary, out.String(), errOut.String(), exitCode, nil
}

type dnsxRecord struct {
	Host  string   `json:"host"`
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	CNAME []string `json:"cname"`
}

func parseDnsx(stdout string) []dnsxRecord {
	records := make([]dnsxRecord, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var rec dnsxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Host == "" {
			continue
		}
		if len(rec.A) == 0 && len(rec.AAAA) == 0 && len(rec.CNAME) == 0 {
			continue
		}
		records = append(records, rec)
	}
	return records
}

func parseDnsxPTR(stdout string) map[string][]string {
	out := map[string][]string{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			Host string   `json:"host"`
			PTR  []string `json:"ptr"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Host != "" && len(rec.PTR) > 0 {
			out[rec.Host] = rec.PTR
		}
	}
	return out
}

type openPort struct {
	ip    string
	port  int
	proto string
	tls   bool
}

func parseNaabu(stdout string) []openPort {
	seen := map[string]struct{}{}
	ports := make([]openPort, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			IP       string `json:"ip"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			TLS      bool   `json:"tls"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		ip := net.ParseIP(rec.IP)
		if ip == nil || ip.To4() == nil {
			continue
		}
		proto := strings.ToLower(rec.Protocol)
		if proto == "" {
			proto = "tcp"
		}
		key := fmt.Sprintf("%s:%d/%s", ip.String(), rec.Port, proto)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		ports = append(ports, openPort{ip: ip.String(), port: rec.Port, proto: proto, tls: rec.TLS})
	}
	return ports
}

type nmapService struct {
	Service string
	Product string
	Version string
}

// nmapHostPorts matches a single grepable host record, capturing the IP and the
// ports field. The ports field may be followed by an "Ignored State" note.
var nmapHostPorts = regexp.MustCompile(`^Host:\s+(\S+)\s+\([^)]*\)\s+Ports:\s+(.+)$`)

func parseNmap(stdout string) map[string]nmapService {
	out := map[string]nmapService{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		m := nmapHostPorts.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ip := net.ParseIP(m[1])
		if ip == nil {
			continue
		}
		portsField := m[2]
		if i := strings.IndexByte(portsField, '\t'); i >= 0 {
			portsField = portsField[:i]
		}
		for _, entry := range strings.Split(portsField, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			parts := strings.Split(strings.Trim(entry, "/"), "/")
			if len(parts) < 5 {
				continue
			}
			port, err := strconv.Atoi(parts[0])
			if err != nil || parts[1] != "open" {
				continue
			}
			service := parts[4]
			product, version := "", ""
			if len(parts) >= 7 {
				product, version = splitProductVersion(parts[6])
			}
			out[fmt.Sprintf("%s:%d", ip.String(), port)] = nmapService{
				Service: service,
				Product: product,
				Version: version,
			}
		}
	}
	return out
}

// splitProductVersion splits an nmap RPC string (e.g. "Apache httpd 2.4.41")
// into its product and version components when a version-like token is present.
func splitProductVersion(rpc string) (string, string) {
	rpc = strings.TrimSpace(rpc)
	if rpc == "" {
		return "", ""
	}
	fields := strings.Fields(rpc)
	for i, f := range fields {
		if looksLikeVersion(f) {
			return strings.Join(fields[:i], " "), strings.Join(fields[i:], " ")
		}
	}
	return rpc, ""
}

func looksLikeVersion(s string) bool {
	t := strings.TrimPrefix(strings.ToLower(s), "v")
	if t == "" {
		return false
	}
	return t[0] >= '0' && t[0] <= '9'
}
