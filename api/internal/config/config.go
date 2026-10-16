package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port                string
	Env                 string
	DatabaseURL         string
	CORSAllowedOrigins  []string
	DefaultRateLimitRPS int
	DefaultToolTimeout  int
	RawOutputDir        string

	DockerBin              string
	SubfinderImage         string
	AmassImage             string
	GauImage               string
	HttpxImage             string
	AssetfinderImage       string
	Sublist3rImage         string
	FindomainImage         string
	CTImage                string
	WaybackurlsImage       string
	KatanaImage            string
	DomainAuditImage       string
	TakeoverImage          string
	NucleiImage            string
	SQLMapImage            string
	JSReconImage           string
	OpenRedirectImage      string
	SSRFMapImage           string
	GopherusImage          string
	RecollapseImage        string
	SSTImapImage           string
	DnsxImage              string
	NaabuImage             string
	NmapImage              string
	WorkerPollInterval     time.Duration
	ToolTimeout            time.Duration
	WorkflowMaxConcurrency int
	NetworkMaxHosts        int
	SQLiMaxTargets         int
	JSReconMaxFiles        int
	OpenRedirectMaxTargets int
	SSRFMaxTargets         int
	SSRFPollSeconds        int
	SSRFRequestTimeout     int
	SSRFConcurrency        int
	OOBServiceURL          string
	TechMaxTargets         int
	WhoisRDAPBase          string
	WhoisTimeout           int
	TechnologyEnabled      bool
	WhatWebImage           string
	WPScanImage            string
	CMSeeKImage            string
	WhatWebEnabled         bool
	WPScanEnabled          bool
	CMSeeKEnabled          bool
	WhoisEnabled           bool
	AmassEnabled           bool
	AmassActive            bool
	SubfinderEnabled       bool
	AssetfinderEnabled     bool
	Sublist3rEnabled       bool
	FindomainEnabled       bool
	CTEnabled              bool
	GauEnabled             bool
	WaybackurlsEnabled     bool
	KatanaEnabled          bool
	TakeoverEnabled        bool
	NucleiEnabled          bool
	NetworkScanEnabled     bool
	SQLiEnabled            bool
	JSReconEnabled         bool
	OpenRedirectEnabled    bool
	OpenRedirectCanary     string
	SSRFEnabled            bool
}

func Load() Config {
	return Config{
		Port:                env("API_PORT", "8080"),
		Env:                 env("API_ENV", "development"),
		DatabaseURL:         env("DATABASE_URL", "postgres://recon:recon@localhost:5432/recon?sslmode=disable"),
		CORSAllowedOrigins:  splitCSV(env("CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost")),
		DefaultRateLimitRPS: envInt("DEFAULT_RATE_LIMIT_RPS", 10),
		DefaultToolTimeout:  envInt("DEFAULT_TOOL_TIMEOUT_SECONDS", 300),
		RawOutputDir:        env("RAW_OUTPUT_DIR", "/var/lib/recon/raw"),

		DockerBin:              env("DOCKER_BIN", "docker"),
		SubfinderImage:         env("SUBFINDER_IMAGE", "projectdiscovery/subfinder:latest"),
		AmassImage:             env("AMASS_IMAGE", "caffix/amass:latest"),
		GauImage:               env("GAU_IMAGE", "sxcurity/gau:latest"),
		HttpxImage:             env("HTTPX_IMAGE", "projectdiscovery/httpx:latest"),
		AssetfinderImage:       env("ASSETFINDER_IMAGE", "recon/assetfinder:latest"),
		Sublist3rImage:         env("SUBLIST3R_IMAGE", "recon/sublist3r:latest"),
		FindomainImage:         env("FINDOMAIN_IMAGE", "recon/findomain:latest"),
		CTImage:                env("CT_IMAGE", "recon/ct:latest"),
		WaybackurlsImage:       env("WAYBACKURLS_IMAGE", "recon/waybackurls:latest"),
		KatanaImage:            env("KATANA_IMAGE", "projectdiscovery/katana:latest"),
		DomainAuditImage:       env("DOMAIN_AUDIT_IMAGE", "recon/domainaudit:latest"),
		TakeoverImage:          env("TAKEOVER_IMAGE", "recon/takeover:latest"),
		NucleiImage:            env("NUCLEI_IMAGE", "recon/nuclei:latest"),
		SQLMapImage:            env("SQLMAP_IMAGE", "recon/sqlmap:latest"),
		JSReconImage:           env("JSRECON_IMAGE", "recon/jsrecon:latest"),
		OpenRedirectImage:      env("OPENREDIRECT_IMAGE", "recon/openredirect:latest"),
		SSRFMapImage:           env("SSRFMAP_IMAGE", "recon/ssrfmap:latest"),
		GopherusImage:          env("GOPHERUS_IMAGE", "recon/gopherus:latest"),
		RecollapseImage:        env("RECOLLAPSE_IMAGE", "recon/recollapse:latest"),
		SSTImapImage:           env("SSTIMAP_IMAGE", "recon/sstimap:latest"),
		DnsxImage:              env("DNSX_IMAGE", "projectdiscovery/dnsx:latest"),
		NaabuImage:             env("NAABU_IMAGE", "projectdiscovery/naabu:latest"),
		NmapImage:              env("NMAP_IMAGE", "instrumentisto/nmap:latest"),
		WorkerPollInterval:     time.Duration(envInt("WORKER_POLL_SECONDS", 3)) * time.Second,
		ToolTimeout:            time.Duration(envInt("DEFAULT_TOOL_TIMEOUT_SECONDS", 300)) * time.Second,
		WorkflowMaxConcurrency: envInt("WORKFLOW_MAX_CONCURRENCY", 3),
		NetworkMaxHosts:        envInt("NETWORK_MAX_HOSTS", 5000),
		SQLiMaxTargets:         envInt("SQLI_MAX_TARGETS", 10),
		JSReconMaxFiles:        envInt("JSRECON_MAX_FILES", 100),
		OpenRedirectMaxTargets: envInt("OPENREDIRECT_MAX_TARGETS", 50),
		SSRFMaxTargets:         envInt("SSRF_MAX_TARGETS", 25),
		SSRFPollSeconds:        envInt("SSRF_POLL_SECONDS", 20),
		SSRFRequestTimeout:     envInt("SSRF_REQUEST_TIMEOUT_SECONDS", 10),
		SSRFConcurrency:        envInt("SSRF_CONCURRENCY", 6),
		OOBServiceURL:          env("OOB_SERVICE_URL", "http://oob:8090"),
		TechMaxTargets:         envInt("TECH_MAX_TARGETS", 500),
		WhoisRDAPBase:          env("WHOIS_RDAP_BASE", "https://rdap.org"),
		WhoisTimeout:           envInt("WHOIS_TIMEOUT_SECONDS", 20),
		TechnologyEnabled:      envBool("TECHNOLOGY_ENABLED", true),
		WhatWebImage:           env("WHATWEB_IMAGE", "recon/whatweb:latest"),
		WPScanImage:            env("WPSCAN_IMAGE", "recon/wpscan:latest"),
		CMSeeKImage:            env("CMSEEK_IMAGE", "recon/cmseek:latest"),
		WhatWebEnabled:         envBool("WHATWEB_ENABLED", true),
		WPScanEnabled:          envBool("WPSCAN_ENABLED", true),
		CMSeeKEnabled:          envBool("CMSEEK_ENABLED", true),
		WhoisEnabled:           envBool("WHOIS_ENABLED", true),
		AmassEnabled:           envBool("AMASS_ENABLED", true),
		AmassActive:            envBool("AMASS_ACTIVE", true),
		SubfinderEnabled:       envBool("SUBFINDER_ENABLED", true),
		AssetfinderEnabled:     envBool("ASSETFINDER_ENABLED", true),
		Sublist3rEnabled:       envBool("SUBLIST3R_ENABLED", true),
		FindomainEnabled:       envBool("FINDOMAIN_ENABLED", true),
		CTEnabled:              envBool("CT_ENABLED", true),
		GauEnabled:             envBool("GAU_ENABLED", true),
		WaybackurlsEnabled:     envBool("WAYBACKURLS_ENABLED", true),
		KatanaEnabled:          envBool("KATANA_ENABLED", true),
		TakeoverEnabled:        envBool("TAKEOVER_ENABLED", true),
		NucleiEnabled:          envBool("NUCLEI_ENABLED", true),
		NetworkScanEnabled:     envBool("NETWORK_SCAN_ENABLED", true),
		SQLiEnabled:            envBool("SQLI_ENABLED", true),
		JSReconEnabled:         envBool("JSRECON_ENABLED", true),
		OpenRedirectEnabled:    envBool("OPENREDIRECT_ENABLED", true),
		OpenRedirectCanary:     env("OPENREDIRECT_CANARY", "evil.com"),
		SSRFEnabled:            envBool("SSRF_ENABLED", true),
	}
}

func envBool(key string, fallback bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func (c Config) IsProduction() bool {
	return strings.EqualFold(c.Env, "production")
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
