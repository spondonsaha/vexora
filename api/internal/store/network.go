package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
)

// NetworkServiceRow is a single open port + service detected by the netscan
// tool, keyed by (ip, port, protocol).
type NetworkServiceRow struct {
	IP       string
	Port     int
	Protocol string
	State    string
	TLS      bool
	Service  string
	Product  string
	Version  string
	Banner   string
	Hosts    []string
}

// UpsertNetworkServices stores open ports / services for a scope target. The
// hosts array on each row is overwritten with the current set of subdomains
// that resolve to the IP so re-runs stay accurate.
func (s *PGStore) UpsertNetworkServices(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []NetworkServiceRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	payload := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		state := r.State
		if state == "" {
			state = "open"
		}
		protocol := r.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		payload = append(payload, map[string]any{
			"ip":       r.IP,
			"port":     r.Port,
			"protocol": protocol,
			"state":    state,
			"tls":      r.TLS,
			"service":  nullIfEmpty(r.Service),
			"product":  nullIfEmpty(r.Product),
			"version":  nullIfEmpty(r.Version),
			"banner":   nullIfEmpty(r.Banner),
			"hosts":    emptyIfNil(r.Hosts),
		})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	tag, err := s.pool.Exec(ctx,
		`INSERT INTO network_services
		     (scope_target_id, scan_job_id, ip, port, protocol, state, tls,
		      service, product, version, banner, hosts)
		 SELECT $2, $3, v.ip, v.port, v.protocol, v.state, v.tls,
		        v.service, v.product, v.version, v.banner, v.hosts
		 FROM jsonb_to_recordset($1::jsonb) AS v(
		     ip text, port integer, protocol text, state text, tls boolean,
		     service text, product text, version text, banner text, hosts text[]
		 )
		 ON CONFLICT (scope_target_id, ip, port, protocol) DO UPDATE SET
		     scan_job_id = EXCLUDED.scan_job_id,
		     state       = EXCLUDED.state,
		     tls         = EXCLUDED.tls,
		     service     = EXCLUDED.service,
		     product     = EXCLUDED.product,
		     version     = EXCLUDED.version,
		     banner      = EXCLUDED.banner,
		     hosts       = EXCLUDED.hosts,
		     updated_at  = now()`,
		string(encoded), scopeTargetID, scanJobID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *PGStore) ListNetworkServicesByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.NetworkService, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, scope_target_id, scan_job_id, ip, port, protocol, state, tls,
		        service, product, version, banner, COALESCE(hosts, '{}'),
		        created_at, updated_at
		 FROM network_services
		 WHERE scope_target_id = $1
		 ORDER BY ip, port`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	services := make([]models.NetworkService, 0)
	for rows.Next() {
		var svc models.NetworkService
		if err := rows.Scan(&svc.ID, &svc.ScopeTargetID, &svc.ScanJobID, &svc.IP, &svc.Port,
			&svc.Protocol, &svc.State, &svc.TLS, &svc.Service, &svc.Product, &svc.Version,
			&svc.Banner, &svc.Hosts, &svc.CreatedAt, &svc.UpdatedAt); err != nil {
			return nil, err
		}
		services = append(services, svc)
	}
	return services, rows.Err()
}

// SubdomainDNSRow carries the address / CNAME / reverse-DNS enrichment produced
// by the netscan resolver for one already-discovered subdomain. It deliberately
// does not touch the takeover_* columns (owned by the takeover tool).
type SubdomainDNSRow struct {
	Subdomain  string
	CNAME      string
	ARecords   []string
	ReverseDNS []string
}

// UpdateSubdomainDNS writes resolved A/AAAA records, CNAME and reverse DNS back
// onto the matching subdomains without clobbering takeover enrichment.
func (s *PGStore) UpdateSubdomainDNS(ctx context.Context, wildcardTargetID uuid.UUID, rows []SubdomainDNSRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	payload := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		payload = append(payload, map[string]any{
			"subdomain":   r.Subdomain,
			"cname":       nullIfEmpty(r.CNAME),
			"a_records":   emptyIfNil(r.ARecords),
			"reverse_dns": emptyIfNil(r.ReverseDNS),
		})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	tag, err := s.pool.Exec(ctx,
		`UPDATE subdomains s SET
		     cname = v.cname,
		     a_records = v.a_records,
		     reverse_dns = v.reverse_dns,
		     dns_checked_at = now()
		 FROM jsonb_to_recordset($1::jsonb) AS v(
		     subdomain text, cname text, a_records text[], reverse_dns text[]
		 )
		 WHERE s.wildcard_target_id = $2 AND s.subdomain = v.subdomain`,
		string(encoded), wildcardTargetID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
