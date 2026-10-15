import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { formatTime } from '../lib/format'
import type { PortProfile } from '../lib/types'
import { Badge } from './Badge'
import { RawOutputViewer } from './RawOutputViewer'
import { StatusDot } from './StatusDot'
import { CollapsiblePanel } from './ui'

const profiles: { value: PortProfile; label: string; hint: string }[] = [
  { value: 'top100', label: 'Top 100', hint: 'Fast scan of the 100 most common TCP ports' },
  { value: 'top1000', label: 'Top 1000', hint: 'Full common-port scan (slower, more coverage)' },
  { value: 'full', label: 'All 65535', hint: 'Full TCP sweep — very slow, use sparingly' },
]

export function NetworkPanel({
  scopeTargetId,
  authConfirmed,
}: {
  scopeTargetId: string
  authConfirmed: boolean
}) {
  const queryClient = useQueryClient()
  const [profile, setProfile] = useState<PortProfile>('top100')
  const [selectedJob, setSelectedJob] = useState<string | null>(null)

  const scans = useQuery({
    queryKey: ['scans', scopeTargetId],
    queryFn: () => api.listScans(scopeTargetId),
    refetchInterval: (query) => {
      const items = (query.state.data?.items ?? []).filter((job) => job.tool === 'netscan')
      return items.some((job) => job.status === 'queued' || job.status === 'running') ? 2500 : false
    },
  })

  const services = useQuery({
    queryKey: ['network-services', scopeTargetId],
    queryFn: () => api.listNetworkServices(scopeTargetId),
    refetchInterval: 5000,
  })

  const subdomains = useQuery({
    queryKey: ['subdomains', scopeTargetId],
    queryFn: () => api.listSubdomains(scopeTargetId),
    refetchInterval: 5000,
  })

  const run = useMutation({
    mutationFn: () => api.runScan('netscan', scopeTargetId, { profile }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['scans', scopeTargetId] })
    },
  })

  const jobs = (scans.data?.items ?? []).filter((job) => job.tool === 'netscan')
  const rows = services.data?.items ?? []
  const subs = subdomains.data?.items ?? []
  const running = jobs.some((job) => job.status === 'queued' || job.status === 'running')
  const activeHint = profiles.find((p) => p.value === profile)?.hint

  const resolved = subs.filter((s) => s.a_records.length > 0)
  const ipSet = new Set<string>()
  for (const s of resolved) for (const ip of s.a_records) ipSet.add(ip)
  const productCount = rows.filter((r) => r.service).length

  return (
    <CollapsiblePanel
      id="network"
      title="Network Recon"
      description="Resolve subdomains to IPs, port scan unique hosts, reverse-DNS and fingerprint services."
      defaultOpen={false}
      status={
        running ? (
          <span className="flex items-center gap-2 text-xs text-ink-muted">
            <StatusDot tone="accent" pulse />
            scanning
          </span>
        ) : undefined
      }
      actions={
        <button
          className="btn btn-primary"
          disabled={!authConfirmed || run.isPending || running}
          title={!authConfirmed ? 'Confirm authorization before scanning' : undefined}
          onClick={() => run.mutate()}
        >
          {run.isPending ? 'Queuing...' : 'Run Network Scan'}
        </button>
      }
    >
      <div className="card p-4">
        <label className="label" htmlFor="network-profile">
          Port profile
        </label>
        <select
          id="network-profile"
          className="input w-full sm:max-w-xs"
          value={profile}
          onChange={(event) => setProfile(event.target.value as PortProfile)}
        >
          {profiles.map((p) => (
            <option key={p.value} value={p.value}>
              {p.label}
            </option>
          ))}
        </select>
        {activeHint && <p className="mt-2 text-xs text-ink-muted">{activeHint}</p>}

        {run.isError && (
          <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
            {run.error instanceof ApiError ? run.error.message : 'Failed to start network scan'}
          </p>
        )}
      </div>

      <div className="card mt-4 p-6 text-center md:p-8">
        <h3 className="section-title">Network Summary</h3>
        <p className="mx-auto mt-2 max-w-2xl text-sm text-ink-muted">
          dnsx resolves each subdomain, naabu scans the unique IPs and nmap fingerprints the open
          ports. Requires discovered subdomains — run the wildcard workflow first.
        </p>
        <div className="mt-6 flex flex-wrap items-center justify-center gap-8 sm:gap-12">
          <div>
            <div className="stat-number">{resolved.length}</div>
            <div className="stat-label mt-1">Resolved hosts</div>
          </div>
          <div>
            <div className="stat-number">{ipSet.size}</div>
            <div className="stat-label mt-1">Unique IPs</div>
          </div>
          <div>
            <div className="stat-number">{rows.length}</div>
            <div className="stat-label mt-1">Open ports</div>
          </div>
          <div>
            <div className="stat-number">{productCount}</div>
            <div className="stat-label mt-1">Services</div>
          </div>
        </div>
      </div>

      {jobs.length > 0 && (
        <div className="card mt-4 overflow-hidden">
          <div className="border-b border-accent/25 px-4 py-2.5 font-display text-base font-medium text-ink-muted">
            Network scans
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Profile</th>
                  <th>Exit</th>
                  <th>Started</th>
                  <th>Finished</th>
                  <th className="text-right">Output</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => {
                  const jobProfile =
                    job.options && typeof job.options === 'object' && 'profile' in job.options
                      ? String((job.options as { profile?: unknown }).profile ?? '-')
                      : '-'
                  return (
                    <tr key={job.id} className="hover:bg-base-border/30">
                      <td>
                        <span className="inline-flex items-center gap-2">
                          <StatusDot
                            tone={
                              job.status === 'failed'
                                ? 'critical'
                                : job.status === 'done'
                                  ? 'accent'
                                  : 'low'
                            }
                            pulse={job.status === 'running'}
                          />
                          {job.status}
                        </span>
                      </td>
                      <td className="font-mono text-xs">{jobProfile}</td>
                      <td>{job.exit_code ?? '-'}</td>
                      <td className="text-ink-muted">{formatTime(job.started_at)}</td>
                      <td className="text-ink-muted">{formatTime(job.finished_at)}</td>
                      <td className="text-right">
                        <button
                          className="btn"
                          onClick={() => setSelectedJob((prev) => (prev === job.id ? null : job.id))}
                        >
                          {selectedJob === job.id ? 'Hide' : 'View'}
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selectedJob && <RawOutputViewer jobId={selectedJob} />}

      <div className="card mt-6 overflow-hidden">
        <div className="flex items-center justify-between border-b border-accent/25 px-4 py-2.5">
          <span className="section-label font-display font-medium text-ink">
            IP inventory &middot; subdomain / address / reverse DNS
          </span>
          <span className="font-mono text-xs text-ink-muted">{resolved.length} hosts</span>
        </div>
        {resolved.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            No resolved subdomains yet. Run a network scan to resolve discovered subdomains to their
            IP addresses.
          </p>
        ) : (
          <div className="max-h-[28rem] overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Subdomain</th>
                  <th>IP addresses</th>
                  <th>CNAME</th>
                  <th>Reverse DNS</th>
                </tr>
              </thead>
              <tbody>
                {resolved.map((sub) => (
                  <tr key={sub.id} className="align-top hover:bg-base-border/30">
                    <td className="font-mono text-xs text-ink">{sub.subdomain}</td>
                    <td className="font-mono text-xs text-ink-muted">
                      {sub.a_records.map((ip) => (
                        <span key={ip} className="block">
                          {ip}
                        </span>
                      ))}
                    </td>
                    <td className="break-all font-mono text-xs text-ink-muted">
                      {sub.cname ?? '-'}
                    </td>
                    <td className="break-all font-mono text-xs text-ink-muted">
                      {sub.reverse_dns.length > 0 ? sub.reverse_dns.join(', ') : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card mt-6 overflow-hidden">
        <div className="flex items-center justify-between border-b border-accent/25 px-4 py-2.5">
          <span className="section-label font-display font-medium text-ink">
            Ports &amp; services &middot; ip / port / service
          </span>
          <span className="font-mono text-xs text-ink-muted">{rows.length} open</span>
        </div>
        {rows.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            No open ports recorded yet. Run a network scan to populate this table.
          </p>
        ) : (
          <div className="max-h-[32rem] overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Port</th>
                  <th>Service</th>
                  <th>Product / version</th>
                  <th>Hosts</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((svc) => (
                  <tr key={svc.id} className="align-top hover:bg-base-border/30">
                    <td className="font-mono text-xs text-ink">{svc.ip}</td>
                    <td className="font-mono text-xs text-ink-muted">
                      {svc.port}/{svc.protocol}
                      {svc.tls && (
                        <>
                          {' '}
                          <Badge tone="low">tls</Badge>
                        </>
                      )}
                    </td>
                    <td className="text-xs text-ink-muted">{svc.service ?? '-'}</td>
                    <td className="text-xs text-ink-muted">
                      {[svc.product, svc.version].filter(Boolean).join(' ') || '-'}
                    </td>
                    <td className="break-all font-mono text-[11px] text-ink-muted">
                      {svc.hosts.length > 0 ? svc.hosts.join(', ') : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </CollapsiblePanel>
  )
}
