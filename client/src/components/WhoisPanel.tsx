import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { formatTime } from '../lib/format'
import type { Tone } from './StatusDot'
import { Badge } from './Badge'
import { RawOutputViewer } from './RawOutputViewer'
import { StatusDot } from './StatusDot'
import { CollapsiblePanel } from './ui'

const EXPIRY_WARN_DAYS = 90
const EXPIRY_CRITICAL_DAYS = 30

function daysUntil(iso: string | null): number | null {
  if (!iso) return null
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return null
  return Math.ceil((then - Date.now()) / 86_400_000)
}

function expiryTone(days: number | null): Tone | 'muted' {
  if (days === null) return 'muted'
  if (days < EXPIRY_CRITICAL_DAYS) return 'critical'
  if (days < EXPIRY_WARN_DAYS) return 'medium'
  return 'low'
}

function expiryLabel(days: number | null): string {
  if (days === null) return 'unknown'
  if (days < 0) return `expired ${Math.abs(days)}d ago`
  return `${days}d left`
}

export function WhoisPanel({
  scopeTargetId,
  authConfirmed,
}: {
  scopeTargetId: string
  authConfirmed: boolean
}) {
  const queryClient = useQueryClient()
  const [selectedJob, setSelectedJob] = useState<string | null>(null)
  const [expiringOnly, setExpiringOnly] = useState(false)

  const scans = useQuery({
    queryKey: ['scans', scopeTargetId],
    queryFn: () => api.listScans(scopeTargetId),
    refetchInterval: (query) => {
      const items = (query.state.data?.items ?? []).filter((job) => job.tool === 'whois')
      return items.some((job) => job.status === 'queued' || job.status === 'running') ? 2500 : false
    },
  })

  const records = useQuery({
    queryKey: ['whois-records', scopeTargetId],
    queryFn: () => api.listWhoisRecords(scopeTargetId),
    refetchInterval: 5000,
  })

  const run = useMutation({
    mutationFn: () => api.runScan('whois', scopeTargetId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['scans', scopeTargetId] })
    },
  })

  const jobs = (scans.data?.items ?? []).filter((job) => job.tool === 'whois')
  const rows = records.data?.items ?? []
  const running = jobs.some((job) => job.status === 'queued' || job.status === 'running')

  const orgClusters = useMemo(() => {
    const orgs = new Set<string>()
    for (const r of rows) {
      if (r.registrant_org) orgs.add(r.registrant_org.trim().toLowerCase())
    }
    return orgs.size
  }, [rows])

  const expiring = useMemo(
    () => rows.filter((r) => {
      const days = daysUntil(r.expires_at)
      return days !== null && days < EXPIRY_WARN_DAYS
    }),
    [rows],
  )

  const visible = expiringOnly ? expiring : rows

  return (
    <CollapsiblePanel
      id="whois"
      title="WHOIS / Ownership"
      description="Resolve registrant ownership, nameservers and the registration lifecycle for the target's root domain via RDAP."
      defaultOpen={false}
      status={
        running ? (
          <span className="flex items-center gap-2 text-xs text-ink-muted">
            <StatusDot tone="accent" pulse />
            querying
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
          {run.isPending ? 'Queuing...' : 'Run WHOIS'}
        </button>
      }
    >
      <div className="card p-6 text-center md:p-8">
        <h3 className="section-title">WHOIS / Ownership Consolidation</h3>
        <p className="mx-auto mt-2 max-w-2xl text-sm text-ink-muted">
          Registration data clustered by registrant organization, with domains at risk of expiration
          flagged for takeover review.
        </p>

        <div className="mt-6 flex flex-wrap items-center justify-center gap-10 sm:gap-16">
          <div>
            <div className="stat-number">{orgClusters}</div>
            <div className="stat-label mt-1">Registrant orgs</div>
          </div>
          <div>
            <div className={`stat-number ${expiring.length > 0 ? 'text-sev-medium' : ''}`}>
              {expiring.length}
            </div>
            <div className="stat-label mt-1">Expiring &lt; {EXPIRY_WARN_DAYS}d</div>
          </div>
        </div>

        <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
          <button
            className="btn btn-primary"
            disabled={!authConfirmed || run.isPending || running}
            title={!authConfirmed ? 'Confirm authorization before scanning' : undefined}
            onClick={() => run.mutate()}
          >
            {run.isPending ? 'Queuing...' : 'Run WHOIS'}
          </button>
          <button
            className={`btn ${expiringOnly ? 'btn-primary' : ''}`}
            disabled={expiring.length === 0}
            onClick={() => setExpiringOnly((v) => !v)}
          >
            {expiringOnly ? `Show all (${rows.length})` : `Expiring soon (${expiring.length})`}
          </button>
        </div>

        {run.isError && (
          <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
            {run.error instanceof ApiError ? run.error.message : 'Failed to start WHOIS lookup'}
          </p>
        )}
      </div>

      {jobs.length > 0 && (
        <div className="card mt-4 overflow-hidden">
          <div className="border-b border-accent/25 px-4 py-2.5 font-display text-base font-medium text-ink-muted">
            WHOIS runs
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Exit</th>
                  <th>Started</th>
                  <th className="text-right">Output</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <tr key={job.id} className="hover:bg-surface-border/30">
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
                    <td>{job.exit_code ?? '-'}</td>
                    <td className="text-ink-muted">{formatTime(job.started_at)}</td>
                    <td className="text-right">
                      <button
                        className="btn"
                        onClick={() => setSelectedJob((prev) => (prev === job.id ? null : job.id))}
                      >
                        {selectedJob === job.id ? 'Hide' : 'View'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selectedJob && <RawOutputViewer jobId={selectedJob} />}

      <div className="card mt-6 overflow-hidden">
        <div className="flex items-center justify-between border-b border-accent/25 px-4 py-2.5">
          <span className="section-label font-display font-medium text-ink">
            WHOIS records &middot; domain / registrant
          </span>
          <span className="font-mono text-xs text-ink-muted">{visible.length} records</span>
        </div>
        {visible.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            No WHOIS records yet. Run WHOIS to resolve the root domain's registrant, registrar and
            expiry via RDAP.
          </p>
        ) : (
          <div className="max-h-[32rem] overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Registrant</th>
                  <th>Registrar</th>
                  <th>Nameservers</th>
                  <th>Registered</th>
                  <th>Expires</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((rec) => {
                  const days = daysUntil(rec.expires_at)
                  return (
                    <tr key={rec.id} className="align-top hover:bg-surface-border/30">
                      <td className="font-mono text-xs text-ink">{rec.domain}</td>
                      <td className="text-xs text-ink-muted">{rec.registrant_org || 'redacted'}</td>
                      <td className="text-xs text-ink-muted">{rec.registrar || '-'}</td>
                      <td className="text-xs text-ink-muted">
                        {rec.nameservers.length === 0 ? (
                          '-'
                        ) : (
                          <div className="flex flex-col gap-0.5 font-mono text-[11px]">
                            {rec.nameservers.map((ns) => (
                              <span key={ns}>{ns}</span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="font-mono text-xs text-ink-muted">
                        {rec.registered_at ? new Date(rec.registered_at).toLocaleDateString() : '-'}
                      </td>
                      <td className="font-mono text-xs text-ink-muted">
                        {rec.expires_at ? new Date(rec.expires_at).toLocaleDateString() : '-'}
                      </td>
                      <td>
                        <Badge tone={expiryTone(days)}>{expiryLabel(days)}</Badge>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </CollapsiblePanel>
  )
}
