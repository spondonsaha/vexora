import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { formatTime } from '../lib/format'
import type { Subdomain, TakeoverStatus } from '../lib/types'
import { Badge } from './Badge'
import { RawOutputViewer } from './RawOutputViewer'
import { StatusDot, type Tone } from './StatusDot'
import { CollapsiblePanel } from './ui'

const takeoverTone: Record<TakeoverStatus, Tone> = {
  vulnerable: 'critical',
  dangling: 'high',
  edge: 'medium',
  safe: 'low',
  unknown: 'info',
}

const takeoverLabel: Record<TakeoverStatus, string> = {
  vulnerable: 'Vulnerable',
  dangling: 'Dangling',
  edge: 'Edge',
  safe: 'Safe',
  unknown: 'Unknown',
}

function countBy(subdomains: Subdomain[], status: TakeoverStatus): number {
  return subdomains.filter((s) => s.takeover_status === status).length
}

export function TakeoverPanel({
  scopeTargetId,
  authConfirmed,
}: {
  scopeTargetId: string
  authConfirmed: boolean
}) {
  const queryClient = useQueryClient()
  const [selectedJob, setSelectedJob] = useState<string | null>(null)

  const scans = useQuery({
    queryKey: ['scans', scopeTargetId],
    queryFn: () => api.listScans(scopeTargetId),
    refetchInterval: (query) => {
      const items = (query.state.data?.items ?? []).filter((job) => job.tool === 'takeover')
      return items.some((job) => job.status === 'queued' || job.status === 'running') ? 2500 : false
    },
  })

  const subdomains = useQuery({
    queryKey: ['subdomains', scopeTargetId],
    queryFn: () => api.listSubdomains(scopeTargetId),
    refetchInterval: 5000,
  })

  const run = useMutation({
    mutationFn: () => api.runScan('takeover', scopeTargetId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['scans', scopeTargetId] })
    },
  })

  const jobs = (scans.data?.items ?? []).filter((job) => job.tool === 'takeover')
  const subs = subdomains.data?.items ?? []
  const running = jobs.some((job) => job.status === 'queued' || job.status === 'running')
  const checked = subs.filter((s) => s.dns_checked_at).length
  const vulnerable = countBy(subs, 'vulnerable')
  const dangling = countBy(subs, 'dangling')
  const edge = countBy(subs, 'edge')

  return (
    <CollapsiblePanel
      id="takeover"
      title="CNAME, Reverse-DNS & Subdomain Takeover"
      description="Resolve CNAME chains & PTR records, then match against hijackable-service fingerprints."
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
          disabled={!authConfirmed || run.isPending || running || subs.length === 0}
          title={
            !authConfirmed
              ? 'Confirm authorization before scanning'
              : subs.length === 0
                ? 'Enumerate subdomains first'
                : undefined
          }
          onClick={() => run.mutate()}
        >
          {run.isPending ? 'Queuing...' : 'Run Subdomain Takeover'}
        </button>
      }
    >
      {run.isError && (
        <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
          {run.error instanceof ApiError ? run.error.message : 'Failed to start takeover scan'}
        </p>
      )}

      <div className="card mt-4 p-6 text-center md:p-8">
        <h3 className="section-title">Subdomain Takeover Summary</h3>
        <p className="mx-auto mt-2 max-w-2xl text-sm text-ink-muted">
          A subdomain is flagged when its CNAME points at a known hijackable service that is no
          longer claimed, or when its CNAME target no longer resolves (NXDOMAIN).
        </p>

        <div className="mt-6 flex flex-col items-center justify-center gap-8 sm:flex-row sm:gap-14">
          <div>
            <div className={`stat-number ${vulnerable ? 'text-sev-critical' : ''}`}>{vulnerable}</div>
            <div className="stat-label mt-1">Vulnerable</div>
          </div>
          <div>
            <div className="stat-number">{dangling}</div>
            <div className="stat-label mt-1">Dangling</div>
          </div>
          <div>
            <div className="stat-number">{edge}</div>
            <div className="stat-label mt-1">Edge</div>
          </div>
          <div>
            <div className="stat-number">{checked}</div>
            <div className="stat-label mt-1">Checked / {subs.length}</div>
          </div>
        </div>

        {(vulnerable > 0 || dangling > 0) && (
          <p className="mx-auto mt-5 max-w-2xl rounded-lg border border-sev-critical/40 bg-sev-critical/10 p-3 text-sm text-sev-critical">
            {vulnerable > 0
              ? `${vulnerable} subdomain(s) match an unclaimed service — verify ownership before reporting.`
              : `${dangling} subdomain(s) have a non-resolving CNAME target worth manual review.`}
          </p>
        )}
      </div>

      {jobs.length > 0 && (
        <div className="card mt-4 overflow-hidden">
          <div className="border-b border-accent/25 px-4 py-2.5 font-display text-base font-medium text-ink-muted">
            Takeover scans
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Exit</th>
                  <th>Started</th>
                  <th>Finished</th>
                  <th className="text-right">Output</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
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
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selectedJob && <RawOutputViewer jobId={selectedJob} />}

      <div id="subdomains" className="card mt-6 overflow-hidden scroll-mt-40">
        <div className="flex items-center justify-between border-b border-accent/25 px-4 py-2.5">
          <span className="section-label font-display font-medium text-ink">
            Subdomains &middot; CNAME / reverse-DNS / takeover
          </span>
          <span className="font-mono text-xs text-ink-muted">
            {subs.length} total &middot; {checked} checked &middot;{' '}
            <span className={vulnerable + dangling ? 'text-sev-critical' : ''}>
              {vulnerable + dangling} flagged
            </span>
          </span>
        </div>
        {subs.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            No subdomains yet. Run a subdomain tool (e.g. Subfinder) from the Recon section first.
          </p>
        ) : (
          <div className="max-h-96 overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Subdomain</th>
                  <th>CNAME</th>
                  <th>A / Reverse-DNS</th>
                  <th>Takeover</th>
                </tr>
              </thead>
              <tbody>
                {subs.map((sub) => {
                  const status = sub.takeover_status
                  return (
                    <tr key={sub.id} className="align-top hover:bg-base-border/30">
                      <td className="font-mono">{sub.subdomain}</td>
                      <td className="break-all font-mono text-xs text-ink-muted">
                        {sub.cname ||
                          (sub.cname_chain?.length ? sub.cname_chain.join(' \u2192 ') : '-')}
                      </td>
                      <td className="font-mono text-xs text-ink-muted">
                        {sub.a_records?.length ? sub.a_records.join(', ') : '-'}
                        {sub.reverse_dns?.length ? (
                          <span className="block text-ink-muted/70">
                            PTR: {sub.reverse_dns.join(', ')}
                          </span>
                        ) : null}
                      </td>
                      <td>
                        {status ? (
                          <div className="space-y-1">
                            <Badge tone={takeoverTone[status]}>{takeoverLabel[status]}</Badge>
                            {sub.takeover_service && (
                              <span className="block text-[11px] text-ink-muted">
                                {sub.takeover_service}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-[11px] text-ink-muted">not checked</span>
                        )}
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
