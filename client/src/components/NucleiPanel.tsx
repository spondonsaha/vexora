import { Fragment, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { formatTime } from '../lib/format'
import type { NucleiCategory, NucleiFinding, NucleiSeverity } from '../lib/types'
import { Badge } from './Badge'
import { RawOutputViewer } from './RawOutputViewer'
import { StatusDot, type Tone } from './StatusDot'
import { CollapsiblePanel } from './ui'

const categories: { value: NucleiCategory; label: string; hint: string }[] = [
  { value: 'xss', label: 'XSS', hint: 'Reflected / DOM cross-site scripting templates' },
  { value: 'cve', label: 'CVEs', hint: 'Known CVE detection templates (largest set)' },
  { value: 'takeover', label: 'Takeover', hint: 'Dangling subdomain takeover templates' },
  { value: 'misconfig', label: 'Misconfig', hint: 'Security misconfiguration & exposure templates' },
  { value: 'all', label: 'All', hint: 'Run every category together' },
]

const severityTone: Record<NucleiSeverity, Tone | 'muted'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  unknown: 'muted',
}

const severityOrder: NucleiSeverity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

function countBySeverity(findings: NucleiFinding[], severity: NucleiSeverity): number {
  return findings.filter((f) => f.severity === severity).length
}

export function NucleiPanel({
  scopeTargetId,
  authConfirmed,
}: {
  scopeTargetId: string
  authConfirmed: boolean
}) {
  const queryClient = useQueryClient()
  const [category, setCategory] = useState<NucleiCategory>('all')
  const [selectedJob, setSelectedJob] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<number | null>(null)

  const scans = useQuery({
    queryKey: ['scans', scopeTargetId],
    queryFn: () => api.listScans(scopeTargetId),
    refetchInterval: (query) => {
      const items = (query.state.data?.items ?? []).filter((job) => job.tool === 'nuclei')
      return items.some((job) => job.status === 'queued' || job.status === 'running') ? 2500 : false
    },
  })

  const findings = useQuery({
    queryKey: ['nuclei-findings', scopeTargetId],
    queryFn: () => api.listNucleiFindings(scopeTargetId),
    refetchInterval: 5000,
  })

  const run = useMutation({
    mutationFn: () => api.runScan('nuclei', scopeTargetId, { category }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['scans', scopeTargetId] })
    },
  })

  const jobs = (scans.data?.items ?? []).filter((job) => job.tool === 'nuclei')
  const rows = findings.data?.items ?? []
  const running = jobs.some((job) => job.status === 'queued' || job.status === 'running')
  const activeHint = categories.find((c) => c.value === category)?.hint

  return (
    <CollapsiblePanel
      id="nuclei"
      title="Nuclei Vulnerability Scanning"
      description="Template-based checks for XSS, CVEs, subdomain takeover & security misconfiguration."
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
          {run.isPending ? 'Queuing...' : 'Run Nuclei'}
        </button>
      }
    >
      <div className="card p-4">
        <label className="label" htmlFor="nuclei-category">
          Template category
        </label>
        <select
          id="nuclei-category"
          className="input w-full sm:max-w-xs"
          value={category}
          onChange={(event) => setCategory(event.target.value as NucleiCategory)}
        >
          {categories.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </select>
        {activeHint && <p className="mt-2 text-xs text-ink-muted">{activeHint}</p>}

        {run.isError && (
          <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
            {run.error instanceof ApiError ? run.error.message : 'Failed to start nuclei scan'}
          </p>
        )}
      </div>

      <div className="card mt-4 p-6 text-center md:p-8">
        <h3 className="section-title">Findings Summary</h3>
        <p className="mx-auto mt-2 max-w-2xl text-sm text-ink-muted">
          Template matches discovered for this target. CVE, XSS and misconfig categories scan live
          web servers; the takeover category scans discovered subdomains.
        </p>

        <div className="mt-6 flex flex-wrap items-center justify-center gap-8 sm:gap-12">
          {severityOrder.map((sev) => (
            <div key={sev}>
              <div
                className={`stat-number ${sev === 'critical' || sev === 'high' ? 'text-sev-critical' : ''}`}
              >
                {countBySeverity(rows, sev)}
              </div>
              <div className="stat-label mt-1 capitalize">{sev}</div>
            </div>
          ))}
          <div>
            <div className="stat-number">{rows.length}</div>
            <div className="stat-label mt-1">Total</div>
          </div>
        </div>
      </div>

      {jobs.length > 0 && (
        <div className="card mt-4 overflow-hidden">
          <div className="border-b border-accent/25 px-4 py-2.5 font-display text-base font-medium text-ink-muted">
            Nuclei scans
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Category</th>
                  <th>Exit</th>
                  <th>Started</th>
                  <th>Finished</th>
                  <th className="text-right">Output</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => {
                  const jobCategory =
                    job.options && typeof job.options === 'object' && 'category' in job.options
                      ? String((job.options as { category?: unknown }).category ?? '-')
                      : '-'
                  return (
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
                      <td className="font-mono text-xs">{jobCategory}</td>
                      <td>{job.exit_code ?? '-'}</td>
                      <td className="text-ink-muted">{formatTime(job.started_at)}</td>
                      <td className="text-ink-muted">{formatTime(job.finished_at)}</td>
                      <td className="text-right">
                        <button
                          className="btn"
                          onClick={() =>
                            setSelectedJob((prev) => (prev === job.id ? null : job.id))
                          }
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
            Findings &middot; severity / template / host
          </span>
          <span className="font-mono text-xs text-ink-muted">{rows.length} findings</span>
        </div>
        {rows.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            No findings yet. Pick a category and run Nuclei. CVE/misconfig scans need live web
            servers, which come from the wildcard workflow.
          </p>
        ) : (
          <div className="max-h-[32rem] overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Host / matched at</th>
                  <th>Category</th>
                  <th>CVSS</th>
                  <th className="text-right">Detail</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((finding) => (
                  <Fragment key={finding.id}>
                    <tr className="align-top hover:bg-surface-border/30">
                      <td>
                        <Badge tone={severityTone[finding.severity]}>{finding.severity}</Badge>
                      </td>
                      <td>
                        <span className="text-sm text-ink">{finding.name}</span>
                        <span className="block font-mono text-[11px] text-ink-muted">
                          {finding.template_id}
                        </span>
                      </td>
                      <td className="break-all font-mono text-xs text-ink-muted">
                        {finding.matched_at}
                        {finding.host && finding.host !== finding.matched_at && (
                          <span className="block text-ink-muted/70">host: {finding.host}</span>
                        )}
                      </td>
                      <td className="text-xs text-ink-muted">{finding.category}</td>
                      <td className="font-mono text-xs text-ink-muted">
                        {finding.cvss_score ?? '-'}
                      </td>
                      <td className="text-right">
                        <button
                          className="btn"
                          onClick={() =>
                            setExpanded((prev) => (prev === finding.id ? null : finding.id))
                          }
                        >
                          {expanded === finding.id ? 'Hide' : 'Show'}
                        </button>
                      </td>
                    </tr>
                    {expanded === finding.id && (
                      <tr className="bg-surface-border/20">
                        <td colSpan={6} className="space-y-2 px-4 py-3">
                          {finding.description && (
                            <p className="text-sm text-ink-muted">{finding.description}</p>
                          )}
                          {finding.extracted.length > 0 && (
                            <p className="font-mono text-xs text-ink">
                              detail: {finding.extracted.join(', ')}
                            </p>
                          )}
                          {finding.tags.length > 0 && (
                            <p className="text-xs text-ink-muted">
                              tags: {finding.tags.join(', ')}
                            </p>
                          )}
                          {finding.reference.length > 0 && (
                            <p className="text-xs">
                              {finding.reference.map((ref) => (
                                <a
                                  key={ref}
                                  href={ref}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="mr-3 text-accent hover:underline"
                                >
                                  {ref}
                                </a>
                              ))}
                            </p>
                          )}
                          {finding.curl_command && (
                            <pre className="overflow-x-auto rounded border border-surface-border bg-surface-panel p-2 font-mono text-xs text-ink-muted">
                              {finding.curl_command}
                            </pre>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </CollapsiblePanel>
  )
}
