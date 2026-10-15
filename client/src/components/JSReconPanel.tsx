import { Fragment, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { formatTime } from '../lib/format'
import type { Tone } from './StatusDot'
import { Badge } from './Badge'
import { RawOutputViewer } from './RawOutputViewer'
import { StatusDot } from './StatusDot'
import { CollapsiblePanel } from './ui'

const maxFilesOptions = [25, 50, 100, 250, 500]

const criticalTypes = new Set([
  'aws_key',
  'google_api_key',
  'google_oauth',
  'github_token',
  'slack_token',
  'stripe_key',
  'twilio_key',
  'sendgrid_key',
  'mailgun_key',
  'private_key',
  'credential',
  'jwt',
])

const highTypes = new Set(['s3_bucket', 'firebase', 'internal_ip', 'graphql', 'admin_route'])

function typeTone(type: string): Tone {
  if (criticalTypes.has(type)) return 'critical'
  if (highTypes.has(type)) return 'high'
  if (type === 'api_endpoint') return 'medium'
  if (type === 'subdomain') return 'low'
  return 'info'
}

function typeLabel(type: string): string {
  return type.replace(/_/g, ' ')
}

export function JSReconPanel({
  scopeTargetId,
  authConfirmed,
}: {
  scopeTargetId: string
  authConfirmed: boolean
}) {
  const queryClient = useQueryClient()
  const [maxFiles, setMaxFiles] = useState(100)
  const [selectedJob, setSelectedJob] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<number | null>(null)
  const [typeFilter, setTypeFilter] = useState('')

  const scans = useQuery({
    queryKey: ['scans', scopeTargetId],
    queryFn: () => api.listScans(scopeTargetId),
    refetchInterval: (query) => {
      const items = (query.state.data?.items ?? []).filter((job) => job.tool === 'jsrecon')
      return items.some((job) => job.status === 'queued' || job.status === 'running') ? 2500 : false
    },
  })

  const findings = useQuery({
    queryKey: ['js-findings', scopeTargetId],
    queryFn: () => api.listJSFindings(scopeTargetId),
    refetchInterval: 5000,
  })

  const run = useMutation({
    mutationFn: () => api.runScan('jsrecon', scopeTargetId, { max_files: maxFiles }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['scans', scopeTargetId] })
    },
  })

  const jobs = (scans.data?.items ?? []).filter((job) => job.tool === 'jsrecon')
  const rows = findings.data?.items ?? []
  const running = jobs.some((job) => job.status === 'queued' || job.status === 'running')

  const countsByType = useMemo(() => {
    const counts = new Map<string, number>()
    for (const row of rows) {
      counts.set(row.finding_type, (counts.get(row.finding_type) ?? 0) + 1)
    }
    return counts
  }, [rows])

  const typeOptions = useMemo(
    () => [...countsByType.entries()].sort((a, b) => a[0].localeCompare(b[0])),
    [countsByType],
  )

  const visibleRows = typeFilter ? rows.filter((row) => row.finding_type === typeFilter) : rows

  const jsFiles = new Set(rows.map((r) => r.js_url))
  const secrets = rows.filter((r) => criticalTypes.has(r.finding_type)).length
  const endpoints = rows.filter((r) => r.finding_type === 'api_endpoint').length
  const hosts = rows.filter((r) => r.finding_type === 'subdomain').length

  return (
    <CollapsiblePanel
      id="js-recon"
      title="JavaScript Recon"
      description="Fetch JavaScript assets discovered during URL discovery and extract secrets, API endpoints, hosts and other artifacts."
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
          {run.isPending ? 'Queuing...' : 'Run JS Recon'}
        </button>
      }
    >
      <div className="card p-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="jsrecon-max">
              Max JS files ({maxFiles})
            </label>
            <select
              id="jsrecon-max"
              className="input w-full"
              value={maxFiles}
              onChange={(event) => setMaxFiles(Number(event.target.value))}
            >
              {maxFilesOptions.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>
        </div>

        <p className="mt-3 text-xs text-ink-muted">
          Analyses the <span className="font-mono">.js</span> URLs collected from the wildcard URL
          discovery step (katana -jc / gau / waybackurls). Run the wildcard workflow first so there
          are JavaScript files to inspect.
        </p>

        {run.isError && (
          <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
            {run.error instanceof ApiError ? run.error.message : 'Failed to start JavaScript recon'}
          </p>
        )}
      </div>

      <div className="card mt-4 p-6 text-center md:p-8">
        <h3 className="section-title">JavaScript Recon Summary</h3>
        <p className="mx-auto mt-2 max-w-2xl text-sm text-ink-muted">
          Secrets, endpoints and hosts extracted from the target&apos;s JavaScript.
        </p>
        <div className="mt-6 flex flex-wrap items-center justify-center gap-8 sm:gap-12">
          <div>
            <div className="stat-number">{rows.length}</div>
            <div className="stat-label mt-1">Findings</div>
          </div>
          <div>
            <div className="stat-number">{jsFiles.size}</div>
            <div className="stat-label mt-1">JS files</div>
          </div>
          <div>
            <div className="stat-number">{secrets}</div>
            <div className="stat-label mt-1">Secrets / keys</div>
          </div>
          <div>
            <div className="stat-number">{endpoints}</div>
            <div className="stat-label mt-1">API endpoints</div>
          </div>
          <div>
            <div className="stat-number">{hosts}</div>
            <div className="stat-label mt-1">Hosts</div>
          </div>
        </div>
      </div>

      {jobs.length > 0 && (
        <div className="card mt-4 overflow-hidden">
          <div className="border-b border-accent/25 px-4 py-2.5 font-display text-base font-medium text-ink-muted">
            JS Recon runs
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Max files</th>
                  <th>Exit</th>
                  <th>Started</th>
                  <th className="text-right">Output</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => {
                  const opts =
                    job.options && typeof job.options === 'object'
                      ? (job.options as Record<string, unknown>)
                      : {}
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
                      <td className="font-mono text-xs">{String(opts.max_files ?? '-')}</td>
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
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selectedJob && <RawOutputViewer jobId={selectedJob} />}

      <div className="card mt-6 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-accent/25 px-4 py-2.5">
          <span className="section-label font-display font-medium text-ink">
            JS findings &middot; type / value
          </span>
          <div className="flex items-center gap-2">
            <select
              className="input text-xs"
              value={typeFilter}
              onChange={(event) => setTypeFilter(event.target.value)}
            >
              <option value="">All types ({rows.length})</option>
              {typeOptions.map(([type, count]) => (
                <option key={type} value={type}>
                  {typeLabel(type)} ({count})
                </option>
              ))}
            </select>
          </div>
        </div>
        {rows.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            No findings yet. Run JavaScript recon against a target with discovered JS files.
          </p>
        ) : (
          <div className="max-h-[32rem] overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Source file</th>
                  <th className="text-right">Detail</th>
                </tr>
              </thead>
              <tbody>
                {visibleRows.map((finding) => (
                  <Fragment key={finding.id}>
                    <tr className="align-top hover:bg-base-border/30">
                      <td>
                        <Badge tone={typeTone(finding.finding_type)}>
                          {typeLabel(finding.finding_type)}
                        </Badge>
                      </td>
                      <td className="break-all font-mono text-xs text-ink">{finding.value}</td>
                      <td
                        className="max-w-xs truncate font-mono text-xs text-ink-muted"
                        title={finding.js_url}
                      >
                        {finding.js_url}
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
                    {expanded === finding.id && finding.context && (
                      <tr className="bg-base-border/20">
                        <td colSpan={4} className="px-4 py-3">
                          <pre className="overflow-x-auto rounded border border-base-border bg-base-panel-alt p-2 font-mono text-xs text-ink-muted">
                            {finding.context}
                          </pre>
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
