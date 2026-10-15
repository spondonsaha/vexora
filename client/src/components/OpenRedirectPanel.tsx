import { Fragment, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { formatTime } from '../lib/format'
import type { Tone } from './StatusDot'
import { Badge } from './Badge'
import { RawOutputViewer } from './RawOutputViewer'
import { StatusDot } from './StatusDot'
import { CollapsiblePanel } from './ui'

const maxTargetsOptions = [10, 25, 50, 100, 250]

const typeToneMap: Record<string, Tone> = {
  open_redirect: 'critical',
  dom_redirect: 'high',
  header_injection: 'high',
  javascript_uri: 'medium',
  reflection: 'low',
  redirect_external: 'low',
}

function typeLabel(t: string): string {
  return t.replace(/_/g, ' ')
}

function typeTone(t: string): Tone {
  return typeToneMap[t] ?? 'info'
}

export function OpenRedirectPanel({
  scopeTargetId,
  authConfirmed,
}: {
  scopeTargetId: string
  authConfirmed: boolean
}) {
  const queryClient = useQueryClient()
  const [maxTargets, setMaxTargets] = useState(50)
  const [testAllParams, setTestAllParams] = useState(false)
  const [selectedJob, setSelectedJob] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<number | null>(null)

  const scans = useQuery({
    queryKey: ['scans', scopeTargetId],
    queryFn: () => api.listScans(scopeTargetId),
    refetchInterval: (query) => {
      const items = (query.state.data?.items ?? []).filter((job) => job.tool === 'openredirect')
      return items.some((job) => job.status === 'queued' || job.status === 'running') ? 2500 : false
    },
  })

  const findings = useQuery({
    queryKey: ['open-redirect-findings', scopeTargetId],
    queryFn: () => api.listOpenRedirectFindings(scopeTargetId),
    refetchInterval: 5000,
  })

  const run = useMutation({
    mutationFn: () =>
      api.runScan('openredirect', scopeTargetId, {
        max_targets: maxTargets,
        test_all_params: testAllParams,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['scans', scopeTargetId] })
    },
  })

  const jobs = (scans.data?.items ?? []).filter((job) => job.tool === 'openredirect')
  const rows = findings.data?.items ?? []
  const running = jobs.some((job) => job.status === 'queued' || job.status === 'running')

  const countsByType = useMemo(() => {
    const counts = new Map<string, number>()
    for (const row of rows) {
      counts.set(row.finding_type, (counts.get(row.finding_type) ?? 0) + 1)
    }
    return counts
  }, [rows])

  const urls = new Set(rows.map((r) => r.url))
  const params = new Set(rows.map((r) => `${r.url}\x00${r.parameter}`))

  return (
    <CollapsiblePanel
      id="open-redirect"
      title="Open Redirect"
      description="Probe parameterised URLs for open redirects, client-side redirect sinks, header injection and reflected payloads."
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
          {run.isPending ? 'Queuing...' : 'Run Open Redirect'}
        </button>
      }
    >
      <div className="card p-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="or-max">
              Max targets ({maxTargets})
            </label>
            <select
              id="or-max"
              className="input w-full"
              value={maxTargets}
              onChange={(event) => setMaxTargets(Number(event.target.value))}
            >
              {maxTargetsOptions.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-end">
            <label className="flex items-center gap-2 text-sm text-ink">
              <input
                type="checkbox"
                checked={testAllParams}
                onChange={() => setTestAllParams((v) => !v)}
              />
              Test all query parameters (not just known redirect params)
            </label>
          </div>
        </div>

        <p className="mt-3 text-xs text-ink-muted">
          Targets parameterised endpoints discovered during URL discovery (gau/waybackurls/katana).
          The scanner injects payloads pointing at the canary host and checks for 3xx Location,
          client-side redirect sinks, CRLF header injection and reflected payloads.
        </p>

        {run.isError && (
          <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
            {run.error instanceof ApiError ? run.error.message : 'Failed to start open redirect scan'}
          </p>
        )}
      </div>

      <div className="card mt-4 p-6 text-center md:p-8">
        <h3 className="section-title">Open Redirect Summary</h3>
        <p className="mx-auto mt-2 max-w-2xl text-sm text-ink-muted">
          Candidate issues detected by injecting canary-hosted payloads into redirect-style parameters.
        </p>
        <div className="mt-6 flex flex-wrap items-center justify-center gap-8 sm:gap-12">
          <div>
            <div className="stat-number">{rows.length}</div>
            <div className="stat-label mt-1">Findings</div>
          </div>
          <div>
            <div className="stat-number">{urls.size}</div>
            <div className="stat-label mt-1">URLs</div>
          </div>
          <div>
            <div className="stat-number">{params.size}</div>
            <div className="stat-label mt-1">Params</div>
          </div>
          <div>
            <div className="stat-number">{countsByType.get('open_redirect') ?? 0}</div>
            <div className="stat-label mt-1">Confirmed redirects</div>
          </div>
        </div>
      </div>

      {jobs.length > 0 && (
        <div className="card mt-4 overflow-hidden">
          <div className="border-b border-accent/25 px-4 py-2.5 font-display text-base font-medium text-ink-muted">
            Open redirect runs
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Max targets</th>
                  <th>Test all</th>
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
                      <td className="font-mono text-xs">{String(opts.max_targets ?? '-')}</td>
                      <td className="font-mono text-xs">{String(opts.test_all_params ? 'yes' : 'no')}</td>
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
        <div className="flex items-center justify-between border-b border-accent/25 px-4 py-2.5">
          <span className="section-label font-display font-medium text-ink">
            Open redirect findings &middot; url / parameter
          </span>
          <span className="font-mono text-xs text-ink-muted">{rows.length} findings</span>
        </div>
        {rows.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            No redirect issues found yet. Run Open Redirect against a target with parameterised
            endpoints, or enable &quot;test all parameters&quot;.
          </p>
        ) : (
          <div className="max-h-[32rem] overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>URL</th>
                  <th>Parameter</th>
                  <th>Status</th>
                  <th>Location</th>
                  <th className="text-right">Detail</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((finding) => (
                  <Fragment key={finding.id}>
                    <tr className="align-top hover:bg-base-border/30">
                      <td>
                        <Badge tone={typeTone(finding.finding_type)}>
                          {typeLabel(finding.finding_type)}
                        </Badge>
                      </td>
                      <td className="break-all font-mono text-xs text-ink">{finding.url}</td>
                      <td className="font-mono text-xs text-ink-muted">{finding.parameter}</td>
                      <td className="font-mono text-xs text-ink-muted">{finding.status_code ?? '-'}</td>
                      <td
                        className="max-w-xs truncate font-mono text-xs text-ink-muted"
                        title={finding.location}
                      >
                        {finding.location || '-'}
                      </td>
                      <td className="text-right">
                        <button
                          className="btn"
                          onClick={() => setExpanded((prev) => (prev === finding.id ? null : finding.id))}
                        >
                          {expanded === finding.id ? 'Hide' : 'Show'}
                        </button>
                      </td>
                    </tr>
                    {expanded === finding.id && (
                      <tr className="bg-base-border/20">
                        <td colSpan={6} className="space-y-2 px-4 py-3">
                          {finding.payload && (
                            <div>
                              <span className="label">Payload</span>
                              <pre className="overflow-x-auto rounded border border-base-border bg-base-panel-alt p-2 font-mono text-xs text-ink">
                                {finding.payload}
                              </pre>
                            </div>
                          )}
                          {finding.evidence && (
                            <div>
                              <span className="label">Evidence</span>
                              <pre className="overflow-x-auto rounded border border-base-border bg-base-panel-alt p-2 font-mono text-xs text-ink-muted">
                                {finding.evidence}
                              </pre>
                            </div>
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
