import { Fragment, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { formatTime } from '../lib/format'
import type { SQLiTechnique } from '../lib/types'
import { Badge } from './Badge'
import { RawOutputViewer } from './RawOutputViewer'
import { StatusDot } from './StatusDot'
import { CollapsiblePanel } from './ui'

const techniques: { value: SQLiTechnique; label: string; hint: string }[] = [
  { value: 'B', label: 'B — Boolean-based blind', hint: 'Infer data from true/false responses' },
  { value: 'E', label: 'E — Error-based', hint: 'Abuse database error messages' },
  { value: 'U', label: 'U — Union-based', hint: 'UNION query injection' },
  { value: 'S', label: 'S — Stacked queries', hint: 'Chained statements (stacked queries)' },
  { value: 'T', label: 'T — Time-based blind', hint: 'Infer data from response delays' },
  { value: 'Q', label: 'Q — Inline queries', hint: 'Inject within a query clause' },
]

const levelHints: Record<number, string> = {
  1: 'Always test GET/POST parameters',
  2: 'Add Cookie header values',
  3: 'Add User-Agent / Referer headers',
  4: 'Add other headers',
  5: 'Add Host header (slowest, most thorough)',
}

const riskHints: Record<number, string> = {
  1: 'Safe for low-risk environments',
  2: 'Add time-based and heavy-query tests',
  3: 'Add OR-based tests (may modify data)',
}

const dbmsOptions = [
  { value: '', label: 'Auto-detect' },
  { value: 'MySQL', label: 'MySQL / MariaDB' },
  { value: 'PostgreSQL', label: 'PostgreSQL' },
  { value: 'Microsoft SQL Server', label: 'Microsoft SQL Server' },
  { value: 'Oracle', label: 'Oracle' },
  { value: 'SQLite', label: 'SQLite' },
]

const allTechniques: Record<SQLiTechnique, boolean> = {
  B: true,
  E: true,
  U: true,
  S: true,
  T: true,
  Q: true,
}

export function SQLiPanel({
  scopeTargetId,
  authConfirmed,
}: {
  scopeTargetId: string
  authConfirmed: boolean
}) {
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState<Record<SQLiTechnique, boolean>>(allTechniques)
  const [level, setLevel] = useState(1)
  const [risk, setRisk] = useState(1)
  const [threads, setThreads] = useState(4)
  const [dbms, setDbms] = useState('')
  const [tamper, setTamper] = useState('')
  const [forms, setForms] = useState(false)
  const [crawl, setCrawl] = useState(0)
  const [selectedJob, setSelectedJob] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<number | null>(null)

  const scans = useQuery({
    queryKey: ['scans', scopeTargetId],
    queryFn: () => api.listScans(scopeTargetId),
    refetchInterval: (query) => {
      const items = (query.state.data?.items ?? []).filter((job) => job.tool === 'sqli')
      return items.some((job) => job.status === 'queued' || job.status === 'running') ? 2500 : false
    },
  })

  const findings = useQuery({
    queryKey: ['sqli-findings', scopeTargetId],
    queryFn: () => api.listSQLiFindings(scopeTargetId),
    refetchInterval: 5000,
  })

  const technique = techniques
    .filter((t) => selected[t.value])
    .map((t) => t.value)
    .join('')

  const run = useMutation({
    mutationFn: () =>
      api.runScan('sqli', scopeTargetId, {
        technique,
        level,
        risk,
        threads,
        dbms,
        tamper: tamper.trim(),
        forms,
        crawl,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['scans', scopeTargetId] })
    },
  })

  const jobs = (scans.data?.items ?? []).filter((job) => job.tool === 'sqli')
  const rows = findings.data?.items ?? []
  const running = jobs.some((job) => job.status === 'queued' || job.status === 'running')

  const injectableURLs = new Set(rows.map((r) => r.url))
  const parameters = new Set(rows.map((r) => `${r.url}\x00${r.parameter}`))
  const dbmsSet = new Set(rows.map((r) => r.dbms).filter(Boolean))

  const toggleTechnique = (value: SQLiTechnique) => {
    setSelected((prev) => ({ ...prev, [value]: !prev[value] }))
  }

  return (
    <CollapsiblePanel
      id="sqli"
      title="SQL Injection (sqlmap)"
      description="Automated SQL injection testing of discovered parameterised endpoints with advanced techniques."
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
          disabled={!authConfirmed || run.isPending || running || technique === ''}
          title={
            !authConfirmed
              ? 'Confirm authorization before scanning'
              : technique === ''
                ? 'Select at least one technique'
                : undefined
          }
          onClick={() => run.mutate()}
        >
          {run.isPending ? 'Queuing...' : 'Run SQLMap'}
        </button>
      }
    >
      <div className="card p-4">
        <span className="label">Injection techniques</span>
        <div className="mt-1 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {techniques.map((t) => (
            <label
              key={t.value}
              className="flex items-start gap-2 rounded border border-base-border bg-base-panel-alt p-2 text-sm"
            >
              <input
                type="checkbox"
                className="mt-0.5"
                checked={selected[t.value]}
                onChange={() => toggleTechnique(t.value)}
              />
              <span>
                <span className="text-ink">{t.label}</span>
                <span className="block text-[11px] text-ink-muted">{t.hint}</span>
              </span>
            </label>
          ))}
        </div>
        {technique === '' && (
          <p className="mt-2 text-xs text-sev-critical">Select at least one technique.</p>
        )}

        <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <label className="label" htmlFor="sqli-level">
              Level ({level})
            </label>
            <select
              id="sqli-level"
              className="input w-full"
              value={level}
              onChange={(event) => setLevel(Number(event.target.value))}
            >
              {[1, 2, 3, 4, 5].map((n) => (
                <option key={n} value={n}>
                  {n} — {levelHints[n]}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label" htmlFor="sqli-risk">
              Risk ({risk})
            </label>
            <select
              id="sqli-risk"
              className="input w-full"
              value={risk}
              onChange={(event) => setRisk(Number(event.target.value))}
            >
              {[1, 2, 3].map((n) => (
                <option key={n} value={n}>
                  {n} — {riskHints[n]}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label" htmlFor="sqli-threads">
              Threads ({threads})
            </label>
            <select
              id="sqli-threads"
              className="input w-full"
              value={threads}
              onChange={(event) => setThreads(Number(event.target.value))}
            >
              {[1, 2, 4, 6, 8, 10].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label" htmlFor="sqli-dbms">
              Back-end DBMS
            </label>
            <select
              id="sqli-dbms"
              className="input w-full"
              value={dbms}
              onChange={(event) => setDbms(event.target.value)}
            >
              {dbmsOptions.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="sqli-tamper">
              Tamper scripts (comma-separated)
            </label>
            <input
              id="sqli-tamper"
              className="input w-full"
              placeholder="e.g. space2comment,between"
              value={tamper}
              onChange={(event) => setTamper(event.target.value)}
            />
          </div>
          <div>
            <label className="label" htmlFor="sqli-crawl">
              Crawl depth ({crawl === 0 ? 'off' : crawl})
            </label>
            <select
              id="sqli-crawl"
              className="input w-full"
              value={crawl}
              onChange={(event) => setCrawl(Number(event.target.value))}
            >
              {[0, 1, 2, 3, 5].map((n) => (
                <option key={n} value={n}>
                  {n === 0 ? 'Off' : n}
                </option>
              ))}
            </select>
          </div>
        </div>

        <label className="mt-4 flex items-center gap-2 text-sm text-ink">
          <input type="checkbox" checked={forms} onChange={() => setForms((v) => !v)} />
          Parse and test HTML forms on target pages
        </label>

        <p className="mt-3 text-xs text-ink-muted">
          Targets discovered parameterised URLs (query strings) from the wildcard workflow. With no
          parameters, enable forms or crawling to test live servers instead.
        </p>

        {run.isError && (
          <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
            {run.error instanceof ApiError ? run.error.message : 'Failed to start SQLMap scan'}
          </p>
        )}
      </div>

      <div className="card mt-4 p-6 text-center md:p-8">
        <h3 className="section-title">SQL Injection Summary</h3>
        <p className="mx-auto mt-2 max-w-2xl text-sm text-ink-muted">
          sqlmap probes each parameter with the selected techniques. Requires discovered endpoints —
          run the wildcard workflow first.
        </p>
        <div className="mt-6 flex flex-wrap items-center justify-center gap-8 sm:gap-12">
          <div>
            <div className="stat-number">{rows.length}</div>
            <div className="stat-label mt-1">Injection points</div>
          </div>
          <div>
            <div className="stat-number">{injectableURLs.size}</div>
            <div className="stat-label mt-1">Vulnerable URLs</div>
          </div>
          <div>
            <div className="stat-number">{parameters.size}</div>
            <div className="stat-label mt-1">Parameters</div>
          </div>
          <div>
            <div className="stat-number">{dbmsSet.size}</div>
            <div className="stat-label mt-1">DBMS</div>
          </div>
        </div>
      </div>

      {jobs.length > 0 && (
        <div className="card mt-4 overflow-hidden">
          <div className="border-b border-accent/25 px-4 py-2.5 font-display text-base font-medium text-ink-muted">
            SQLMap scans
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Technique</th>
                  <th>Level / risk</th>
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
                      <td className="font-mono text-xs">{String(opts.technique ?? '-')}</td>
                      <td className="font-mono text-xs">
                        {String(opts.level ?? '-')} / {String(opts.risk ?? '-')}
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
            SQL injection findings &middot; url / parameter / technique
          </span>
          <span className="font-mono text-xs text-ink-muted">{rows.length} points</span>
        </div>
        {rows.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            No injection points yet. Run SQLMap against a target with discovered parameters, or
            enable form crawling.
          </p>
        ) : (
          <div className="max-h-[32rem] overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Parameter</th>
                  <th>Technique</th>
                  <th>DBMS</th>
                  <th className="text-right">Detail</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((finding) => (
                  <Fragment key={finding.id}>
                    <tr className="align-top hover:bg-base-border/30">
                      <td className="break-all font-mono text-xs text-ink">{finding.url}</td>
                      <td className="font-mono text-xs text-ink-muted">
                        {finding.parameter}
                        {finding.method && (
                          <span className="ml-1 text-ink-muted/70">({finding.method})</span>
                        )}
                      </td>
                      <td className="text-xs text-ink-muted">{finding.technique || '-'}</td>
                      <td className="text-xs text-ink-muted">{finding.dbms || '-'}</td>
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
                      <tr className="bg-base-border/20">
                        <td colSpan={5} className="space-y-2 px-4 py-3">
                          {finding.title && (
                            <p className="text-sm text-ink-muted">
                              <Badge tone="critical">injectable</Badge> {finding.title}
                            </p>
                          )}
                          {finding.payload && (
                            <pre className="overflow-x-auto rounded border border-base-border bg-base-panel-alt p-2 font-mono text-xs text-ink">
                              {finding.payload}
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
