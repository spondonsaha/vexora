import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, liveServerScreenshotUrl } from '../lib/api'
import { formatDuration } from '../lib/format'
import type { ScanJob, StepStatus, Workflow, WorkflowStep } from '../lib/types'
import { Badge } from './Badge'
import { RawOutputViewer } from './RawOutputViewer'
import { SectionHeader, StatusPill, CollapsiblePanel } from './ui'

const sectionLabels: Record<string, string> = {
  enum: 'Enumeration',
  scrape: 'Subdomain Scraping',
  urls: 'JavaScript / Link Discovery',
  consolidate_probe: 'Consolidation',
}

const plannedTools: Record<string, string[]> = {
  enum: ['amass'],
  scrape: ['subfinder', 'assetfinder', 'sublist3r', 'findomain', 'ct'],
  urls: ['gau', 'waybackurls', 'katana'],
}

interface ToolMeta {
  label: string
  desc: string
  stat: string
}

const toolMeta: Record<string, ToolMeta> = {
  amass: { label: 'Amass', desc: 'Active + passive DNS enumeration.', stat: 'Subdomains' },
  subfinder: { label: 'Subfinder', desc: 'Passive subdomain sources.', stat: 'Subdomains' },
  assetfinder: { label: 'Assetfinder', desc: 'Related domains & subdomains.', stat: 'Subdomains' },
  sublist3r: { label: 'Sublist3r', desc: 'Search-engine enumeration.', stat: 'Subdomains' },
  findomain: { label: 'Findomain', desc: 'Fast certificate-log search.', stat: 'Subdomains' },
  ct: { label: 'crt.sh', desc: 'Certificate Transparency logs.', stat: 'Subdomains' },
  gau: { label: 'GAU', desc: 'Get All URLs from archives.', stat: 'URLs' },
  waybackurls: { label: 'Waybackurls', desc: 'URLs from the Wayback Machine.', stat: 'URLs' },
  katana: { label: 'Katana', desc: 'Crawl & extract endpoints.', stat: 'URLs' },
}

export function WorkflowPanel({
  scopeTargetId,
  authConfirmed,
}: {
  scopeTargetId: string
  authConfirmed: boolean
}) {
  const queryClient = useQueryClient()

  const workflows = useQuery({
    queryKey: ['workflows', scopeTargetId],
    queryFn: () => api.listWorkflows(scopeTargetId),
    refetchInterval: (query) => {
      const items = (query.state.data?.items ?? []).filter((wf) => wf.workflow_type === 'wildcard')
      return items.some((wf) => wf.status === 'queued' || wf.status === 'running') ? 2500 : false
    },
  })

  const subdomains = useQuery({
    queryKey: ['subdomains', scopeTargetId],
    queryFn: () => api.listSubdomains(scopeTargetId),
    refetchInterval: 8000,
  })

  const liveServers = useQuery({
    queryKey: ['live-servers', scopeTargetId],
    queryFn: () => api.listLiveServers(scopeTargetId),
    refetchInterval: 8000,
  })

  const endpoints = useQuery({
    queryKey: ['endpoints', scopeTargetId],
    queryFn: () => api.listEndpoints(scopeTargetId),
    refetchInterval: 8000,
  })

  const run = useMutation({
    mutationFn: () => api.runWildcardWorkflow(scopeTargetId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['workflows', scopeTargetId] })
    },
  })

  const items = (workflows.data?.items ?? []).filter((wf) => wf.workflow_type === 'wildcard')
  const active: Workflow | undefined = items[0]
  const running = active?.status === 'queued' || active?.status === 'running'
  const subs = subdomains.data?.items ?? []
  const servers = liveServers.data?.items ?? []
  const endpointsList = endpoints.data?.items ?? []
  const steps = active?.steps ?? []

  return (
    <CollapsiblePanel
      id="workflow"
      title="Wildcard workflow"
      description="Enumeration → parallel scraping → consolidate & live-probe → URL discovery."
      status={active ? <StatusPill status={active.status} /> : undefined}
      actions={
        <button
          className="btn btn-primary"
          disabled={!authConfirmed || run.isPending || running}
          title={!authConfirmed ? 'Confirm authorization before running a workflow' : undefined}
          onClick={() => run.mutate()}
        >
          {run.isPending ? 'Starting...' : 'Run Wildcard Workflow'}
        </button>
      }
    >
      {run.isError && (
        <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
          {run.error instanceof ApiError ? run.error.message : 'Failed to start workflow'}
        </p>
      )}

      {active ? (
        <>
          {steps.map((step) => {
            const duration = step.finished_at
              ? formatDuration(step.started_at, step.finished_at)
              : undefined
            if (step.step_key === 'consolidate_probe') {
              return (
                <ConsolidateMilestone
                  key={step.id}
                  step={step}
                  duration={duration}
                  totalSubdomains={subs.length}
                  liveServers={servers.length}
                />
              )
            }
            return <ToolSection key={step.id} step={step} duration={duration} />
          })}
          <DecisionPoint
            status={active.status}
            totalSubdomains={subs.length}
            liveServers={servers.length}
            urls={endpointsList.length}
            interesting={endpointsList.filter((ep) => ep.interesting).length}
          />
        </>
      ) : (
        <p className="card mt-4 p-5 text-sm text-ink-muted">
          No workflow run yet. Run the wildcard workflow to enumerate subdomains and find live
          servers.
        </p>
      )}

      {active?.error && (
        <p className="mt-3 font-mono text-xs text-sev-critical">{active.error}</p>
      )}

      <div id="live-servers" className="card mt-10 overflow-hidden scroll-mt-40">
        <div className="flex items-center justify-between border-b border-accent/25 px-4 py-2.5">
          <span className="section-label font-display font-medium text-ink">Live web servers</span>
          <span className="font-mono text-xs text-ink-muted">{servers.length}</span>
        </div>
        {servers.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            No live servers yet. They appear here after consolidation finishes.
          </p>
        ) : (
          <div className="max-h-96 overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Screenshot</th>
                  <th>Status</th>
                  <th>Title</th>
                  <th>Tech</th>
                  <th>IP</th>
                </tr>
              </thead>
              <tbody>
                {servers.map((srv) => (
                  <tr key={srv.id} className="hover:bg-base-border/30">
                    <td className="font-mono">{srv.url}</td>
                    <td>
                      {srv.screenshot_path ? (
                        <a
                          href={liveServerScreenshotUrl(srv.id)}
                          target="_blank"
                          rel="noreferrer"
                        >
                          <img
                            src={liveServerScreenshotUrl(srv.id)}
                            alt={srv.url}
                            loading="lazy"
                            className="h-12 w-20 rounded border border-base-border object-cover transition-opacity hover:opacity-80"
                          />
                        </a>
                      ) : (
                        <span className="text-ink-muted">-</span>
                      )}
                    </td>
                    <td>
                      {srv.status_code != null && (
                        <Badge tone={srv.status_code < 400 ? 'accent' : 'medium'}>
                          {srv.status_code}
                        </Badge>
                      )}
                    </td>
                    <td className="max-w-xs truncate text-ink-muted">{srv.title || '-'}</td>
                    <td className="text-ink-muted">
                      {Array.isArray(srv.tech_stack) && srv.tech_stack.length > 0
                        ? srv.tech_stack.join(', ')
                        : '-'}
                    </td>
                    <td className="font-mono text-ink-muted">{srv.ip || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div id="endpoints" className="card mt-6 overflow-hidden scroll-mt-40">
        <div className="flex items-center justify-between border-b border-accent/25 px-4 py-2.5">
          <span className="section-label font-display font-medium text-ink">
            Discovered URLs / endpoints
          </span>
          <span className="font-mono text-xs text-ink-muted">
            {endpointsList.length} total &middot;{' '}
            {endpointsList.filter((e) => e.interesting).length} interesting
          </span>
        </div>
        {endpointsList.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            No URLs yet. They appear here after URL discovery completes.
          </p>
        ) : (
          <div className="max-h-96 overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Source</th>
                  <th>Flags</th>
                </tr>
              </thead>
              <tbody>
                {endpointsList.map((ep) => (
                  <tr key={ep.id} className="hover:bg-base-border/30">
                    <td className="max-w-xl truncate font-mono" title={ep.url ?? ep.path}>
                      {ep.url ?? ep.path}
                    </td>
                    <td className="text-ink-muted">{ep.source_tool || '-'}</td>
                    <td>{ep.interesting && <Badge tone="medium">interesting</Badge>}</td>
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

function ToolSection({ step, duration }: { step: WorkflowStep; duration?: string }) {
  const [openJob, setOpenJob] = useState<string | null>(null)
  const jobs = step.jobs ?? []
  const tools = plannedTools[step.step_key] ?? jobs.map((job) => job.tool)
  const sources = (step.summary?.sources ?? {}) as Record<string, number>
  const summaryLine = summarize(step.summary)

  return (
    <section className="mt-10">
      <SectionHeader
        label={sectionLabels[step.step_key] ?? step.title}
        status={step.status}
        description={step.description ?? undefined}
        duration={duration}
      />

      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
        {tools.map((tool) => (
          <ToolCard
            key={tool}
            tool={tool}
            job={jobs.find((job) => job.tool.toLowerCase() === tool.toLowerCase())}
            count={sources[tool]}
            openJobId={openJob}
            onToggleResults={(id) => setOpenJob((prev) => (prev === id ? null : id))}
          />
        ))}
      </div>

      {summaryLine && <p className="mt-3 text-xs text-ink-muted">{summaryLine}</p>}

      {openJob && <RawOutputViewer jobId={openJob} />}
    </section>
  )
}

function ConsolidateMilestone({
  step,
  duration,
  totalSubdomains,
  liveServers,
}: {
  step: WorkflowStep
  duration?: string
  totalSubdomains: number
  liveServers: number
}) {
  return (
    <section className="mt-10">
      <SectionHeader
        label={sectionLabels[step.step_key] ?? step.title}
        status={step.status}
        description={step.description ?? undefined}
        duration={duration}
      />

      <div className="card mt-4 p-6 text-center md:p-8">
        <h3 className="section-title">Consolidate Subdomains &amp; Discover Live Web Servers</h3>
        <p className="mx-auto mt-2 max-w-2xl text-sm text-ink-muted">{firstSentence(step.description)}</p>

        <div className="mt-6 flex flex-col items-center justify-center gap-8 sm:flex-row sm:gap-16">
          <div>
            <div className="stat-number">{totalSubdomains}</div>
            <div className="stat-label mt-1">Unique Subdomains</div>
          </div>
          <div>
            <div className="stat-number">{liveServers}</div>
            <div className="stat-label mt-1">Live Web Servers</div>
          </div>
        </div>

        <div className="mt-6 flex flex-wrap justify-center gap-2">
          <a href="#live-servers" className="btn btn-primary">
            Recon Results
          </a>
          <a href="#live-servers" className="btn">
            Live Servers
          </a>
          <a href="#endpoints" className="btn">
            Endpoints
          </a>
        </div>
      </div>
    </section>
  )
}

function DecisionPoint({
  status,
  totalSubdomains,
  liveServers,
  urls,
  interesting,
}: {
  status: StepStatus
  totalSubdomains: number
  liveServers: number
  urls: number
  interesting: number
}) {
  return (
    <section className="mt-10">
      <SectionHeader
        label="Decision Point"
        status={status}
        description="Review the collected surface and decide what to test manually first. Prioritise the live servers and interesting endpoints with the highest return on effort — then move into the manual-testing modules."
      />

      <div className="card mt-4 p-6 text-center md:p-8">
        <h3 className="section-title">Decision Point &amp; ROI Hand-off</h3>
        <p className="mx-auto mt-2 max-w-2xl text-sm text-ink-muted">
          The recon phase is complete. Use these totals to pick the highest-value targets to test
          next.
        </p>

        <div className="mt-6 flex flex-col items-center justify-center gap-8 sm:flex-row sm:gap-16">
          <div>
            <div className="stat-number">{totalSubdomains}</div>
            <div className="stat-label mt-1">Subdomains</div>
          </div>
          <div>
            <div className="stat-number">{liveServers}</div>
            <div className="stat-label mt-1">Live Web Servers</div>
          </div>
          <div>
            <div className="stat-number">{urls}</div>
            <div className="stat-label mt-1">Discovered URLs</div>
          </div>
          <div>
            <div className="stat-number">{interesting}</div>
            <div className="stat-label mt-1">Interesting</div>
          </div>
        </div>

        <div className="mt-6 flex flex-wrap justify-center gap-2">
          <a href="#live-servers" className="btn btn-primary">
            Recon Results
          </a>
          <a href="#live-servers" className="btn">
            View Live Servers
          </a>
          <a href="#endpoints" className="btn">
            View Endpoints
          </a>
          <a href="#endpoints" className="btn">
            ROI Report
          </a>
        </div>
      </div>
    </section>
  )
}

function ToolCard({
  tool,
  job,
  count,
  openJobId,
  onToggleResults,
}: {
  tool: string
  job: ScanJob | undefined
  count: number | undefined
  openJobId: string | null
  onToggleResults: (id: string) => void
}) {
  const [help, setHelp] = useState(false)
  const meta = toolMeta[tool] ?? { label: tool, desc: '', stat: 'Results' }
  const value = count == null ? (job ? 0 : '\u2014') : count

  return (
    <div className="card flex flex-col items-center p-4 text-center">
      <span className="card-title">{meta.label}</span>
      <p className="mt-1 text-xs italic text-ink-muted">{meta.desc}</p>

      <div className="mt-4">
        <div className="stat-number text-2xl">{value}</div>
        <div className="stat-label mt-1">{meta.stat}</div>
      </div>

      <div className="mt-3">
        {job ? (
          <StatusPill status={job.status} />
        ) : (
          <span className="text-[11px] text-ink-muted">Not started</span>
        )}
      </div>

      <div className="mt-auto flex w-full gap-2 pt-4">
        <button
          type="button"
          className="btn btn-sm flex-1"
          disabled={!job}
          onClick={() => job && onToggleResults(job.id)}
        >
          {job && openJobId === job.id ? 'Hide' : 'Results'}
        </button>
        <button type="button" className="btn btn-sm flex-1" onClick={() => setHelp((v) => !v)}>
          Help
        </button>
      </div>

      {help && meta.desc && (
        <p className="mt-3 w-full rounded border border-base-border bg-base-panel p-2 text-[11px] leading-relaxed text-ink-muted">
          {meta.desc}
        </p>
      )}

      {job?.exit_code != null && job.exit_code !== 0 && (
        <span className="mt-2 font-mono text-[11px] text-sev-critical">exit {job.exit_code}</span>
      )}
    </div>
  )
}

function firstSentence(text: string | null | undefined): string {
  if (!text) return ''
  const match = text.match(/^[^.]*\./)
  return match ? match[0] : text
}

function summarize(summary: Record<string, unknown>): string {
  const parts: string[] = []
  if (typeof summary.total === 'number') parts.push(`${summary.total} subdomains`)
  if (typeof summary.probed === 'number') parts.push(`${summary.probed} probed`)
  if (typeof summary.live === 'number') parts.push(`${summary.live} live`)
  if (typeof summary.hosts === 'number') parts.push(`${summary.hosts} hosts`)
  if (typeof summary.urls === 'number') parts.push(`${summary.urls} urls`)
  if (typeof summary.interesting === 'number') parts.push(`${summary.interesting} interesting`)
  const sources = summary.sources as Record<string, number> | undefined
  if (sources && typeof sources === 'object') {
    const detail = Object.entries(sources)
      .map(([name, count]) => `${name}: ${count}`)
      .join(', ')
    if (detail) parts.push(detail)
  }
  return parts.join(' \u00b7 ')
}
