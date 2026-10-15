import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { formatTime } from '../lib/format'
import type { ScanJobStatus } from '../lib/types'
import { Badge } from './Badge'
import { RawOutputViewer } from './RawOutputViewer'
import { StatusDot, type Tone } from './StatusDot'
import { CollapsiblePanel } from './ui'

const statusTone: Record<ScanJobStatus, Tone> = {
  queued: 'info',
  running: 'low',
  done: 'accent',
  failed: 'critical',
  cancelled: 'info',
}

const statusLabel: Record<ScanJobStatus, string> = {
  queued: 'Queued',
  running: 'Running',
  done: 'Done',
  failed: 'Failed',
  cancelled: 'Cancelled',
}

interface ToolButton {
  tool: string
  label: string
  hint: string
}

const subdomainTools: ToolButton[] = [
  { tool: 'subfinder', label: 'Subfinder', hint: 'Passive subdomain enumeration' },
  { tool: 'amass', label: 'Amass', hint: 'Active + passive enumeration' },
  { tool: 'assetfinder', label: 'Assetfinder', hint: 'Related domains & subdomains' },
  { tool: 'sublist3r', label: 'Sublist3r', hint: 'Search-engine subdomain scraping' },
  { tool: 'findomain', label: 'Findomain', hint: 'Fast certificate-based enumeration' },
  { tool: 'ct', label: 'CT Logs', hint: 'Certificate Transparency lookup' },
]

const urlTools: ToolButton[] = [
  { tool: 'gau', label: 'GAU', hint: 'Fetch known URLs from archives' },
  { tool: 'waybackurls', label: 'Wayback', hint: 'Wayback Machine URLs' },
  { tool: 'katana', label: 'Katana', hint: 'Crawl live hosts for URLs' },
]

const allTools: ToolButton[] = [...subdomainTools, ...urlTools]

export function ScanPanel({
  scopeTargetId,
  authConfirmed,
  showSubdomains = true,
}: {
  scopeTargetId: string
  authConfirmed: boolean
  showSubdomains?: boolean
}) {
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState<string | null>(null)
  const [tool, setTool] = useState<string>(subdomainTools[0].tool)

  const scans = useQuery({
    queryKey: ['scans', scopeTargetId],
    queryFn: () => api.listScans(scopeTargetId),
    refetchInterval: (query) => {
      const items = (query.state.data?.items ?? []).filter((job) => !job.workflow_id)
      return items.some((job) => job.status === 'queued' || job.status === 'running')
        ? 2500
        : false
    },
  })

  const subdomains = useQuery({
    queryKey: ['subdomains', scopeTargetId],
    queryFn: () => api.listSubdomains(scopeTargetId),
    refetchInterval: 5000,
  })

  const run = useMutation({
    mutationFn: (tool: string) => api.runScan(tool, scopeTargetId),
    onSuccess: (job) => {
      setSelected(job.id)
      setLastTool(null)
      void queryClient.invalidateQueries({ queryKey: ['scans', scopeTargetId] })
    },
  })
  const [lastTool, setLastTool] = useState<string | null>(null)

  const jobs = (scans.data?.items ?? []).filter((job) => !job.workflow_id)
  const subs = subdomains.data?.items ?? []
  const active = jobs.some((job) => job.status === 'queued' || job.status === 'running')
  const selectedTool = allTools.find((t) => t.tool === tool) ?? subdomainTools[0]

  const start = (tool: string) => {
    setLastTool(tool)
    run.mutate(tool)
  }

  return (
    <CollapsiblePanel
      id="recon"
      title="Recon (individual tools)"
      description="Run any individual tool on demand — each in its own Docker container."
      status={
        active ? (
          <span className="flex items-center gap-2 text-xs text-ink-muted">
            <StatusDot tone="accent" pulse />
            working
          </span>
        ) : undefined
      }
      actions={
        <button
          className="btn btn-primary"
          disabled={!authConfirmed || run.isPending}
          title={selectedTool.hint}
          onClick={() => start(tool)}
        >
          {run.isPending ? 'Queuing...' : `Run ${selectedTool.label}`}
        </button>
      }
    >
      {!authConfirmed && (
        <p className="text-xs text-sev-medium">Confirm authorization before scanning.</p>
      )}

      <div className="card mt-3 p-4">
        <label className="label" htmlFor="recon-tool">
          Select a tool
        </label>
        <select
          id="recon-tool"
          className="input w-full sm:max-w-xs"
          value={tool}
          onChange={(event) => setTool(event.target.value)}
        >
          <optgroup label="Subdomain enumeration">
            {subdomainTools.map((t) => (
              <option key={t.tool} value={t.tool}>
                {t.label}
              </option>
            ))}
          </optgroup>
          <optgroup label="URL / endpoint discovery">
            {urlTools.map((t) => (
              <option key={t.tool} value={t.tool}>
                {t.label}
              </option>
            ))}
          </optgroup>
        </select>
        {selectedTool.hint && <p className="mt-2 text-xs text-ink-muted">{selectedTool.hint}</p>}
      </div>

      {run.isError && (
        <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
          {lastTool ? `[${lastTool}] ` : ''}
          {run.error instanceof ApiError ? run.error.message : 'Failed to queue scan'}
        </p>
      )}

      <div className="card mt-3 overflow-hidden">
        <div className="border-b border-accent/25 px-4 py-2.5 font-display text-base font-medium text-ink-muted">
          Scan jobs
        </div>
        {jobs.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">No scans yet. Pick a tool above to start.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Tool</th>
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
                    <td>{job.tool}</td>
                    <td>
                      <span className="inline-flex items-center gap-2">
                        <StatusDot tone={statusTone[job.status]} pulse={job.status === 'running'} />
                        {statusLabel[job.status]}
                      </span>
                    </td>
                    <td>{job.exit_code ?? '-'}</td>
                    <td className="text-ink-muted">{formatTime(job.started_at)}</td>
                    <td className="text-ink-muted">{formatTime(job.finished_at)}</td>
                    <td className="text-right">
                      <button
                        className="btn"
                        onClick={() => setSelected((prev) => (prev === job.id ? null : job.id))}
                      >
                        {selected === job.id ? 'Hide' : 'View'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected && <RawOutputViewer jobId={selected} />}

      {showSubdomains && (
      <div className="card mt-4 overflow-hidden">
        <div className="flex items-center justify-between border-b border-accent/25 px-4 py-2.5">
          <span className="font-display text-base font-medium text-ink-muted">Subdomains</span>
          <span className="font-mono text-xs text-ink-muted">{subs.length}</span>
        </div>
        {subs.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            No subdomains yet. Results appear here after a run completes.
          </p>
        ) : (
          <div className="max-h-96 overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Subdomain</th>
                  <th>Source</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {subs.map((sub) => (
                  <tr key={sub.id} className="hover:bg-base-border/30">
                    <td>{sub.subdomain}</td>
                    <td>
                      <Badge tone="muted">{sub.source_tool}</Badge>
                    </td>
                    <td className="text-ink-muted">{formatTime(sub.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      )}
    </CollapsiblePanel>
  )
}

