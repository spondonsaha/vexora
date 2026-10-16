import { Fragment, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import type { Technology } from '../lib/types'
import { formatTime } from '../lib/format'
import type { Tone } from './StatusDot'
import { Badge } from './Badge'
import { RawOutputViewer } from './RawOutputViewer'
import { StatusDot } from './StatusDot'
import { CollapsiblePanel } from './ui'

const maxTargetsOptions = [100, 250, 500, 1000]

const categoryToneMap: Record<string, Tone> = {
  cms: 'medium',
  framework: 'low',
  server: 'info',
  'js-library': 'info',
  analytics: 'info',
  cdn: 'low',
  waf: 'medium',
  language: 'info',
  database: 'high',
  'wordpress-theme': 'low',
  'wordpress-plugin': 'low',
  other: 'info',
}

const fingerprintTools: { name: string; tag: string; blurb: string; tool?: string }[] = [
  {
    name: 'httpx',
    tag: '-tech-detect',
    blurb: 'Fast first pass over every live server.',
    tool: 'techdetect',
  },
  {
    name: 'WhatWeb',
    tag: 'signatures',
    blurb: 'Deeper matching (1800+ signatures).',
    tool: 'whatweb',
  },
  {
    name: 'CMSeeK',
    tag: 'CMS deep scan',
    blurb: 'CMS, version and plugin enumeration.',
    tool: 'cmseek',
  },
  {
    name: 'WPScan',
    tag: 'WordPress',
    blurb: 'Auto-chains when WordPress is detected.',
    tool: 'wpscan',
  },
  {
    name: 'Wappalyzer',
    tag: 'CLI',
    blurb: 'Cross-check detection coverage.',
  },
  {
    name: 'retire.js',
    tag: 'JS libraries',
    blurb: 'Flags vulnerable JavaScript libraries.',
  },
]

const fingerprintToolKeys = fingerprintTools
  .map((tool) => tool.tool)
  .filter((tool): tool is string => Boolean(tool))

function categoryTone(category: string): Tone {
  return categoryToneMap[category] ?? 'info'
}

const categoryLabel: Record<string, string> = {
  cms: 'CMS',
  framework: 'Framework',
  server: 'Server',
  'js-library': 'JS Library',
  analytics: 'Analytics',
  cdn: 'CDN',
  waf: 'WAF',
  language: 'Language',
  database: 'Database',
  'wordpress-theme': 'WordPress Theme',
  'wordpress-plugin': 'WordPress Plugin',
  other: 'Other',
}

const categoryOrder = [
  'cms',
  'wordpress-theme',
  'wordpress-plugin',
  'framework',
  'language',
  'server',
  'database',
  'js-library',
  'analytics',
  'cdn',
  'waf',
  'other',
]

// MergedTechnology is the deduplicated union of a technology as reported by one
// or more detectors, aggregated across the live servers it was seen on.
interface MergedTechnology {
  key: string
  category: string
  name: string
  version: string
  tools: string[]
  serverIds: string[]
  cves: string[]
}

function nameKey(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '')
}

function categoryRank(category: string): number {
  const index = categoryOrder.indexOf(category)
  return index === -1 ? categoryOrder.length : index
}

function mergeTechnologies(rows: Technology[]): MergedTechnology[] {
  const map = new Map<
    string,
    MergedTechnology & { categoryVotes: Map<string, number>; labelVotes: Map<string, number> }
  >()
  for (const row of rows) {
    // Normalise case, spacing and punctuation so variants reported by different
    // detectors ("Atlassian-JIRA" / "Atlassian Jira", "Nginx" / "nginx") merge.
    const key = `${nameKey(row.name)}\u0000${row.version.toLowerCase()}`
    let group = map.get(key)
    if (!group) {
      group = {
        key,
        category: row.category,
        name: row.name,
        version: row.version,
        tools: [],
        serverIds: [],
        cves: [],
        categoryVotes: new Map(),
        labelVotes: new Map(),
      }
      map.set(key, group)
    }
    group.categoryVotes.set(row.category, (group.categoryVotes.get(row.category) ?? 0) + 1)
    group.labelVotes.set(row.name, (group.labelVotes.get(row.name) ?? 0) + 1)
    if (!group.tools.includes(row.detected_by)) group.tools.push(row.detected_by)
    if (!group.serverIds.includes(row.live_web_server_id)) group.serverIds.push(row.live_web_server_id)
    for (const cve of row.cve_refs ?? []) {
      if (!group.cves.includes(cve)) group.cves.push(cve)
    }
  }

  const pick = (
    votes: Map<string, number>,
    prefer: (a: string, b: string) => number,
  ): string => {
    let best = ''
    let bestCount = -1
    for (const [value, count] of votes) {
      if (count > bestCount || (count === bestCount && prefer(value, best) < 0)) {
        best = value
        bestCount = count
      }
    }
    return best
  }

  const merged = Array.from(map.values()).map((group): MergedTechnology => {
    const category = pick(
      group.categoryVotes,
      (a, b) => categoryRank(a) - categoryRank(b),
    )
    // Prefer the most descriptive label: mixed case, longer, with spaces.
    const name = pick(group.labelVotes, (a, b) => b.length - a.length || a.localeCompare(b))
    return {
      key: group.key,
      category,
      name,
      version: group.version,
      tools: group.tools,
      serverIds: group.serverIds,
      cves: group.cves,
    }
  })

  // Fold a version-less entry into its only versioned sibling (e.g. "nginx" and
  // "nginx 1.14.2" reported by different detectors become one row).
  const byName = new Map<string, MergedTechnology[]>()
  for (const item of merged) {
    const list = byName.get(nameKey(item.name)) ?? []
    list.push(item)
    byName.set(nameKey(item.name), list)
  }
  const absorbed = new Set<string>()
  const union = (a: string[], b: string[]) => [...a, ...b.filter((value) => !a.includes(value))]
  for (const list of byName.values()) {
    const versioned = list.filter((item) => item.version)
    const blank = list.filter((item) => !item.version)
    if (versioned.length === 1 && blank.length === 1) {
      const target = versioned[0]
      const extra = blank[0]
      target.tools = union(target.tools, extra.tools)
      target.serverIds = union(target.serverIds, extra.serverIds)
      target.cves = union(target.cves, extra.cves)
      absorbed.add(extra.key)
    }
  }

  return merged
    .filter((item) => !absorbed.has(item.key))
    .sort(
      (a, b) =>
        categoryRank(a.category) - categoryRank(b.category) ||
        a.name.localeCompare(b.name) ||
        a.version.localeCompare(b.version),
    )
}

export function TechnologyPanel({
  scopeTargetId,
  authConfirmed,
}: {
  scopeTargetId: string
  authConfirmed: boolean
}) {
  const queryClient = useQueryClient()
  const [maxTargets, setMaxTargets] = useState(500)
  const [selectedJob, setSelectedJob] = useState<string | null>(null)

  const scans = useQuery({
    queryKey: ['scans', scopeTargetId],
    queryFn: () => api.listScans(scopeTargetId),
    refetchInterval: (query) => {
      const items = (query.state.data?.items ?? []).filter((job) =>
        fingerprintToolKeys.includes(job.tool),
      )
      return items.some((job) => job.status === 'queued' || job.status === 'running') ? 2500 : false
    },
  })

  const technologies = useQuery({
    queryKey: ['technologies', scopeTargetId],
    queryFn: () => api.listTechnologies(scopeTargetId),
    refetchInterval: 5000,
  })

  const servers = useQuery({
    queryKey: ['live-servers', scopeTargetId],
    queryFn: () => api.listLiveServers(scopeTargetId),
  })

  const run = useMutation({
    mutationFn: (tool: string) =>
      api.runScan(tool, scopeTargetId, { max_targets: maxTargets }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['scans', scopeTargetId] })
    },
  })

  const jobs = (scans.data?.items ?? []).filter((job) =>
    fingerprintToolKeys.includes(job.tool),
  )
  const rows = technologies.data?.items ?? []
  const running = jobs.some((job) => job.status === 'queued' || job.status === 'running')

  const urlByServer = useMemo(() => {
    const map = new Map<string, string>()
    for (const srv of servers.data?.items ?? []) {
      map.set(srv.id, srv.url)
    }
    return map
  }, [servers.data])

  const merged = useMemo(() => mergeTechnologies(rows), [rows])
  const categories = new Set(rows.map((r) => r.category))
  const hosts = new Set(rows.map((r) => r.live_web_server_id))

  return (
    <CollapsiblePanel
      id="fingerprint"
      title="Technology Fingerprinting"
      description="Fingerprint the CMS, frameworks, servers, JS libraries, analytics, CDNs and WAFs running on every live server."
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
          onClick={() => run.mutate('techdetect')}
        >
          {run.isPending && run.variables === 'techdetect' ? 'Queuing...' : 'Run Fingerprinting'}
        </button>
      }
    >
      <div className="card p-4">
        <label className="label" htmlFor="tech-max">
          Max live servers ({maxTargets})
        </label>
        <select
          id="tech-max"
          className="input w-full sm:w-48"
          value={maxTargets}
          onChange={(event) => setMaxTargets(Number(event.target.value))}
        >
          {maxTargetsOptions.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>

        <p className="mt-3 text-xs text-ink-muted">
          Runs the technology detectors against the live web servers discovered during the wildcard
          workflow. Results from every detector merge into one deduplicated view below. Proxy
          technologies are often reported by the CDN in front of the origin, so confirm the true
          origin before reporting.
        </p>

        {run.isError && (
          <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
            {run.error instanceof ApiError ? run.error.message : 'Failed to start fingerprinting'}
          </p>
        )}

        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {fingerprintTools.map((tool) => {
            const active = Boolean(tool.tool)
            const pendingTool = run.isPending ? run.variables : undefined
            return (
              <div
                key={tool.name}
                className={`rounded-lg border p-3 ${
                  active ? 'border-accent/40 bg-accent/5' : 'border-surface-border bg-surface-panel'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-ink">{tool.name}</span>
                  <span className="font-mono text-[11px] text-ink-muted">{tool.tag}</span>
                  <span className="ml-auto">
                    {active ? (
                      <Badge tone="accent">Active</Badge>
                    ) : (
                      <Badge tone="muted">Planned</Badge>
                    )}
                  </span>
                </div>
                <p className="mt-1 text-xs text-ink-muted">{tool.blurb}</p>
                {active && (
                  <button
                    className="btn mt-2 w-full"
                    disabled={!authConfirmed || run.isPending || running}
                    title={!authConfirmed ? 'Confirm authorization before scanning' : undefined}
                    onClick={() => tool.tool && run.mutate(tool.tool)}
                  >
                    {pendingTool === tool.tool ? 'Queuing...' : `Run ${tool.name}`}
                  </button>
                )}
              </div>
            )
          })}
        </div>
      </div>

      <div className="card mt-4 p-6 text-center md:p-8">
        <h3 className="section-title">Fingerprint Summary</h3>
        <p className="mx-auto mt-2 max-w-2xl text-sm text-ink-muted">
          Technologies detected across the live servers for this target, deduplicated across tools.
        </p>
        <div className="mt-6 flex flex-wrap items-center justify-center gap-8 sm:gap-12">
          <div>
            <div className="stat-number">{merged.length}</div>
            <div className="stat-label mt-1">Technologies</div>
          </div>
          <div>
            <div className="stat-number">{hosts.size}</div>
            <div className="stat-label mt-1">Servers</div>
          </div>
          <div>
            <div className="stat-number">{categories.size}</div>
            <div className="stat-label mt-1">Categories</div>
          </div>
          <div>
            <div className="stat-number">{rows.length}</div>
            <div className="stat-label mt-1">Detections</div>
          </div>
        </div>
      </div>

      {jobs.length > 0 && (
        <div className="card mt-4 overflow-hidden">
          <div className="border-b border-accent/25 px-4 py-2.5 font-display text-base font-medium text-ink-muted">
            Fingerprint runs
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Detector</th>
                  <th>Max servers</th>
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
                      <td className="font-mono text-xs">{job.tool}</td>
                      <td className="font-mono text-xs">{String(opts.max_targets ?? '-')}</td>
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
            Deduplicated technologies
          </span>
          <span className="font-mono text-xs text-ink-muted">
            {merged.length} technologies &middot; {rows.length} detections
          </span>
        </div>
        {merged.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            No technologies detected yet. Run fingerprinting against a target with live web servers
            (run the wildcard workflow first).
          </p>
        ) : (
          <div className="max-h-[32rem] overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Technology</th>
                  <th>Version</th>
                  <th>Detected by</th>
                  <th className="text-right">Servers</th>
                  <th>CVEs</th>
                </tr>
              </thead>
              <tbody>
                {merged.map((tech, index) => {
                  const prev = merged[index - 1]
                  const isNewCategory = !prev || prev.category !== tech.category
                  const categoryCount = merged.filter(
                    (item) => item.category === tech.category,
                  ).length
                  const serverList = tech.serverIds.map(
                    (id) => urlByServer.get(id) ?? id,
                  )
                  return (
                    <Fragment key={tech.key}>
                      {isNewCategory && (
                        <tr className="bg-surface-panel/60">
                          <td colSpan={5} className="px-4 py-1.5">
                            <span className="inline-flex items-center gap-2">
                              <Badge tone={categoryTone(tech.category)}>
                                {categoryLabel[tech.category] ?? tech.category}
                              </Badge>
                              <span className="font-mono text-[11px] text-ink-muted">
                                {categoryCount}
                              </span>
                            </span>
                          </td>
                        </tr>
                      )}
                      <tr className="hover:bg-surface-border/30">
                        <td className="font-mono text-xs text-ink">{tech.name}</td>
                        <td className="font-mono text-xs text-ink-muted">{tech.version || '-'}</td>
                        <td>
                          <div className="flex flex-wrap gap-1">
                            {tech.tools.map((tool) => (
                              <Badge key={tool} tone="muted">
                                {tool}
                              </Badge>
                            ))}
                          </div>
                        </td>
                        <td
                          className="text-right font-mono text-xs text-ink-muted"
                          title={serverList.join('\n')}
                        >
                          {serverList.length}
                        </td>
                        <td className="font-mono text-xs text-ink-muted">
                          {tech.cves.length > 0 ? tech.cves.join(', ') : '-'}
                        </td>
                      </tr>
                    </Fragment>
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
