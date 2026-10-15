import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import {
  scopeTargetTypeLabels,
  type ScopeTargetType,
  type StepStatus,
  type WorkflowStep,
} from '../lib/types'
import { Badge } from '../components/Badge'
import { DomainAuditPanel } from '../components/DomainAuditPanel'
import { JSReconPanel } from '../components/JSReconPanel'
import { NetworkPanel } from '../components/NetworkPanel'
import { NotesPanel } from '../components/NotesPanel'
import { NucleiPanel } from '../components/NucleiPanel'
import { OpenRedirectPanel } from '../components/OpenRedirectPanel'
import { ScanPanel } from '../components/ScanPanel'
import { SQLiPanel } from '../components/SQLiPanel'
import { TakeoverPanel } from '../components/TakeoverPanel'
import { WorkflowPanel } from '../components/WorkflowPanel'
import { Workspace } from '../components/workspace/Workspace'
import { ApiStatus } from '../components/workspace/ApiStatus'
import { ArrowLeftIcon } from '../components/workspace/icons'
import type { PhaseDef, PhaseStatus } from '../components/workspace/types'

interface PlannedStep {
  title: string
  tools: string
  blurb: string
}

const workflowSteps: Record<ScopeTargetType, PlannedStep[]> = {
  company: [
    {
      title: 'ASN / network range discovery',
      tools: 'Amass Intel, Metabigor',
      blurb:
        'Find the ASNs and CIDR ranges the organization announces, so on-prem infrastructure can be scanned.',
    },
    {
      title: 'Live web server discovery',
      tools: 'naabu/masscan, httpx',
      blurb: 'Port-scan discovered ranges, then HTTP-probe to find live services.',
    },
    {
      title: 'Root domain discovery (no API key)',
      tools: 'Google dorking, crt.sh, reverse WHOIS',
      blurb: 'Surface root domains from certificate transparency and public sources.',
    },
    {
      title: 'Root domain discovery (API key)',
      tools: 'SecurityTrails, Shodan, Censys, GitHub',
      blurb: 'Use API-backed sources and code search for deeper domain coverage.',
    },
    {
      title: 'Consolidate root domains',
      tools: 'internal',
      blurb: 'Dedupe and auto-create a wildcard target per unique root domain.',
    },
    {
      title: 'Cloud asset enumeration (DNS)',
      tools: 'Amass Enum, dnsx',
      blurb: 'Pick up cloud-hosted subdomains across every discovered domain.',
    },
  ],
  wildcard: [
    { title: 'Amass Enum', tools: 'amass', blurb: 'Active + passive subdomain enumeration.' },
    {
      title: 'Subdomain scraping',
      tools: 'subfinder, assetfinder, sublist3r, gau, ctl, enumrust',
      blurb: 'Run many sources in parallel, then merge.',
    },
    {
      title: 'Consolidate + live probe (1)',
      tools: 'httpx',
      blurb: 'Dedupe resolved subdomains and flag which serve HTTP(S).',
    },
    {
      title: 'Brute-force',
      tools: 'CeWL, ShuffleDNS',
      blurb: 'Generate a target-specific wordlist and mass-resolve.',
    },
    { title: 'Consolidate + live probe (2)', tools: 'httpx', blurb: 'Second dedupe + live pass.' },
    {
      title: 'JS / link discovery',
      tools: 'gospider, subdomainizer, linkfinder',
      blurb: 'Crawl live sites and extract endpoints and subdomains from JavaScript.',
    },
    {
      title: 'Consolidate + live probe (3)',
      tools: 'httpx',
      blurb: 'Final pass before prioritization.',
    },
    {
      title: 'ROI / decision point',
      tools: 'gowitness, httpx',
      blurb: 'Screenshot + metadata to compute an ROI score per target.',
    },
  ],
  url: [
    {
      title: 'Directory / content discovery',
      tools: 'ffuf, feroxbuster, katana, gau',
      blurb: 'Find hidden paths with a 404-diff baseline.',
    },
    {
      title: 'Parameter discovery',
      tools: 'arjun, x8',
      blurb: 'Uncover hidden GET/POST parameters.',
    },
    {
      title: 'Client-side injection (XSS)',
      tools: 'dalfox, domdig',
      blurb: 'Find and verify reflected/DOM sinks with context.',
    },
    {
      title: 'Server-side injection',
      tools: 'sqlmap, commix, sstimap, lfimap',
      blurb: 'SQLi, command injection, SSTI, LFI.',
    },
    {
      title: 'SSRF / open redirect',
      tools: 'ssrfmap, recollapse',
      blurb: 'Probe server-side request forgery and redirects.',
    },
    {
      title: 'Access control / smuggling / cache',
      tools: 'nomore403, smugglex, cacheboom',
      blurb: 'Bypass and cache-poisoning candidates.',
    },
    {
      title: 'GraphQL',
      tools: 'graphw00f, graphql-cop, clairvoyance',
      blurb: 'Fingerprint, audit, and recover schema.',
    },
    {
      title: 'Secrets & exposure',
      tools: 'trufflehog, mantra, snallygaster',
      blurb: 'Exposed secrets and files.',
    },
    { title: 'JWT / auth', tools: 'jwt_tool', blurb: 'Token tampering and session-flow testing.' },
  ],
}

const WILDCARD_PHASES: PhaseDef[] = [
  {
    id: 'enum',
    label: 'Enumerate',
    title: 'Enumeration',
    help: 'Map the target domain footprint from passive and active DNS sources. Amass combines public datasets with optional active resolution to surface as many subdomains as possible.',
    tools: ['amass'],
  },
  {
    id: 'scrape',
    label: 'Subdomain Scraping',
    title: 'Subdomain Scraping',
    help: 'Run several enumeration sources in parallel — each queries a different dataset, so overlapping coverage is expected. Results are merged and deduplicated in the next phase.',
    tools: ['subfinder', 'assetfinder', 'sublist3r', 'findomain', 'ct'],
  },
  {
    id: 'consolidate_probe',
    label: 'Consolidate & Probe',
    title: 'Consolidate & Live-Probe',
    help: 'Deduplicate every discovered subdomain, then probe them with httpx to determine which actually serve HTTP(S). Live servers become your working set for manual testing.',
    tools: ['httpx'],
  },
  {
    id: 'urls',
    label: 'URL Discovery',
    title: 'URL / Endpoint Discovery',
    help: 'Pull historical and crawled URLs from archives and live crawling. Endpoints with parameters or interesting extensions are flagged as higher-value test candidates.',
    tools: ['gau', 'waybackurls', 'katana'],
  },
  {
    id: 'domain-audit',
    label: 'Domain Audit',
    title: 'Domain & DNS Security',
    help: 'Audit DNS & DNSSEC, email security (SPF/DKIM/DMARC), HTTP security headers, and TLS configuration. Each section returns a scored checklist of pass/warn/fail findings.',
    tools: ['dnsx', 'domainaudit'],
  },
  {
    id: 'recon',
    label: 'Recon Tools',
    title: 'Recon (Individual Tools)',
    help: 'Run any individual enumeration tool on demand — each in its own isolated Docker container. Useful for re-running a single source or filling gaps left by a workflow run.',
    tools: ['subfinder', 'amass', 'assetfinder', 'gau', 'katana'],
  },
  {
    id: 'takeover',
    label: 'Takeover',
    title: 'Subdomain Takeover',
    help: 'Resolve CNAME chains and reverse-DNS, then match against known hijackable service fingerprints. A subdomain is flagged when its CNAME points at an unclaimed service or no longer resolves.',
    tools: ['takeover'],
  },
  {
    id: 'nuclei',
    label: 'Nuclei',
    title: 'Nuclei Scanning',
    help: 'Run template-based vulnerability scanning across live hosts. Findings are grouped by category and severity so you can triage the highest-impact issues first.',
    tools: ['nuclei'],
  },
  {
    id: 'network',
    label: 'Network Recon',
    title: 'Network Recon',
    help: 'Resolve hosts (dnsx), scan ports (naabu), then fingerprint services (nmap). Turns a list of hosts into a picture of exposed, network-reachable services.',
    tools: ['dnsx', 'naabu', 'nmap'],
  },
  {
    id: 'sqli',
    label: 'SQL Injection',
    title: 'SQL Injection (sqlmap)',
    help: 'Test URL parameters for SQL injection with sqlmap. Tune level/risk and techniques; detections are recorded with the technique, DBMS and payload used.',
    tools: ['sqlmap'],
  },
  {
    id: 'js-recon',
    label: 'JS Recon',
    title: 'JavaScript Recon',
    help: 'Fetch JavaScript from live hosts and extract endpoints, API routes, secrets and keys. Surfaces client-side data that expands your attack surface.',
    tools: ['jsrecon'],
  },
  {
    id: 'open-redirect',
    label: 'Open Redirect',
    title: 'Open Redirect',
    help: 'Probe redirect parameters and headers for open-redirect, DOM-redirect and header-injection behaviour using a safe canary host.',
    tools: ['openredirect'],
  },
  {
    id: 'notes',
    label: 'Notes',
    title: 'Notes',
    help: 'Keep context, hypotheses and follow-ups about this target in one place. Notes are stored with the scope target.',
    tools: [],
  },
]

function buildPhases(type: ScopeTargetType): PhaseDef[] {
  if (type === 'wildcard') return WILDCARD_PHASES
  if (type === 'url') {
    return [
      {
        id: 'domain-audit',
        label: 'Domain Audit',
        title: 'Domain & DNS Security',
        help: 'Audit DNS & DNSSEC, email security (SPF/DKIM/DMARC), HTTP security headers, and TLS configuration for this URL.',
        tools: ['domainaudit'],
      },
      {
        id: 'planned',
        label: 'Workflow Plan',
        title: 'Manual testing workflow plan',
        help: 'The planned manual-testing pipeline for URL targets. Orchestration is wired up in a later milestone; each step below is the planned pipeline.',
        tools: [],
      },
      {
        id: 'notes',
        label: 'Notes',
        title: 'Notes',
        help: 'Keep context, hypotheses and follow-ups about this target in one place.',
        tools: [],
      },
    ]
  }
  return [
    {
      id: 'planned',
      label: 'Workflow Plan',
      title: 'Company workflow plan',
      help: 'The planned company discovery pipeline: ASN/range discovery, live-server discovery, root-domain discovery, and consolidation into wildcard targets.',
      tools: [],
    },
    {
      id: 'notes',
      label: 'Notes',
      title: 'Notes',
      help: 'Keep context, hypotheses and follow-ups about this target in one place.',
      tools: [],
    },
  ]
}

function mapStepStatus(status: StepStatus | undefined): PhaseStatus {
  switch (status) {
    case 'done':
      return 'done'
    case 'failed':
      return 'failed'
    case 'running':
      return 'running'
    case 'queued':
      return 'queued'
    default:
      return 'todo'
  }
}

function aggregateStatus(steps: WorkflowStep[] | undefined): PhaseStatus {
  if (!steps || steps.length === 0) return 'todo'
  const statuses = steps.map((step) => step.status)
  if (statuses.some((s) => s === 'running')) return 'running'
  if (statuses.some((s) => s === 'failed')) return 'failed'
  if (statuses.some((s) => s === 'queued')) return 'queued'
  if (statuses.every((s) => s === 'done')) return 'done'
  return 'todo'
}

const RECON_TOOLS = [
  'subfinder',
  'amass',
  'assetfinder',
  'sublist3r',
  'findomain',
  'ct',
  'gau',
  'waybackurls',
  'katana',
]

export function ScopeTargetDetailPage() {
  const { id = '' } = useParams()
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState<string | null>(null)

  const query = useQuery({
    queryKey: ['scope-target', id],
    queryFn: () => api.getScopeTarget(id),
    enabled: id !== '',
  })

  const workflows = useQuery({
    queryKey: ['workflows', id],
    queryFn: () => api.listWorkflows(id),
    enabled: id !== '',
    refetchInterval: (q) => {
      const items = q.state.data?.items ?? []
      return items.some((wf) => wf.status === 'queued' || wf.status === 'running') ? 2500 : false
    },
  })

  const scans = useQuery({
    queryKey: ['scans', id],
    queryFn: () => api.listScans(id),
    enabled: id !== '',
    refetchInterval: (q) => {
      const items = (q.state.data?.items ?? []).filter((job) => !job.workflow_id)
      return items.some((job) => job.status === 'queued' || job.status === 'running') ? 2500 : false
    },
  })

  const activate = useMutation({
    mutationFn: () => api.activateScopeTarget(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['scope-target', id] })
      void queryClient.invalidateQueries({ queryKey: ['scope-targets'] })
    },
  })

  if (query.isLoading) {
    return <p className="p-8 text-sm text-ink-muted">Loading target...</p>
  }

  if (query.isError || !query.data) {
    return (
      <div className="space-y-3 p-8">
        <p className="font-mono text-sm text-sev-critical">
          {query.error instanceof ApiError ? query.error.message : 'Failed to load target'}
        </p>
        <Link to="/targets" className="text-sm text-accent hover:underline">
          Back to scope targets
        </Link>
      </div>
    )
  }

  const target = query.data
  const phases = buildPhases(target.type)

  const wfItems = workflows.data?.items ?? []
  const wildcardWf = wfItems.find((wf) => wf.workflow_type === 'wildcard')
  const domainWf = wfItems.find((wf) => wf.workflow_type === 'domain')
  const scanItems = (scans.data?.items ?? []).filter((job) => !job.workflow_id)

  const fromScans = (tools: string[]): PhaseStatus => {
    const rel = scanItems.filter((job) => tools.includes(job.tool))
    if (rel.length === 0) return 'todo'
    if (rel.some((job) => job.status === 'running' || job.status === 'queued')) return 'running'
    if (rel.some((job) => job.status === 'failed')) return 'failed'
    if (rel.every((job) => job.status === 'done')) return 'done'
    return 'todo'
  }

  const status: Record<string, PhaseStatus> = {}
  for (const phase of phases) {
    switch (phase.id) {
      case 'enum':
      case 'scrape':
      case 'consolidate_probe':
      case 'urls':
        status[phase.id] = mapStepStatus(
          wildcardWf?.steps?.find((step) => step.step_key === phase.id)?.status,
        )
        break
      case 'domain-audit':
        status[phase.id] = aggregateStatus(domainWf?.steps)
        break
      case 'recon':
        status[phase.id] = fromScans(RECON_TOOLS)
        break
      case 'takeover':
        status[phase.id] = fromScans(['takeover'])
        break
      case 'nuclei':
        status[phase.id] = fromScans(['nuclei'])
        break
      case 'network':
        status[phase.id] = fromScans(['netscan'])
        break
      case 'sqli':
        status[phase.id] = fromScans(['sqli'])
        break
      case 'js-recon':
        status[phase.id] = fromScans(['jsrecon'])
        break
      case 'open-redirect':
        status[phase.id] = fromScans(['openredirect'])
        break
      default:
        status[phase.id] = 'todo'
    }
  }

  const firstPending =
    phases.find((phase) => (status[phase.id] ?? 'todo') !== 'done') ?? phases[0]
  const activeId =
    selected && phases.some((phase) => phase.id === selected) ? selected : firstPending.id

  const renderPhase = (phaseId: string) => {
    switch (phaseId) {
      case 'enum':
      case 'scrape':
      case 'consolidate_probe':
      case 'urls':
        return (
          <WorkflowPanel
            scopeTargetId={target.id}
            authConfirmed={target.auth_confirmed}
            activeStepKey={phaseId}
            showRun={phaseId === 'enum'}
          />
        )
      case 'domain-audit':
        return <DomainAuditPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      case 'recon':
        return (
          <ScanPanel
            scopeTargetId={target.id}
            authConfirmed={target.auth_confirmed}
            showSubdomains={target.type !== 'wildcard'}
          />
        )
      case 'takeover':
        return <TakeoverPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      case 'nuclei':
        return <NucleiPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      case 'network':
        return <NetworkPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      case 'sqli':
        return <SQLiPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      case 'js-recon':
        return <JSReconPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      case 'open-redirect':
        return (
          <OpenRedirectPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
        )
      case 'notes':
        return <NotesPanel scopeTargetId={target.id} initialNotes={target.notes} />
      case 'planned':
        return <PlannedWorkflow type={target.type} />
      default:
        return null
    }
  }

  const header = (
    <div className="border-b border-surface-border px-4 py-4 md:px-6">
      <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center gap-x-3 gap-y-2">
        <Link
          to="/targets"
          className="inline-flex items-center gap-1.5 text-xs text-ink-muted transition-colors hover:text-accent"
        >
          <ArrowLeftIcon className="h-3.5 w-3.5" />
          Scope targets
        </Link>
        <span className="text-ink-muted/40">/</span>
        <h1 className="min-w-0 break-all font-mono text-base text-ink sm:text-lg">
          {target.value}
        </h1>
        <Badge tone="muted">{scopeTargetTypeLabels[target.type]}</Badge>
        {target.auth_confirmed ? (
          <Badge tone="low">Auth confirmed</Badge>
        ) : (
          <Badge tone="medium">Auth pending</Badge>
        )}
        {target.active ? <Badge tone="accent">Active</Badge> : <Badge tone="muted">Inactive</Badge>}

        <div className="flex w-full flex-wrap items-center gap-3 sm:ml-auto sm:w-auto">
          <ApiStatus />
          {activate.isError && (
            <span className="font-mono text-xs text-sev-critical">
              {activate.error instanceof ApiError ? activate.error.message : 'Activation failed'}
            </span>
          )}
          <button
            className="btn btn-primary w-full sm:w-auto"
            disabled={target.active || !target.auth_confirmed || activate.isPending}
            title={!target.auth_confirmed ? 'Confirm authorization before activating' : undefined}
            onClick={() => activate.mutate()}
          >
            {target.active ? 'Active' : activate.isPending ? 'Activating...' : 'Activate for scanning'}
          </button>
        </div>
      </div>
      {target.description && (
        <p className="mx-auto mt-2 w-full max-w-6xl text-sm text-ink-muted">{target.description}</p>
      )}
    </div>
  )

  return (
    <Workspace
      phases={phases}
      activeId={activeId}
      onSelect={setSelected}
      status={status}
      header={header}
    >
      {renderPhase(activeId)}
    </Workspace>
  )
}

function PlannedWorkflow({ type }: { type: ScopeTargetType }) {
  const steps = workflowSteps[type]
  return (
    <section>
      <p className="text-sm text-ink-muted">
        {scopeTargetTypeLabels[type]} workflow (planned). Steps run in order with a consolidation
        pass between discovery rounds.
      </p>
      <p className="mt-2 text-sm text-ink-muted">
        Orchestration is wired up in the next milestone; each step below is the planned pipeline.
      </p>

      <ol className="mt-4 space-y-2">
        {steps.map((step, index) => (
          <li key={step.title} className="card p-3">
            <div className="flex items-center gap-3">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-surface-border font-mono text-xs text-ink-muted">
                {index + 1}
              </span>
              <span className="text-sm text-ink">{step.title}</span>
              <span className="ml-auto hidden font-mono text-[11px] text-ink-muted sm:inline">
                {step.tools}
              </span>
              <Badge tone="muted">Planned</Badge>
            </div>
            <p className="mt-2 pl-9 text-sm text-ink-muted">{step.blurb}</p>
          </li>
        ))}
      </ol>
    </section>
  )
}
