import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { scopeTargetTypeLabels, type ScopeTargetType } from '../lib/types'
import { Badge } from '../components/Badge'
import { DomainAuditPanel } from '../components/DomainAuditPanel'
import { NotesPanel } from '../components/NotesPanel'
import { NucleiPanel } from '../components/NucleiPanel'
import { NetworkPanel } from '../components/NetworkPanel'
import { JSReconPanel } from '../components/JSReconPanel'
import { OpenRedirectPanel } from '../components/OpenRedirectPanel'
import { ScanPanel } from '../components/ScanPanel'
import { SQLiPanel } from '../components/SQLiPanel'
import { TakeoverPanel } from '../components/TakeoverPanel'
import { WorkflowPanel } from '../components/WorkflowPanel'
import { CollapsiblePanel } from '../components/ui'

interface Step {
  title: string
  tools: string
  blurb: string
}

const workflowSteps: Record<ScopeTargetType, Step[]> = {
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
    { title: 'Brute-force', tools: 'CeWL, ShuffleDNS', blurb: 'Generate a target-specific wordlist and mass-resolve.' },
    { title: 'Consolidate + live probe (2)', tools: 'httpx', blurb: 'Second dedupe + live pass.' },
    {
      title: 'JS / link discovery',
      tools: 'gospider, subdomainizer, linkfinder',
      blurb: 'Crawl live sites and extract endpoints and subdomains from JavaScript.',
    },
    { title: 'Consolidate + live probe (3)', tools: 'httpx', blurb: 'Final pass before prioritization.' },
    {
      title: 'ROI / decision point',
      tools: 'gowitness, httpx',
      blurb: 'Screenshot + metadata to compute an ROI score per target.',
    },
  ],
  url: [
    { title: 'Directory / content discovery', tools: 'ffuf, feroxbuster, katana, gau', blurb: 'Find hidden paths with a 404-diff baseline.' },
    { title: 'Parameter discovery', tools: 'arjun, x8', blurb: 'Uncover hidden GET/POST parameters.' },
    { title: 'Client-side injection (XSS)', tools: 'dalfox, domdig', blurb: 'Find and verify reflected/DOM sinks with context.' },
    { title: 'Server-side injection', tools: 'sqlmap, commix, sstimap, lfimap', blurb: 'SQLi, command injection, SSTI, LFI.' },
    { title: 'SSRF / open redirect', tools: 'ssrfmap, recollapse', blurb: 'Probe server-side request forgery and redirects.' },
    { title: 'Access control / smuggling / cache', tools: 'nomore403, smugglex, cacheboom', blurb: 'Bypass and cache-poisoning candidates.' },
    { title: 'GraphQL', tools: 'graphw00f, graphql-cop, clairvoyance', blurb: 'Fingerprint, audit, and recover schema.' },
    { title: 'Secrets & exposure', tools: 'trufflehog, mantra, snallygaster', blurb: 'Exposed secrets and files.' },
    { title: 'JWT / auth', tools: 'jwt_tool', blurb: 'Token tampering and session-flow testing.' },
  ],
}

export function ScopeTargetDetailPage() {
  const { id = '' } = useParams()
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: ['scope-target', id],
    queryFn: () => api.getScopeTarget(id),
    enabled: id !== '',
  })

  const activate = useMutation({
    mutationFn: () => api.activateScopeTarget(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['scope-target', id] })
      void queryClient.invalidateQueries({ queryKey: ['scope-targets'] })
    },
  })

  if (query.isLoading) {
    return <p className="text-sm text-ink-muted">Loading target...</p>
  }

  if (query.isError || !query.data) {
    return (
      <div className="space-y-3">
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
  const steps = workflowSteps[target.type]

  const sections = [
    { id: 'notes', label: 'Notes' },
    ...(target.type === 'wildcard' ? [{ id: 'workflow', label: 'Wildcard workflow' }] : []),
    ...(target.type !== 'company'
      ? [{ id: 'domain-audit', label: 'Domain & DNS Security' }]
      : []),
    ...(target.type !== 'url' ? [{ id: 'recon', label: 'Recon (individual tools)' }] : []),
    ...(target.type === 'wildcard'
      ? [
          { id: 'takeover', label: 'Subdomain Takeover' },
          { id: 'nuclei', label: 'Nuclei Scanning' },
          { id: 'network', label: 'Network Recon' },
          { id: 'sqli', label: 'SQL Injection (sqlmap)' },
          { id: 'js-recon', label: 'JavaScript Recon' },
          { id: 'open-redirect', label: 'Open Redirect' },
        ]
      : []),
    ...(target.type !== 'wildcard' ? [{ id: 'planned', label: 'Workflow plan' }] : []),
  ]

  const jumpToSection = (id: string) => {
    if (!id) return
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="mx-auto max-w-4xl">
      <Link to="/targets" className="text-xs text-ink-muted hover:text-accent">
        &larr; Scope targets
      </Link>

      <div className="mt-2 flex flex-wrap items-center gap-3">
        <h1 className="font-mono text-xl text-ink">{target.value}</h1>
        <Badge tone="muted">{scopeTargetTypeLabels[target.type]}</Badge>
        {target.auth_confirmed ? <Badge tone="low">Auth confirmed</Badge> : <Badge tone="medium">Auth pending</Badge>}
        {target.active ? <Badge tone="accent">Active</Badge> : <Badge tone="muted">Inactive</Badge>}
      </div>

      {target.description && <p className="mt-2 text-sm text-ink-muted">{target.description}</p>}

      <div className="mt-4 flex items-center gap-3">
        <button
          className="btn btn-primary"
          disabled={target.active || !target.auth_confirmed || activate.isPending}
          title={!target.auth_confirmed ? 'Confirm authorization before activating' : undefined}
          onClick={() => activate.mutate()}
        >
          {target.active ? 'Active' : activate.isPending ? 'Activating...' : 'Activate for scanning'}
        </button>
        {activate.isError && (
          <span className="font-mono text-xs text-sev-critical">
            {activate.error instanceof ApiError ? activate.error.message : 'Activation failed'}
          </span>
        )}
      </div>

      <div className="mt-6 flex flex-wrap items-center gap-2 rounded-lg border border-base-border bg-base-raised px-3 py-2">
        <label htmlFor="section-nav" className="text-xs text-ink-muted">
          Jump to
        </label>
        <select
          id="section-nav"
          className="input w-full sm:max-w-xs"
          value=""
          onChange={(event) => {
            jumpToSection(event.target.value)
            event.target.value = ''
          }}
        >
          <option value="">Select a section…</option>
          {sections.map((section) => (
            <option key={section.id} value={section.id}>
              {section.label}
            </option>
          ))}
        </select>
      </div>

      <NotesPanel scopeTargetId={target.id} initialNotes={target.notes} />

      {target.type === 'wildcard' && (
        <WorkflowPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      )}
      {target.type !== 'company' && (
        <DomainAuditPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      )}

      {target.type !== 'url' && (
        <ScanPanel
          scopeTargetId={target.id}
          authConfirmed={target.auth_confirmed}
          showSubdomains={target.type !== 'wildcard'}
        />
      )}

      {target.type === 'wildcard' && (
        <TakeoverPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      )}

      {target.type === 'wildcard' && (
        <NucleiPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      )}

      {target.type === 'wildcard' && (
        <NetworkPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      )}

      {target.type === 'wildcard' && (
        <SQLiPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      )}

      {target.type === 'wildcard' && (
        <JSReconPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      )}

      {target.type === 'wildcard' && (
        <OpenRedirectPanel scopeTargetId={target.id} authConfirmed={target.auth_confirmed} />
      )}

      {target.type !== 'wildcard' && (
      <CollapsiblePanel
        id="planned"
        title={`${scopeTargetTypeLabels[target.type]} workflow (planned)`}
        description="Steps run in order with a consolidation pass between discovery rounds."
        defaultOpen={false}
      >
        <p className="text-sm text-ink-muted">
          Orchestration is wired up in the next milestone; each step below is the planned pipeline.
        </p>

        <ol className="mt-4 space-y-2">
          {steps.map((step, index) => (
            <li key={step.title} className="card p-3">
              <div className="flex items-center gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-base-border font-mono text-xs text-ink-muted">
                  {index + 1}
                </span>
                <span className="text-sm text-ink">{step.title}</span>
                <span className="ml-auto hidden font-mono text-[11px] text-ink-muted sm:inline">
                  {step.tools}
                </span>
                <Badge tone="muted">Planned</Badge>
              </div>
              <details className="mt-2 pl-9">
                <summary className="cursor-pointer text-xs text-accent">Help me learn</summary>
                <p className="mt-1 text-sm text-ink-muted">{step.blurb}</p>
              </details>
            </li>
          ))}
        </ol>
      </CollapsiblePanel>
      )}
    </div>
  )
}
