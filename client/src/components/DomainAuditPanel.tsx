import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { formatDuration } from '../lib/format'
import type { AuditStatus, AuditSummary, Workflow, WorkflowStep } from '../lib/types'
import { Badge } from './Badge'
import { RawOutputViewer } from './RawOutputViewer'
import { SectionHeader, StatusPill, CollapsiblePanel } from './ui'
import type { Tone } from './StatusDot'

const sectionLabels: Record<string, string> = {
  dns_config: 'DNS & DNSSEC',
  email_config: 'Email Security (SPF/DKIM/DMARC)',
  header_config: 'HTTP Security Headers',
  tls_config: 'TLS / SSL',
}

const auditTone: Record<AuditStatus, Tone> = {
  pass: 'low',
  warn: 'medium',
  fail: 'critical',
  info: 'info',
}

const auditLabel: Record<AuditStatus, string> = {
  pass: 'Pass',
  warn: 'Warn',
  fail: 'Fail',
  info: 'Info',
}

function scoreClass(score: number): string {
  if (score >= 90) return 'text-accent'
  if (score >= 70) return 'text-sev-low'
  if (score >= 50) return 'text-sev-medium'
  return 'text-sev-critical'
}

export function DomainAuditPanel({
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
      const items = (query.state.data?.items ?? []).filter((wf) => wf.workflow_type === 'domain')
      return items.some((wf) => wf.status === 'queued' || wf.status === 'running') ? 2500 : false
    },
  })

  const run = useMutation({
    mutationFn: () => api.runDomainWorkflow(scopeTargetId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['workflows', scopeTargetId] })
    },
  })

  const items = (workflows.data?.items ?? []).filter((wf) => wf.workflow_type === 'domain')
  const active: Workflow | undefined = items[0]
  const running = active?.status === 'queued' || active?.status === 'running'

  return (
    <CollapsiblePanel
      id="domain-audit"
      title="Domain & DNS Security"
      description="DNS/DNSSEC → email (SPF/DKIM/DMARC) → HTTP security headers → TLS."
      status={
        active ? (
          <StatusPill status={active.status} />
        ) : (
          <span className="text-xs text-ink-muted">not run</span>
        )
      }
      actions={
        <button
          className="btn btn-primary"
          disabled={!authConfirmed || run.isPending || running}
          title={!authConfirmed ? 'Confirm authorization before running an audit' : undefined}
          onClick={() => run.mutate()}
        >
          {run.isPending ? 'Starting...' : 'Run Domain Audit'}
        </button>
      }
    >
      {run.isError && (
        <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
          {run.error instanceof ApiError ? run.error.message : 'Failed to start domain audit'}
        </p>
      )}

      {active ? (
        (active.steps ?? []).map((step) => {
          const duration = step.finished_at
            ? formatDuration(step.started_at, step.finished_at)
            : undefined
          return (
            <AuditStepSection
              key={step.id}
              step={step}
              duration={duration}
              label={sectionLabels[step.step_key] ?? step.title}
            />
          )
        })
      ) : (
        <p className="card mt-4 p-5 text-sm text-ink-muted">
          No audit run yet. Run the domain audit to review DNS, email, header and TLS configuration.
        </p>
      )}

      {active?.error && <p className="mt-3 font-mono text-xs text-sev-critical">{active.error}</p>}
    </CollapsiblePanel>
  )
}

function AuditStepSection({
  step,
  duration,
  label,
}: {
  step: WorkflowStep
  duration?: string
  label: string
}) {
  const [openJob, setOpenJob] = useState<string | null>(null)
  const jobs = step.jobs ?? []
  const summary = auditSummary(step.summary)
  const checks = summary?.checks ?? []
  const score = typeof summary?.score === 'number' ? summary.score : null

  return (
    <section className="mt-8">
      <SectionHeader
        label={label}
        status={step.status}
        description={step.description ?? undefined}
        duration={duration}
      />

      <div className="card mt-4 overflow-hidden">
        {score != null && (
          <div className="flex items-baseline gap-3 border-b border-accent/25 px-4 py-3">
            <span className={`stat-number text-2xl ${scoreClass(score)}`}>{score}</span>
            <span className="stat-label">/ 100 &middot; section score</span>
          </div>
        )}

        {checks.length > 0 ? (
          <table className="data-table">
            <tbody>
              {checks.map((c) => (
                <tr key={c.id} className="align-top hover:bg-base-border/30">
                  <td className="w-24">
                    <Badge tone={auditTone[c.status]}>{auditLabel[c.status]}</Badge>
                  </td>
                  <td className="w-56 text-ink">{c.title}</td>
                  <td className="break-words font-mono text-xs text-ink-muted">{c.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="p-4 text-sm text-ink-muted">
            {step.status === 'done' ? 'No checks returned.' : 'Awaiting results...'}
          </p>
        )}

        {jobs.length > 0 && (
          <div className="flex flex-wrap gap-2 border-t border-base-border px-4 py-3">
            {jobs.map((job) => (
              <button
                key={job.id}
                type="button"
                className={`btn btn-sm ${openJob === job.id ? 'btn-primary' : ''}`}
                onClick={() => setOpenJob((prev) => (prev === job.id ? null : job.id))}
              >
                {openJob === job.id ? 'Hide' : 'Results'} &middot; {job.tool}
                {job.exit_code != null ? ` (exit ${job.exit_code})` : ''}
              </button>
            ))}
          </div>
        )}
      </div>

      {openJob && <RawOutputViewer jobId={openJob} />}
    </section>
  )
}

function auditSummary(summary: Record<string, unknown> | undefined | null): AuditSummary | null {
  if (!summary || typeof summary !== 'object') return null
  if (!Array.isArray((summary as AuditSummary).checks)) return null
  return summary as AuditSummary
}
