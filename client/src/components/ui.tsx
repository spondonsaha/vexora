import { useState, type ReactNode } from 'react'
import type { StepStatus } from '../lib/types'
import { StatusDot, type Tone } from './StatusDot'

export const statusTone: Record<StepStatus, Tone> = {
  queued: 'info',
  running: 'low',
  done: 'accent',
  failed: 'critical',
  cancelled: 'info',
}

export const statusLabel: Record<StepStatus, string> = {
  queued: 'Queued',
  running: 'Running',
  done: 'Success',
  failed: 'Failed',
  cancelled: 'Cancelled',
}

export function StatusPill({ status }: { status: StepStatus }) {
  return (
    <span className="inline-flex items-center gap-2 text-xs text-ink-muted">
      <StatusDot tone={statusTone[status]} pulse={status === 'running'} />
      {statusLabel[status]}
    </span>
  )
}

export function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={`h-4 w-4 shrink-0 transition-transform ${open ? 'rotate-180' : ''}`}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  )
}

export function CollapsiblePanel({
  id,
  title,
  description,
  status,
  actions,
  defaultOpen = true,
  children,
}: {
  id?: string
  title: string
  description?: string
  status?: ReactNode
  actions?: ReactNode
  defaultOpen?: boolean
  children: ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <section id={id} className="mt-8 scroll-mt-28">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border border-base-border bg-base-raised px-4 py-3 transition-colors hover:border-accent/40">
        <button
          type="button"
          className="flex items-center gap-2 text-accent"
          aria-expanded={open}
          onClick={() => setOpen((value) => !value)}
        >
          <Chevron open={open} />
          <span className="section-title">{title}</span>
        </button>
        {description && (
          <span className="hidden text-xs text-ink-muted lg:inline">{description}</span>
        )}
        <div className="ml-auto flex flex-wrap items-center gap-3">
          {status}
          {actions}
        </div>
      </div>
      <div className={open ? 'mt-4 block' : 'hidden'}>{children}</div>
    </section>
  )
}

export function SectionHeader({
  label,
  status,
  description,
  duration,
}: {
  label: string
  status: StepStatus
  description?: string
  duration?: string
}) {
  const [open, setOpen] = useState(false)
  return (
    <div>
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-display text-base font-medium text-ink-muted">{label}</span>
        <StatusPill status={status} />
        {duration && <span className="font-mono text-xs text-ink-muted">{duration}</span>}
      </div>
      <button
        type="button"
        className="helpbar mt-2"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <span>Help Me Learn!</span>
        <Chevron open={open} />
      </button>
      {open && description && (
        <p className="mt-2 rounded-lg border border-base-border bg-base-panel p-4 text-sm leading-relaxed text-ink-muted">
          {description}
        </p>
      )}
    </div>
  )
}
