import type { Tone } from '../StatusDot'

export type PhaseStatus = 'todo' | 'queued' | 'running' | 'done' | 'failed'

export interface PhaseDef {
  id: string
  label: string
  title: string
  help: string
  tools?: string[]
}

export const phaseStatusLabel: Record<PhaseStatus, string> = {
  todo: 'Not started',
  queued: 'Queued',
  running: 'Running',
  done: 'Complete',
  failed: 'Failed',
}

export const phaseStatusTone: Record<PhaseStatus, Tone> = {
  todo: 'info',
  queued: 'info',
  running: 'low',
  done: 'accent',
  failed: 'critical',
}

export function chipClass(status: PhaseStatus, active: boolean): string {
  if (active) return 'border-accent bg-accent text-white'
  switch (status) {
    case 'done':
      return 'border-accent/60 bg-accent/20 text-accent'
    case 'running':
      return 'border-sev-low/70 bg-sev-low/15 text-sev-low'
    case 'failed':
      return 'border-sev-critical/70 bg-sev-critical/15 text-sev-critical'
    default:
      return 'border-surface-border bg-surface-panel text-ink-muted'
  }
}

export function dotClass(status: PhaseStatus, active: boolean): string {
  if (active) return 'h-3.5 w-3.5 border-accent bg-accent ring-4 ring-accent/25'
  switch (status) {
    case 'done':
      return 'h-2.5 w-2.5 border-accent bg-accent'
    case 'running':
      return 'h-2.5 w-2.5 animate-pulse border-sev-low bg-sev-low'
    case 'failed':
      return 'h-2.5 w-2.5 border-sev-critical bg-sev-critical'
    default:
      return 'h-2.5 w-2.5 border-surface-border bg-transparent'
  }
}
