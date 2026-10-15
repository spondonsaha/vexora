import type { ReactNode } from 'react'
import type { Tone } from './StatusDot'

const toneClass: Record<Tone | 'muted', string> = {
  accent: 'border-accent/50 bg-accent/10 text-accent',
  critical: 'border-sev-critical/50 bg-sev-critical/10 text-sev-critical',
  high: 'border-sev-high/50 bg-sev-high/10 text-sev-high',
  medium: 'border-sev-medium/50 bg-sev-medium/10 text-sev-medium',
  low: 'border-sev-low/50 bg-sev-low/10 text-sev-low',
  info: 'border-sev-info/40 bg-sev-info/10 text-ink-muted',
  muted: 'border-surface-border bg-surface-border/40 text-ink-muted',
}

export function Badge({ tone = 'info', children }: { tone?: Tone | 'muted'; children: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${toneClass[tone]}`}
    >
      {children}
    </span>
  )
}
