export type Tone = 'accent' | 'critical' | 'high' | 'medium' | 'low' | 'info'

const toneClass: Record<Tone, string> = {
  accent: 'bg-accent',
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
}

export function StatusDot({ tone = 'info', pulse = false }: { tone?: Tone; pulse?: boolean }) {
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full ${toneClass[tone]} ${
        pulse ? 'animate-pulse' : ''
      }`}
      aria-hidden="true"
    />
  )
}
