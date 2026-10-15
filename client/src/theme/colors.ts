export const palette = {
  base: '#0A0D12',
  raised: '#12161D',
  border: '#232833',
  text: '#E6E6E6',
  textMuted: '#8A8F98',
  accent: '#C0392B',
} as const

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export const severityColor: Record<Severity, string> = {
  critical: '#E0554B',
  high: '#D2691E',
  medium: '#C9A227',
  low: '#6E9ECF',
  info: '#8A8F98',
}
