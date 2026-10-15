import { useQuery } from '@tanstack/react-query'
import { api } from '../../lib/api'
import { StatusDot, type Tone } from '../StatusDot'

export function ApiStatus() {
  const health = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
    refetchInterval: 15_000,
  })

  const okay = health.data?.status === 'ok'
  const tone: Tone = health.isLoading ? 'info' : okay ? 'accent' : 'critical'
  const label = health.isLoading
    ? 'connecting'
    : okay
      ? 'operational'
      : health.isError
        ? 'offline'
        : 'degraded'

  return (
    <span className="hidden items-center gap-2 text-xs text-ink-muted sm:flex" title="API status">
      <StatusDot tone={tone} pulse={health.isLoading} />
      <span className="font-mono">api {label}</span>
    </span>
  )
}
