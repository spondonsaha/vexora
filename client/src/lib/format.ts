export function formatTime(value: string | null): string {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString()
}

export function formatDuration(startISO: string | null, endISO: string | null): string {
  if (!startISO) return '-'
  const start = new Date(startISO).getTime()
  const end = endISO ? new Date(endISO).getTime() : Date.now()
  if (Number.isNaN(start) || Number.isNaN(end)) return '-'
  const seconds = Math.max(0, Math.round((end - start) / 1000))
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  return `${minutes}m ${seconds % 60}s`
}
