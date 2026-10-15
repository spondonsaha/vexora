import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'

export function RawOutputViewer({ jobId }: { jobId: string }) {
  const [stream, setStream] = useState<'stdout' | 'stderr'>('stdout')
  const output = useQuery({
    queryKey: ['raw-output', jobId, stream],
    queryFn: () => api.getScanRawOutput(jobId, stream),
    retry: false,
    refetchInterval: 2500,
  })

  return (
    <div className="card mt-3 overflow-hidden">
      <div className="flex items-center gap-2 border-b border-accent/25 px-4 py-2.5">
        <span className="font-display text-base font-medium text-ink-muted">Raw output</span>
        <div className="ml-auto flex gap-1">
          {(['stdout', 'stderr'] as const).map((s) => (
            <button
              key={s}
              className={`btn px-2 py-0.5 text-xs ${stream === s ? 'btn-primary' : ''}`}
              onClick={() => setStream(s)}
            >
              {s}
            </button>
          ))}
        </div>
      </div>
      <pre className="max-h-80 overflow-auto bg-base p-4 font-mono text-xs leading-relaxed text-ink">
        {output.isLoading
          ? 'loading...'
          : output.isError
            ? 'No output available yet.'
            : output.data || '(empty)'}
      </pre>
    </div>
  )
}
