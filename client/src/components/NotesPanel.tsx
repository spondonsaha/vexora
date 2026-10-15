import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { CollapsiblePanel } from './ui'

export function NotesPanel({
  scopeTargetId,
  initialNotes,
}: {
  scopeTargetId: string
  initialNotes: string
}) {
  const queryClient = useQueryClient()
  const [notes, setNotes] = useState(initialNotes ?? '')
  const [saved, setSaved] = useState(initialNotes ?? '')
  const [savedAt, setSavedAt] = useState<string | null>(null)

  useEffect(() => {
    setNotes(initialNotes ?? '')
    setSaved(initialNotes ?? '')
    setSavedAt(null)
  }, [scopeTargetId])

  const mutation = useMutation({
    mutationFn: (value: string) => api.setScopeTargetNotes(scopeTargetId, value),
    onSuccess: (target) => {
      setSaved(target.notes ?? '')
      setSavedAt(target.updated_at)
      void queryClient.invalidateQueries({ queryKey: ['scope-target', scopeTargetId] })
    },
  })

  const dirty = notes !== saved
  const canSave = dirty && !mutation.isPending

  const save = () => {
    if (canSave) mutation.mutate(notes)
  }

  const onKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 's') {
      event.preventDefault()
      save()
    }
  }

  return (
    <CollapsiblePanel
      id="notes"
      title="Notes"
      description="Context, hypotheses and follow-ups about this target."
      status={
        <span className="flex items-center gap-3">
          <span className="font-mono text-xs text-ink-muted">{notes.length} chars</span>
          {dirty ? (
            <span className="text-xs text-sev-medium">Unsaved changes</span>
          ) : savedAt ? (
            <span className="text-xs text-ink-muted">
              Saved {new Date(savedAt).toLocaleString()}
            </span>
          ) : null}
        </span>
      }
      actions={
        <button className="btn btn-primary" disabled={!canSave} onClick={save}>
          {mutation.isPending ? 'Saving...' : 'Save notes'}
        </button>
      }
    >
      {mutation.isError && (
        <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
          {mutation.error instanceof ApiError ? mutation.error.message : 'Failed to save notes'}
        </p>
      )}

      <textarea
        className="input mt-3 min-h-[12rem] w-full resize-y font-mono text-sm leading-relaxed"
        value={notes}
        onChange={(event) => setNotes(event.target.value)}
        onKeyDown={onKeyDown}
        placeholder="Write anything useful about this target... (Ctrl/Cmd+S to save)"
        spellCheck={false}
        aria-label="Target notes"
      />
    </CollapsiblePanel>
  )
}
