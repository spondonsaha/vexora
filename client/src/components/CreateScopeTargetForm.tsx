import { useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { scopeTargetTypeLabels, type ScopeTargetType } from '../lib/types'

const placeholders: Record<ScopeTargetType, string> = {
  company: 'Acme Corp',
  wildcard: '*.example.com',
  url: 'https://app.example.com/login',
}

const hints: Record<ScopeTargetType, string> = {
  company:
    'Discovers everything the organization owns: ASNs, on-prem ranges, root domains, then auto-chains into wildcard targets.',
  wildcard:
    'Enumerates and prioritizes every subdomain under the domain, ending with ROI scoring.',
  url: 'A single target for deep, guided manual-testing modules (content, params, XSS, injection).',
}

interface CreateScopeTargetFormProps {
  onCreated?: (id: string) => void
}

export function CreateScopeTargetForm({ onCreated }: CreateScopeTargetFormProps) {
  const queryClient = useQueryClient()
  const [type, setType] = useState<ScopeTargetType>('wildcard')
  const [value, setValue] = useState('')
  const [description, setDescription] = useState('')
  const [authConfirmed, setAuthConfirmed] = useState(false)

  const mutation = useMutation({
    mutationFn: () =>
      api.createScopeTarget({
        type,
        value: value.trim(),
        description: description.trim(),
        auth_confirmed: authConfirmed,
      }),
    onSuccess: (created) => {
      void queryClient.invalidateQueries({ queryKey: ['scope-targets'] })
      setValue('')
      setDescription('')
      setAuthConfirmed(false)
      onCreated?.(created.id)
    },
  })

  const error =
    mutation.error instanceof ApiError
      ? mutation.error.message
      : mutation.isError
        ? 'Failed to create scope target'
        : null

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (!value.trim()) return
    mutation.mutate()
  }

  return (
    <form onSubmit={handleSubmit} className="card p-4 md:p-5">
      <div className="mb-4">
        <h2 className="section-title">New scope target</h2>
        <p className="mt-1 text-sm text-ink-muted">{hints[type]}</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <label className="label" htmlFor="target-type">
            Type
          </label>
          <select
            id="target-type"
            className="input"
            value={type}
            onChange={(event) => setType(event.target.value as ScopeTargetType)}
          >
            {(Object.keys(scopeTargetTypeLabels) as ScopeTargetType[]).map((key) => (
              <option key={key} value={key}>
                {scopeTargetTypeLabels[key]}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="label" htmlFor="target-value">
            Value
          </label>
          <input
            id="target-value"
            className="input font-mono"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            placeholder={placeholders[type]}
            autoComplete="off"
          />
        </div>

        <div className="md:col-span-2">
          <label className="label" htmlFor="target-description">
            Description (optional)
          </label>
          <input
            id="target-description"
            className="input"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            placeholder="Program, engagement reference, or notes"
            autoComplete="off"
          />
        </div>
      </div>

      <label className="mt-4 flex items-start gap-3 rounded border border-base-border bg-base p-3 text-sm">
        <input
          type="checkbox"
          className="mt-0.5 h-4 w-4 accent-accent"
          checked={authConfirmed}
          onChange={(event) => setAuthConfirmed(event.target.checked)}
        />
        <span className="text-ink-muted">
          <span className="text-ink">I am authorized to test this target.</span> It is owned
          by me/my organization, or it is covered by the scope of a bug bounty program I am
          participating in. I will respect all program rules and out-of-scope exclusions.
        </span>
      </label>

      {error && (
        <p role="alert" className="mt-3 font-mono text-sm text-sev-critical">
          {error}
        </p>
      )}

      <div className="mt-4 flex items-center justify-end gap-3">
        <button
          type="submit"
          className="btn btn-primary"
          disabled={mutation.isPending || !value.trim() || !authConfirmed}
        >
          {mutation.isPending ? 'Creating...' : 'Create target'}
        </button>
      </div>
    </form>
  )
}
