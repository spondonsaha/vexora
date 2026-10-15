import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { scopeTargetTypeLabels, type ScopeTarget, type ScopeTargetType } from '../lib/types'
import { Badge } from '../components/Badge'

type Filter = ScopeTargetType | 'all'

export function ScopeTargetsPage() {
  const [filter, setFilter] = useState<Filter>('all')
  const [actionError, setActionError] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: ['scope-targets', filter],
    queryFn: () => api.listScopeTargets(filter === 'all' ? undefined : filter),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['scope-targets'] })

  const activate = useMutation({
    mutationFn: (target: ScopeTarget) => api.activateScopeTarget(target.id),
    onSuccess: () => {
      setActionError(null)
      void invalidate()
    },
    onError: (error) =>
      setActionError(error instanceof ApiError ? error.message : 'Activation failed'),
  })

  const remove = useMutation({
    mutationFn: (target: ScopeTarget) => api.deleteScopeTarget(target.id),
    onSuccess: () => {
      setActionError(null)
      void invalidate()
    },
    onError: (error) =>
      setActionError(error instanceof ApiError ? error.message : 'Delete failed'),
  })

  const targets = query.data?.items ?? []

  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="page-title">Scope targets</h1>
        <div className="ml-auto flex items-center gap-2">
          <label className="text-xs text-ink-muted" htmlFor="filter">
            Filter
          </label>
          <select
            id="filter"
            className="input w-40"
            value={filter}
            onChange={(event) => setFilter(event.target.value as Filter)}
          >
            <option value="all">All</option>
            {(Object.keys(scopeTargetTypeLabels) as ScopeTargetType[]).map((key) => (
              <option key={key} value={key}>
                {scopeTargetTypeLabels[key]}
              </option>
            ))}
          </select>
        </div>
      </div>

      {actionError && (
        <p role="alert" className="mb-3 rounded border border-sev-critical/40 bg-sev-critical/10 p-3 font-mono text-sm text-sev-critical">
          {actionError}
        </p>
      )}

      <div className="card overflow-hidden">
        {query.isLoading && <p className="p-4 text-sm text-ink-muted">Loading targets...</p>}

        {query.isError && (
          <p className="p-4 font-mono text-sm text-sev-critical">
            Failed to load scope targets.
          </p>
        )}

        {!query.isLoading && targets.length === 0 && (
          <p className="p-4 text-sm text-ink-muted">
            No scope targets yet. Create one from the{' '}
            <Link to="/onboarding" className="text-accent hover:underline">
              Welcome
            </Link>{' '}
            screen.
          </p>
        )}

        {targets.length > 0 && (
          <div className="hidden overflow-x-auto md:block">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Authorization</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((target) => (
                  <tr key={target.id} className="hover:bg-base-border/30">
                    <td>
                      <Badge tone="muted">{scopeTargetTypeLabels[target.type]}</Badge>
                    </td>
                    <td>
                      <Link
                        to={`/targets/${target.id}`}
                        className="text-ink hover:text-accent hover:underline"
                      >
                        {target.value}
                      </Link>
                    </td>
                    <td>
                      {target.auth_confirmed ? (
                        <Badge tone="low">Confirmed</Badge>
                      ) : (
                        <Badge tone="medium">Pending</Badge>
                      )}
                    </td>
                    <td>
                      {target.active ? (
                        <Badge tone="accent">Active</Badge>
                      ) : (
                        <Badge tone="muted">Inactive</Badge>
                      )}
                    </td>
                    <td className="text-ink-muted">{formatDate(target.created_at)}</td>
                    <td>
                      <div className="flex justify-end gap-2">
                        <button
                          className="btn btn-primary"
                          disabled={
                            target.active ||
                            !target.auth_confirmed ||
                            activate.isPending ||
                            remove.isPending
                          }
                          title={
                            !target.auth_confirmed
                              ? 'Confirm authorization before activating'
                              : undefined
                          }
                          onClick={() => activate.mutate(target)}
                        >
                          {target.active ? 'Active' : 'Activate'}
                        </button>
                        <button
                          className="btn btn-danger"
                          disabled={remove.isPending}
                          onClick={() => remove.mutate(target)}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {targets.length > 0 && (
          <div className="divide-y divide-base-border md:hidden">
            {targets.map((target) => (
              <div key={target.id} className="space-y-3 p-4">
                <div className="flex items-center justify-between gap-3">
                  <Link to={`/targets/${target.id}`} className="font-mono text-sm text-ink">
                    {target.value}
                  </Link>
                  <Badge tone="muted">{scopeTargetTypeLabels[target.type]}</Badge>
                </div>
                <div className="flex flex-wrap gap-2">
                  {target.auth_confirmed ? (
                    <Badge tone="low">Auth confirmed</Badge>
                  ) : (
                    <Badge tone="medium">Auth pending</Badge>
                  )}
                  {target.active ? (
                    <Badge tone="accent">Active</Badge>
                  ) : (
                    <Badge tone="muted">Inactive</Badge>
                  )}
                </div>
                <div className="flex gap-2">
                  <button
                    className="btn btn-primary flex-1"
                    disabled={
                      target.active ||
                      !target.auth_confirmed ||
                      activate.isPending ||
                      remove.isPending
                    }
                    onClick={() => activate.mutate(target)}
                  >
                    {target.active ? 'Active' : 'Activate'}
                  </button>
                  <button
                    className="btn btn-danger flex-1"
                    disabled={remove.isPending}
                    onClick={() => remove.mutate(target)}
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function formatDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}
