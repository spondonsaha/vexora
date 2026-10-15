import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { scopeTargetTypeLabels, type ScopeTargetType } from '../lib/types'
import { Badge } from '../components/Badge'

export function DashboardPage() {
  const query = useQuery({
    queryKey: ['scope-targets', 'all'],
    queryFn: () => api.listScopeTargets(),
  })

  const targets = query.data?.items ?? []
  const active = targets.filter((target) => target.active).length
  const counts = targets.reduce<Record<ScopeTargetType, number>>(
    (acc, target) => {
      acc[target.type] += 1
      return acc
    },
    { company: 0, wildcard: 0, url: 0 },
  )

  return (
    <div className="mx-auto max-w-6xl px-4 py-8 md:px-6 md:py-10">
      <h1 className="page-title">Attack surface</h1>
      <p className="mt-1 text-sm text-ink-muted">
        Unified view of your scope. Domains, subdomains, live servers, endpoints, and findings
        populate here as workflows complete.
      </p>

      <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Scope targets" value={targets.length} />
        <StatCard label="Active" value={active} tone="accent" />
        <StatCard label="Root domains" value={0} muted />
        <StatCard label="Live servers" value={0} muted />
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <section className="card p-4 lg:col-span-2">
          <h2 className="section-title">Targets by type</h2>
          <div className="mt-4 space-y-3">
            {(Object.keys(scopeTargetTypeLabels) as ScopeTargetType[]).map((type) => (
              <div key={type} className="flex items-center gap-3">
                <span className="w-24 text-sm text-ink-muted">
                  {scopeTargetTypeLabels[type]}
                </span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-surface-border">
                  <div
                    className="h-full bg-accent/70"
                    style={{
                      width: targets.length
                        ? `${(counts[type] / targets.length) * 100}%`
                        : '0%',
                    }}
                  />
                </div>
                <span className="w-8 text-right font-mono text-sm text-ink">
                  {counts[type]}
                </span>
              </div>
            ))}
          </div>
        </section>

        <section className="card p-4">
          <h2 className="section-title">ROI leaderboard</h2>
          <p className="mt-2 text-sm text-ink-muted">
            The highest-ROI live servers land here once scoring is enabled. This is where you
            decide what to test manually first &mdash; highest score, then forget the rest.
          </p>
          <div className="mt-4 flex h-24 items-center justify-center rounded border border-dashed border-surface-border text-xs text-ink-muted">
            No scored targets yet
          </div>
        </section>
      </div>

      <section className="card mt-6 overflow-hidden">
        <div className="flex items-center justify-between border-b border-surface-border p-4">
          <h2 className="section-title">Scope targets</h2>
          <Link to="/targets" className="text-sm text-accent hover:underline">
            Manage
          </Link>
        </div>
        {targets.length === 0 ? (
          <p className="p-4 text-sm text-ink-muted">
            Nothing in scope yet.{' '}
            <Link to="/onboarding" className="text-accent hover:underline">
              Create a target
            </Link>
            .
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((target) => (
                  <tr key={target.id} className="hover:bg-surface-border/30">
                    <td>
                      <Badge tone="muted">{scopeTargetTypeLabels[target.type]}</Badge>
                    </td>
                    <td>
                      <Link
                        to={`/targets/${target.id}`}
                        className="hover:text-accent hover:underline"
                      >
                        {target.value}
                      </Link>
                    </td>
                    <td>
                      {target.active ? (
                        <Badge tone="accent">Active</Badge>
                      ) : (
                        <Badge tone="muted">Inactive</Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

function StatCard({
  label,
  value,
  tone,
  muted,
}: {
  label: string
  value: number
  tone?: 'accent'
  muted?: boolean
}) {
  return (
    <div className="card p-5">
      <p className="stat-label">{label}</p>
      <p
        className={`stat-number mt-2 ${
          muted ? 'text-ink-muted' : tone === 'accent' ? 'text-accent' : 'text-ink'
        }`}
      >
        {value}
      </p>
    </div>
  )
}
