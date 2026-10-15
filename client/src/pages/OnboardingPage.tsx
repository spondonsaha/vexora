import { useNavigate } from 'react-router-dom'
import { CreateScopeTargetForm } from '../components/CreateScopeTargetForm'

export function OnboardingPage() {
  const navigate = useNavigate()

  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-6">
        <h1 className="page-title">Welcome</h1>
        <p className="mt-1 max-w-2xl text-sm text-ink-muted">
          Start by creating a scope target, or import existing scan data. Recon runs from
          recon &rarr; enumeration &rarr; prioritization &rarr; manual testing, so every
          finding is reproducible and every next step is visible.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-3">
          <CreateScopeTargetForm onCreated={(id) => navigate(`/targets/${id}`)} />
        </div>

        <div className="lg:col-span-2">
          <div className="card h-full p-4 md:p-5">
            <h2 className="section-title">Import existing scan data</h2>
            <p className="mt-1 text-sm text-ink-muted">
              Load a portable export bundle (<span className="font-mono">.vexora</span>-style)
              from a previous engagement.
            </p>

            <div className="mt-4 space-y-3">
              <input
                type="file"
                className="input font-mono text-xs file:mr-3 file:rounded file:border-0 file:bg-base-border file:px-2 file:py-1 file:text-ink-muted"
                disabled
                aria-disabled="true"
              />
              <button className="btn w-full" disabled>
                Import bundle
              </button>
            </div>

            <p className="mt-4 text-xs text-ink-muted">
              Import / export lands in a later milestone. The API surface is already
              reserved for it.
            </p>
          </div>
        </div>
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-3">
        {[
          ['Recon', 'ASN, ranges, root domains, and subdomains via 40+ tools.'],
          ['Prioritize', 'ROI scoring ranks live servers so you test the best targets first.'],
          ['Manual testing', 'Guided modules for content, params, XSS, injection, and more.'],
        ].map(([title, body]) => (
          <div key={title} className="card p-4">
            <h3 className="card-title">{title}</h3>
            <p className="mt-1 text-sm text-ink-muted">{body}</p>
          </div>
        ))}
      </div>

      <div className="mt-8 flex flex-col items-center gap-4 border-t border-base-border/60 pt-6 sm:flex-row sm:justify-between">
        <div className="flex items-center gap-3">
          <img src="/vexora-logo.png" alt="Vexora" className="h-10 w-10 rounded" />
          <div>
            <p className="font-display text-sm font-semibold text-ink">Vexora</p>
            <p className="text-xs text-ink-muted">
              AI-native attack surface reconnaissance and bug bounty framework.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <a
            href="https://www.linkedin.com/in/spondonsaha/"
            target="_blank"
            rel="noreferrer"
            className="text-accent hover:underline"
          >
            LinkedIn
          </a>
          <a
            href="https://github.com/spondonsaha"
            target="_blank"
            rel="noreferrer"
            className="text-accent hover:underline"
          >
            GitHub
          </a>
        </div>
      </div>
    </div>
  )
}
