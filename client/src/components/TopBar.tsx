import { useQuery } from '@tanstack/react-query'
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import { ThemeToggle } from '../theme/ThemeToggle'
import { StatusDot, type Tone } from './StatusDot'

const navItems = [
  { to: '/onboarding', label: 'Welcome' },
  { to: '/targets', label: 'Scope Targets' },
  { to: '/dashboard', label: 'Attack Surface' },
]

function AppLogo({ className = 'h-6 w-6' }: { className?: string }) {
  return (
    <img
      src="/vexora-logo.png"
      alt="Vexora"
      className={`${className} shrink-0 rounded object-contain`}
    />
  )
}

function Icon({ name }: { name: 'help' | 'profile' | 'settings' }) {
  const common = {
    viewBox: '0 0 24 24',
    className: 'h-[18px] w-[18px]',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
  }
  if (name === 'help') {
    return (
      <svg {...common}>
        <circle cx="12" cy="12" r="9" />
        <path d="M9.5 9.5a2.5 2.5 0 1 1 3.4 2.3c-.7.3-1 .9-1 1.7v.3" />
        <line x1="12" y1="17" x2="12" y2="17.01" />
      </svg>
    )
  }
  if (name === 'profile') {
    return (
      <svg {...common}>
        <circle cx="12" cy="8.5" r="3.5" />
        <path d="M5 19.5a7 7 0 0 1 14 0" />
      </svg>
    )
  }
  return (
    <svg {...common}>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2v.2a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.6 1.7 1.7 0 0 0-1.9.4l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.2-2.9H4a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.6-1.1 1.7 1.7 0 0 0-.4-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H10a1.7 1.7 0 0 0 1-1.5V4a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 2.9 1.2l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9v.1a1.7 1.7 0 0 0 1.5 1H22a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
    </svg>
  )
}

export function TopBar() {
  const location = useLocation()
  const navigate = useNavigate()

  const health = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
    refetchInterval: 15_000,
  })

  const targets = useQuery({
    queryKey: ['scope-targets', 'all'],
    queryFn: () => api.listScopeTargets(),
  })

  const okay = health.data?.status === 'ok'
  const tone: Tone = health.isLoading ? 'info' : okay ? 'accent' : 'critical'
  const healthLabel = health.isLoading
    ? 'connecting'
    : okay
      ? 'operational'
      : health.isError
        ? 'offline'
        : 'degraded'

  const match = location.pathname.match(/^\/targets\/([^/]+)/)
  const currentId = match?.[1]
  const items = targets.data?.items ?? []
  const activeTarget = currentId
    ? items.find((target) => target.id === currentId)
    : items.find((target) => target.active)

  return (
    <header className="sticky top-0 z-30 border-b border-base-border bg-base/95 backdrop-blur">
      <div className="mx-auto w-full max-w-7xl px-4 md:px-6">
        <div className="flex h-16 items-center gap-4">
          <Link to="/onboarding" className="flex shrink-0 items-center gap-2.5">
            <AppLogo className="h-8 w-8" />
            <span className="font-display text-lg font-semibold tracking-wide text-accent">
              Vexora
            </span>
          </Link>

          <nav className="ml-2 hidden items-center gap-1 md:flex">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) => `nav-link ${isActive ? 'nav-link-active' : ''}`}
              >
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-2">
            <Link to="/onboarding" className="btn btn-primary hidden sm:inline-flex">
              Add Scope Target
            </Link>
            <select
              className="input hidden w-48 py-1.5 md:block"
              value={currentId ?? ''}
              onChange={(event) => {
                if (event.target.value) navigate(`/targets/${event.target.value}`)
              }}
              aria-label="Select scope target"
              title="Jump to a scope target"
            >
              <option value="">Jump to target…</option>
              {items.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.value}
                </option>
              ))}
            </select>
            <div className="ml-1 flex items-center gap-1">
              <ThemeToggle />
              <Link to="/onboarding" className="icon-btn" aria-label="Help" title="Help">
                <Icon name="help" />
              </Link>
              <button type="button" className="icon-btn" aria-label="Profile" title="Profile">
                <Icon name="profile" />
              </button>
              <button type="button" className="icon-btn" aria-label="Settings" title="Settings">
                <Icon name="settings" />
              </button>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 border-t border-base-border/60 py-2.5">
          <span className="section-label shrink-0 font-display font-medium">Active Scope Target</span>
          <span className="target-bar">
            <span className="truncate">{activeTarget?.value ?? 'None selected'}</span>
          </span>
          <div className="ml-auto flex shrink-0 items-center gap-2 text-xs text-ink-muted">
            <StatusDot tone={tone} pulse={health.isLoading} />
            <span className="font-mono">api {healthLabel}</span>
          </div>
        </div>
      </div>
    </header>
  )
}
