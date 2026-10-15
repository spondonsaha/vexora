import { Link, NavLink } from 'react-router-dom'
import { ThemeToggle } from '../../theme/ThemeToggle'
import type { PhaseDef, PhaseStatus } from './types'
import { chipClass } from './types'
import {
  ChartIcon,
  CheckIcon,
  CloseIcon,
  CrossIcon,
  CrosshairIcon,
  GitHubIcon,
  HomeIcon,
  PanelIcon,
} from './icons'

const appNav = [
  { to: '/onboarding', label: 'Welcome', Icon: HomeIcon },
  { to: '/targets', label: 'Scope Targets', Icon: CrosshairIcon },
  { to: '/dashboard', label: 'Attack Surface', Icon: ChartIcon },
]

export function PhaseRail({
  phases,
  activeId,
  onSelect,
  status,
  collapsed,
  onToggleCollapsed,
  mobileOpen,
  onCloseMobile,
}: {
  phases: PhaseDef[]
  activeId: string
  onSelect: (id: string) => void
  status: Record<string, PhaseStatus>
  collapsed: boolean
  onToggleCollapsed: () => void
  mobileOpen: boolean
  onCloseMobile: () => void
}) {
  const showLabels = mobileOpen || !collapsed

  const select = (id: string) => {
    onSelect(id)
    onCloseMobile()
  }

  return (
    <>
      <div
        onClick={onCloseMobile}
        aria-hidden="true"
        className={`fixed inset-0 z-40 bg-black/60 transition-opacity duration-300 md:hidden ${
          mobileOpen ? 'opacity-100' : 'pointer-events-none opacity-0'
        }`}
      />

      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-72 max-w-[85vw] flex-col border-r border-surface-border bg-surface-raised backdrop-blur transition-transform duration-300 md:sticky md:bottom-auto md:top-0 md:z-20 md:h-screen md:translate-x-0 md:bg-surface-raised/70 md:transition-[width] ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        } ${collapsed ? 'md:w-[4.75rem]' : 'md:w-60'}`}
      >
        <div className="flex h-14 items-center gap-2 border-b border-surface-border px-3">
          <Link to="/onboarding" className="flex min-w-0 items-center gap-2" title="Vexora home">
            <img src="/vexora-logo.png" alt="Vexora" className="h-8 w-8 shrink-0 rounded" />
            {showLabels && (
              <span className="truncate font-display text-base font-semibold tracking-wide text-accent">
                Vexora
              </span>
            )}
          </Link>
          <button
            type="button"
            onClick={onToggleCollapsed}
            className="ml-auto hidden h-8 w-8 shrink-0 items-center justify-center rounded-md border border-surface-border text-ink-muted transition-colors hover:border-accent/50 hover:text-accent md:inline-flex"
            aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
            title={collapsed ? 'Expand' : 'Collapse'}
          >
            <PanelIcon className="h-4 w-4" />
          </button>
          <button
            type="button"
            onClick={onCloseMobile}
            className="ml-auto inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-surface-border text-ink-muted transition-colors hover:border-accent/50 hover:text-accent md:hidden"
            aria-label="Close navigation"
            title="Close"
          >
            <CloseIcon className="h-4 w-4" />
          </button>
        </div>

        {showLabels && (
          <p className="px-4 pb-1 pt-3 text-[10px] font-medium uppercase tracking-wider text-ink-muted">
            Workflow phases
          </p>
        )}

        <nav className="flex flex-1 flex-col gap-1 overflow-y-auto p-2">
          {phases.map((phase, index) => {
            const isActive = phase.id === activeId
            const s = status[phase.id] ?? 'todo'
            return (
              <button
                key={phase.id}
                type="button"
                onClick={() => select(phase.id)}
                title={showLabels ? phase.title : `${index + 1}. ${phase.title}`}
                aria-current={isActive ? 'step' : undefined}
                className={`group flex items-center gap-3 rounded-lg border px-2 py-2 text-left transition-colors ${
                  showLabels ? '' : 'justify-center'
                } ${
                  isActive
                    ? 'border-accent/60 bg-accent/15 text-accent'
                    : 'border-transparent text-ink-muted hover:bg-surface-border/40 hover:text-ink'
                }`}
              >
                <span
                  className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-md border font-mono text-[11px] ${chipClass(
                    s,
                    isActive,
                  )}`}
                >
                  {s === 'done' ? (
                    <CheckIcon className="h-3.5 w-3.5" />
                  ) : s === 'failed' ? (
                    <CrossIcon className="h-3.5 w-3.5" />
                  ) : (
                    index + 1
                  )}
                </span>
                {showLabels && <span className="min-w-0 flex-1 truncate text-sm">{phase.label}</span>}
                {showLabels && s === 'running' && (
                  <span className="h-1.5 w-1.5 shrink-0 animate-pulse rounded-full bg-sev-low" />
                )}
              </button>
            )
          })}
        </nav>

        <div className="border-t border-surface-border p-2">
          <nav className="flex flex-col gap-1">
            {appNav.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                title={item.label}
                onClick={onCloseMobile}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-lg px-2 py-2 text-sm transition-colors ${
                    showLabels ? '' : 'justify-center'
                  } ${
                    isActive
                      ? 'bg-accent/15 text-accent'
                      : 'text-ink-muted hover:bg-surface-border/40 hover:text-ink'
                  }`
                }
              >
                <item.Icon className="h-4 w-4 shrink-0" />
                {showLabels && <span className="truncate">{item.label}</span>}
              </NavLink>
            ))}
          </nav>

          <div
            className={`mt-1 flex items-center gap-1 border-t border-surface-border/60 pt-2 ${
              showLabels ? 'justify-between px-1' : 'flex-col'
            }`}
          >
            <ThemeToggle />
            <a
              href="https://github.com/spondonsaha/vexora"
              target="_blank"
              rel="noreferrer"
              className="icon-btn"
              title="Vexora on GitHub"
              aria-label="Vexora on GitHub"
            >
              <GitHubIcon className="h-4 w-4" />
            </a>
          </div>
        </div>
      </aside>
    </>
  )
}
