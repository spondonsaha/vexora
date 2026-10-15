import { NavLink } from 'react-router-dom'

const navItems = [
  { to: '/onboarding', label: 'Welcome' },
  { to: '/targets', label: 'Scope Targets' },
  { to: '/dashboard', label: 'Attack Surface' },
]

interface SidebarProps {
  open: boolean
  onNavigate: () => void
}

export function Sidebar({ open, onNavigate }: SidebarProps) {
  return (
    <>
      {open && (
        <div
          className="fixed inset-0 z-30 bg-black/60 md:hidden"
          onClick={onNavigate}
          aria-hidden="true"
        />
      )}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-60 border-r border-surface-border bg-surface-raised transition-transform md:static md:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex h-14 items-center gap-2 border-b border-surface-border px-4">
          <img
            src="/vexora-logo.png"
            alt="Vexora"
            className="h-7 w-7 shrink-0 rounded"
          />
          <span className="font-display text-base font-semibold tracking-wide text-accent">
            Vexora
          </span>
        </div>
        <nav className="flex flex-col gap-1 p-2">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={onNavigate}
              className={({ isActive }) =>
                `rounded px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? 'bg-accent/15 text-accent'
                    : 'text-ink-muted hover:bg-surface-border/60 hover:text-ink'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto space-y-3 px-4 py-4 text-[11px] leading-relaxed text-ink-muted">
          <p>
            Authorized testing only. Every target requires an explicit authorization
            acknowledgment before scanning.
          </p>
          <div className="border-t border-surface-border/60 pt-3">
            <p className="font-display text-xs font-semibold text-ink">Vexora</p>
            <p>
              Built by{' '}
              <a
                href="https://www.linkedin.com/in/spondonsaha/"
                target="_blank"
                rel="noreferrer"
                className="text-accent hover:underline"
              >
                Spondon Saha
              </a>
            </p>
            <div className="mt-1.5 flex items-center gap-3">
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
      </aside>
    </>
  )
}
