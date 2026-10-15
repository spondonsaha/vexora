import { Outlet, useLocation } from 'react-router-dom'
import { TopBar } from './TopBar'

export function Layout() {
  const { pathname } = useLocation()
  const isWorkspace = /^\/targets\/[^/]+/.test(pathname)

  return (
    <div className="flex min-h-screen flex-col bg-surface">
      {!isWorkspace && <TopBar />}
      <main className="flex-1">
        <Outlet />
      </main>
      {!isWorkspace && (
        <footer className="border-t border-surface-border/60 px-4 py-4 text-center text-[11px] text-ink-muted">
          Authorized testing only. Every target requires an explicit authorization acknowledgment
          before scanning.
        </footer>
      )}
    </div>
  )
}
