import { Outlet } from 'react-router-dom'
import { TopBar } from './TopBar'

export function Layout() {
  return (
    <div className="flex min-h-screen flex-col bg-base">
      <TopBar />
      <main className="flex-1 overflow-x-hidden">
        <div className="mx-auto w-full max-w-7xl px-4 py-8 md:px-6 md:py-10">
          <Outlet />
        </div>
      </main>
      <footer className="border-t border-base-border/60 px-4 py-4 text-center text-[11px] text-ink-muted">
        Authorized testing only. Every target requires an explicit authorization acknowledgment before scanning.
      </footer>
    </div>
  )
}
