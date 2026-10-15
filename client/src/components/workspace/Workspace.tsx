import { useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { PhaseRail } from './PhaseRail'
import { PhaseProgress } from './PhaseProgress'
import { HelpDrawer } from './HelpDrawer'
import { MenuIcon, QuestionIcon } from './icons'
import type { PhaseDef, PhaseStatus } from './types'

export function Workspace({
  phases,
  activeId,
  onSelect,
  status,
  header,
  children,
}: {
  phases: PhaseDef[]
  activeId: string
  onSelect: (id: string) => void
  status: Record<string, PhaseStatus>
  header?: ReactNode
  children: ReactNode
}) {
  const [collapsed, setCollapsed] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const activePhase = phases.find((phase) => phase.id === activeId)

  return (
    <div className="flex w-full items-stretch">
      <PhaseRail
        phases={phases}
        activeId={activeId}
        onSelect={onSelect}
        status={status}
        collapsed={collapsed}
        onToggleCollapsed={() => setCollapsed((value) => !value)}
        mobileOpen={mobileNavOpen}
        onCloseMobile={() => setMobileNavOpen(false)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <div className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-surface-border bg-surface/95 px-3 backdrop-blur md:hidden">
          <button
            type="button"
            onClick={() => setMobileNavOpen(true)}
            className="icon-btn"
            aria-label="Open navigation"
            title="Menu"
          >
            <MenuIcon className="h-4 w-4" />
          </button>
          <Link to="/onboarding" className="flex items-center gap-2">
            <img src="/vexora-logo.png" alt="Vexora" className="h-7 w-7 rounded" />
            <span className="font-display text-base font-semibold tracking-wide text-accent">
              Vexora
            </span>
          </Link>
          <button
            type="button"
            onClick={() => setHelpOpen(true)}
            className="icon-btn ml-auto"
            aria-label="Help Me Learn"
            title="Help Me Learn"
          >
            <QuestionIcon className="h-4 w-4" />
          </button>
        </div>

        {header}
        <PhaseProgress phases={phases} activeId={activeId} onSelect={onSelect} status={status} />
        <div className="flex-1 px-4 py-6 md:px-6 md:py-8">
          <div className="mx-auto w-full max-w-6xl">{children}</div>
        </div>
      </div>

      {!helpOpen && (
        <button
          type="button"
          onClick={() => setHelpOpen(true)}
          className="fixed right-0 top-1/2 z-30 hidden h-12 w-9 -translate-y-1/2 items-center justify-center rounded-l-lg border border-r-0 border-accent/40 bg-surface-raised text-accent shadow-lg transition-colors hover:bg-accent/10 md:flex"
          aria-label="Open Help Me Learn"
          title="Help Me Learn"
        >
          <QuestionIcon className="h-5 w-5" />
        </button>
      )}

      <HelpDrawer
        open={helpOpen}
        onClose={() => setHelpOpen(false)}
        phase={activePhase}
        status={activePhase ? status[activePhase.id] ?? 'todo' : 'todo'}
      />
    </div>
  )
}
