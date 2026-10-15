import { StatusDot } from '../StatusDot'
import type { PhaseDef, PhaseStatus } from './types'
import { phaseStatusLabel, phaseStatusTone } from './types'
import { CloseIcon, QuestionIcon } from './icons'

export function HelpDrawer({
  open,
  onClose,
  phase,
  status,
}: {
  open: boolean
  onClose: () => void
  phase: PhaseDef | undefined
  status: PhaseStatus
}) {
  return (
    <>
      <div
        onClick={onClose}
        aria-hidden="true"
        className={`fixed inset-0 z-40 bg-black/60 transition-opacity duration-300 ${
          open ? 'opacity-100' : 'pointer-events-none opacity-0'
        }`}
      />

      <aside
        aria-hidden={!open}
        aria-label="Help Me Learn"
        className={`fixed inset-y-0 right-0 z-50 flex w-[360px] max-w-[90vw] flex-col border-l border-surface-border bg-surface-raised shadow-2xl transition-transform duration-300 ${
          open ? 'translate-x-0' : 'translate-x-full'
        }`}
      >
        <div className="flex items-center justify-between border-b border-surface-border px-4 py-3">
          <div className="flex items-center gap-2 text-accent">
            <span className="flex h-7 w-7 items-center justify-center rounded-md border border-accent/40 bg-accent/10">
              <QuestionIcon className="h-4 w-4" />
            </span>
            <span className="font-display text-sm font-semibold">Help Me Learn</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-surface-border text-ink-muted transition-colors hover:border-accent/50 hover:text-accent"
            aria-label="Close help"
            title="Close"
          >
            <CloseIcon className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          {phase ? (
            <>
              <p className="text-[10px] font-medium uppercase tracking-wider text-ink-muted">
                Current phase
              </p>
              <h2 className="mt-1 font-display text-lg font-semibold text-ink">{phase.title}</h2>

              <span className="mt-3 inline-flex items-center gap-2 rounded-full border border-surface-border px-3 py-1 text-xs text-ink-muted">
                <StatusDot tone={phaseStatusTone[status]} pulse={status === 'running'} />
                {phaseStatusLabel[status]}
              </span>

              <p className="mt-4 text-sm leading-relaxed text-ink-muted">{phase.help}</p>

              {phase.tools && phase.tools.length > 0 && (
                <div className="mt-6">
                  <p className="text-[10px] font-medium uppercase tracking-wider text-ink-muted">
                    Tools in this phase
                  </p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {phase.tools.map((tool) => (
                      <span
                        key={tool}
                        className="rounded-md border border-surface-border bg-surface-panel px-2 py-1 font-mono text-[11px] text-ink-muted"
                      >
                        {tool}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <p className="text-sm text-ink-muted">Select a phase to see guidance.</p>
          )}
        </div>

        <div className="border-t border-surface-border px-4 py-3 text-[11px] leading-relaxed text-ink-muted">
          Authorized testing only. Confirm authorization before scanning any target.
        </div>
      </aside>
    </>
  )
}
