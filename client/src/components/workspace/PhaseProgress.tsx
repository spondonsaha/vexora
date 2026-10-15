import { Fragment } from 'react'
import { StatusDot } from '../StatusDot'
import type { PhaseDef, PhaseStatus } from './types'
import { dotClass, phaseStatusLabel, phaseStatusTone } from './types'

export function PhaseProgress({
  phases,
  activeId,
  onSelect,
  status,
}: {
  phases: PhaseDef[]
  activeId: string
  onSelect: (id: string) => void
  status: Record<string, PhaseStatus>
}) {
  const activeIndex = Math.max(
    0,
    phases.findIndex((phase) => phase.id === activeId),
  )
  const active = phases[activeIndex]
  const activeStatus: PhaseStatus = active ? status[active.id] ?? 'todo' : 'todo'

  return (
    <div className="sticky top-14 z-10 border-b border-surface-border bg-surface/95 px-4 py-3 backdrop-blur md:top-0 md:px-6">
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0">
          <p className="text-[10px] font-medium uppercase tracking-wider text-ink-muted">
            Phase {activeIndex + 1} of {phases.length}
          </p>
          <p className="truncate font-display text-sm font-semibold text-ink">{active?.title}</p>
        </div>
        <span className="flex shrink-0 items-center gap-2 text-xs text-ink-muted">
          <StatusDot tone={phaseStatusTone[activeStatus]} pulse={activeStatus === 'running'} />
          {phaseStatusLabel[activeStatus]}
        </span>
      </div>

      <div
        className="mt-1.5 flex items-center overflow-x-auto px-1 py-1.5"
        role="list"
        aria-label="Workflow progress"
      >
        {phases.map((phase, index) => {
          const s = status[phase.id] ?? 'todo'
          const isActive = phase.id === activeId
          const prev = index > 0 ? status[phases[index - 1].id] ?? 'todo' : 'todo'
          return (
            <Fragment key={phase.id}>
              {index > 0 && (
                <span
                  className={`h-px flex-1 ${prev === 'done' ? 'bg-accent/50' : 'bg-surface-border'}`}
                  aria-hidden="true"
                />
              )}
              <button
                type="button"
                role="listitem"
                onClick={() => onSelect(phase.id)}
                title={`${index + 1}. ${phase.title}`}
                aria-label={phase.title}
                aria-current={isActive ? 'step' : undefined}
                className={`shrink-0 rounded-full border transition-all ${dotClass(s, isActive)}`}
              />
            </Fragment>
          )
        })}
      </div>
    </div>
  )
}
