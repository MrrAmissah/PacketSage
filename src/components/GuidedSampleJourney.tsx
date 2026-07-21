import React from 'react';
import { Check, Circle, Compass, X } from 'lucide-react';
import type { JudgePathProgress, JudgePathActionId, JudgePathDestination } from '../lib/judgePath';

interface GuidedSampleJourneyProps {
  progress: JudgePathProgress;
  onDismiss(): void;
  onNavigate(destination: JudgePathDestination): void;
  onPrimaryAction(actionId: JudgePathActionId): void;
}

export default function GuidedSampleJourney({ progress, onDismiss, onNavigate, onPrimaryAction }: GuidedSampleJourneyProps) {
  return (
    <aside
      aria-label="Guided sample journey"
      className="mb-4 rounded-xl border border-accent-primary/20 bg-surface px-3 py-3 shadow-sm sm:px-4"
      data-testid="guided-sample-journey"
    >
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-[9px] font-bold uppercase tracking-widest text-accent-primary">Guided investigation sample</p>
              <p className="mt-0.5 text-xs font-semibold text-text-primary" aria-live="polite">
                {progress.completedCount} of {progress.stages.length} stages complete
              </p>
            </div>
            <button type="button" onClick={onDismiss} className="rounded-md p-1.5 text-text-muted hover:bg-surface-muted hover:text-text-primary lg:hidden" aria-label="Dismiss guided sample journey">
              <X size={14} />
            </button>
          </div>
          <ol className="mt-2 flex flex-wrap gap-x-4 gap-y-1.5">
            {progress.stages.map(stage => (
              <li key={stage.id} className={`flex items-center gap-1.5 text-[10px] ${stage.complete ? 'font-semibold text-status-success' : 'text-text-muted'}`}>
                {stage.complete ? <Check size={11} aria-hidden="true" /> : <Circle size={9} aria-hidden="true" />}
                {stage.label}
              </li>
            ))}
          </ol>
          <p className="mt-2 text-[10px] leading-relaxed text-text-muted">
            Evidence-grounded Investigation examines one selected signal with exact citations. Capture Overview is optional whole-capture orientation.
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <button type="button" onClick={() => onNavigate('capture-overview')} className="inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 text-[10px] font-semibold text-text-secondary hover:border-purple-500/30 hover:text-text-primary">
            <Compass size={11} /> Optional capture overview
          </button>
          <button type="button" onClick={() => onPrimaryAction(progress.nextAction.id)} className="rounded-lg bg-accent-primary px-3 py-2 text-[10px] font-bold text-white hover:bg-accent-primary-hover">
            {progress.nextAction.label}
          </button>
          <button type="button" onClick={onDismiss} className="hidden rounded-md p-1.5 text-text-muted hover:bg-surface-muted hover:text-text-primary lg:inline-flex" aria-label="Dismiss guided sample journey">
            <X size={14} />
          </button>
        </div>
      </div>
    </aside>
  );
}
