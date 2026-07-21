import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowRight, Focus, X } from 'lucide-react';
import { createPortal } from 'react-dom';
import { GUIDED_TOUR_STEPS, guidedTourProgressControl } from '../lib/guidedTour';

interface ContextualSpotlightTourProps {
  workflowIndex: number;
  replay: boolean;
  requestId: number;
  onDismiss(): void;
  onComplete(): void;
  onDisplayStepChange(stepIndex: number): void;
  onReviewSignal(): void;
  onOpenAssessment(): void;
}

interface TargetPosition {
  rect: DOMRect;
  callout: { left: number; top: number; width: number };
}

const EDGE_GAP = 12;
const TARGET_GAP = 10;
const CALLOUT_MAX_WIDTH = 360;

function visibleTarget(selector: string): HTMLElement | null {
  return Array.from(document.querySelectorAll<HTMLElement>(selector)).find(element => {
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0 && getComputedStyle(element).visibility !== 'hidden';
  }) || null;
}

function calloutPosition(rect: DOMRect, height: number): TargetPosition['callout'] {
  const width = Math.min(CALLOUT_MAX_WIDTH, window.innerWidth - EDGE_GAP * 2);
  const left = Math.min(
    Math.max(rect.left + rect.width / 2 - width / 2, EDGE_GAP),
    window.innerWidth - width - EDGE_GAP,
  );
  const below = rect.bottom + TARGET_GAP;
  const above = rect.top - height - TARGET_GAP;
  const preferredTop = below + height <= window.innerHeight - EDGE_GAP
    ? below
    : above >= EDGE_GAP
      ? above
      : window.innerHeight - height - EDGE_GAP;
  const top = Math.min(
    Math.max(preferredTop, EDGE_GAP),
    Math.max(EDGE_GAP, window.innerHeight - height - EDGE_GAP),
  );
  return { left, top, width };
}

export default function ContextualSpotlightTour({
  workflowIndex,
  replay,
  requestId,
  onDismiss,
  onComplete,
  onDisplayStepChange,
  onReviewSignal,
  onOpenAssessment,
}: ContextualSpotlightTourProps) {
  const reachableStepIndex = Math.min(workflowIndex, GUIDED_TOUR_STEPS.length - 1);
  const [displayStepIndex, setDisplayStepIndex] = useState(replay ? 0 : reachableStepIndex);
  const [reviewingEarlierStep, setReviewingEarlierStep] = useState(replay && reachableStepIndex > 0);
  const [position, setPosition] = useState<TargetPosition | null>(null);
  const calloutRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const step = GUIDED_TOUR_STEPS[displayStepIndex];
  const targetAvailable = position !== null;
  const progressControl = guidedTourProgressControl(displayStepIndex, workflowIndex);

  useEffect(() => {
    setDisplayStepIndex(replay ? 0 : reachableStepIndex);
    setReviewingEarlierStep(replay && reachableStepIndex > 0);
  }, [requestId]);

  useEffect(() => {
    if (!reviewingEarlierStep) setDisplayStepIndex(reachableStepIndex);
  }, [reachableStepIndex, reviewingEarlierStep]);

  const refreshPosition = useCallback(() => {
    const target = visibleTarget(`[data-tour-target="${step.target}"]`);
    if (!target) {
      setPosition(null);
      return;
    }
    const rect = target.getBoundingClientRect();
    const calloutHeight = calloutRef.current?.getBoundingClientRect().height || 220;
    setPosition({ rect, callout: calloutPosition(rect, calloutHeight) });
  }, [step.target]);

  const ensureTargetInView = useCallback(() => {
    const target = visibleTarget(`[data-tour-target="${step.target}"]`);
    if (!target) return;
    const rect = target.getBoundingClientRect();
    if (rect.top >= EDGE_GAP && rect.bottom <= window.innerHeight - EDGE_GAP) return;
    target.scrollIntoView({
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
      block: 'center',
      inline: 'nearest',
    });
  }, [step.target]);

  useLayoutEffect(() => {
    const syncTarget = () => {
      ensureTargetInView();
      refreshPosition();
    };
    syncTarget();
    const frame = window.requestAnimationFrame(refreshPosition);
    const observer = new MutationObserver(syncTarget);
    observer.observe(document.body, { childList: true, subtree: true });
    window.addEventListener('resize', syncTarget);
    window.addEventListener('scroll', refreshPosition, true);
    return () => {
      window.cancelAnimationFrame(frame);
      observer.disconnect();
      window.removeEventListener('resize', syncTarget);
      window.removeEventListener('scroll', refreshPosition, true);
    };
  }, [ensureTargetInView, refreshPosition]);

  useEffect(() => {
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    return () => {
      if (previousFocusRef.current?.isConnected) previousFocusRef.current.focus({ preventScroll: true });
    };
  }, [requestId]);

  useEffect(() => {
    if (!targetAvailable) return;
    const frame = window.requestAnimationFrame(() => calloutRef.current?.focus({ preventScroll: true }));
    return () => window.cancelAnimationFrame(frame);
  }, [targetAvailable, displayStepIndex, requestId]);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      onDismiss();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onDismiss]);

  if (!position) return null;

  const { rect, callout } = position;
  const canGoBack = displayStepIndex > 0;

  const focusTarget = () => {
    visibleTarget(`[data-tour-target="${step.target}"]`)?.focus({ preventScroll: true });
  };

  const moveToStep = (nextStepIndex: number) => {
    onDisplayStepChange(nextStepIndex);
    setDisplayStepIndex(nextStepIndex);
    setReviewingEarlierStep(nextStepIndex < reachableStepIndex);
  };

  const handlePrimaryProgression = () => {
    if (!progressControl.enabled) return;
    if (displayStepIndex === 0) {
      onReviewSignal();
      if (workflowIndex >= 1) moveToStep(1);
      return;
    }
    if (displayStepIndex === 1) {
      moveToStep(2);
      return;
    }
    if (displayStepIndex === 2) {
      onOpenAssessment();
      if (workflowIndex >= 3) moveToStep(3);
      return;
    }
    onComplete();
  };

  return createPortal(
    <div data-testid="contextual-spotlight-tour" data-tour-step={step.id} className="pointer-events-none fixed inset-0 z-[60] print:hidden" role="presentation">
      <div aria-hidden="true" className="pointer-events-none fixed left-0 right-0 top-0 bg-slate-950/35 backdrop-blur-[1px]" style={{ height: Math.max(0, rect.top) }} />
      <div aria-hidden="true" className="pointer-events-none fixed bottom-0 left-0 right-0 bg-slate-950/35 backdrop-blur-[1px]" style={{ top: Math.min(window.innerHeight, rect.bottom) }} />
      <div aria-hidden="true" className="pointer-events-none fixed left-0 bg-slate-950/35 backdrop-blur-[1px]" style={{ top: Math.max(0, rect.top), bottom: Math.max(0, window.innerHeight - rect.bottom), width: Math.max(0, rect.left) }} />
      <div aria-hidden="true" className="pointer-events-none fixed right-0 bg-slate-950/35 backdrop-blur-[1px]" style={{ top: Math.max(0, rect.top), bottom: Math.max(0, window.innerHeight - rect.bottom), left: Math.min(window.innerWidth, rect.right) }} />
      <div aria-hidden="true" data-testid="spotlight-target-ring" className="pointer-events-none fixed rounded-xl ring-2 ring-accent-primary shadow-[0_0_18px_rgba(0,98,241,0.24)] motion-reduce:transition-none" style={{ left: rect.left, top: rect.top, width: rect.width, height: rect.height }} />

      <div
        ref={calloutRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="false"
        aria-labelledby="guided-tour-step-title"
        aria-describedby="guided-tour-step-position guided-tour-step-copy guided-tour-keyboard-note"
        className="pointer-events-auto fixed z-[70] max-h-[calc(100vh-24px)] overflow-y-auto rounded-xl border border-border-subtle bg-surface p-4 text-text-primary shadow-2xl outline-none focus:ring-2 focus:ring-accent-primary motion-reduce:transition-none"
        style={callout}
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <p id="guided-tour-step-position" className="text-[9px] font-bold uppercase tracking-widest text-accent-primary">Step {displayStepIndex + 1} of {GUIDED_TOUR_STEPS.length}</p>
            <h2 id="guided-tour-step-title" className="mt-1 text-sm font-bold text-text-primary">{step.title}</h2>
          </div>
          <button type="button" onClick={onDismiss} aria-label="Close guided tour" className="rounded-md border border-border-subtle p-1.5 text-text-muted hover:bg-surface-muted hover:text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary"><X aria-hidden="true" size={13} /></button>
        </div>
        <p id="guided-tour-step-copy" className="mt-2 text-xs leading-relaxed text-text-secondary">{step.copy}</p>
        <p id="guided-tour-keyboard-note" className="mt-2 text-[10px] leading-relaxed text-text-muted">The highlighted control remains live and keyboard reachable.</p>
        <button type="button" onClick={focusTarget} className="mt-1.5 inline-flex items-center gap-1 rounded px-1 py-0.5 text-[10px] font-semibold text-text-muted hover:text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary"><Focus aria-hidden="true" size={10} />Focus target</button>

        {progressControl.requirement && (
          <p id="guided-tour-progress-requirement" className="mt-2 rounded-md bg-surface-muted px-2 py-1.5 text-[9px] leading-relaxed text-text-muted">
            {progressControl.requirement}
          </p>
        )}

        <div className="mt-4 grid grid-cols-[auto_1fr_auto] items-center gap-2" data-testid="guided-tour-footer">
          {canGoBack
            ? <button type="button" onClick={() => moveToStep(displayStepIndex - 1)} className="inline-flex items-center gap-1 rounded-lg border border-border-subtle px-2 py-2 text-[9px] font-semibold text-text-secondary focus:outline-none focus:ring-2 focus:ring-accent-primary"><ArrowLeft aria-hidden="true" size={10} />Back</button>
            : <span aria-hidden="true" />}
          <button type="button" onClick={onDismiss} className="justify-self-center rounded-lg px-1.5 py-2 text-[9px] font-semibold text-text-muted hover:text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary">Skip tour</button>
          <button
            type="button"
            onClick={handlePrimaryProgression}
            disabled={!progressControl.enabled}
            aria-describedby={progressControl.requirement ? 'guided-tour-progress-requirement' : undefined}
            className="inline-flex min-w-0 items-center justify-center gap-1 justify-self-end whitespace-nowrap rounded-lg bg-accent-primary px-2.5 py-2 text-[9px] font-bold text-white hover:bg-accent-primary-hover focus:outline-none focus:ring-2 focus:ring-accent-primary focus:ring-offset-2 disabled:cursor-not-allowed disabled:bg-surface-muted disabled:text-text-muted disabled:ring-0"
          >
            {progressControl.label}<ArrowRight aria-hidden="true" size={10} />
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
