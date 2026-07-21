import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowRight, Focus, X } from 'lucide-react';
import { createPortal } from 'react-dom';
import { GUIDED_TOUR_STEPS } from '../lib/guidedTour';

interface ContextualSpotlightTourProps {
  workflowIndex: number;
  replay: boolean;
  requestId: number;
  onDismiss(): void;
  onComplete(): void;
  onDisplayStepChange(stepIndex: number): void;
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
}: ContextualSpotlightTourProps) {
  const reachableStepIndex = Math.min(workflowIndex, GUIDED_TOUR_STEPS.length - 1);
  const [displayStepIndex, setDisplayStepIndex] = useState(replay ? 0 : reachableStepIndex);
  const [reviewingEarlierStep, setReviewingEarlierStep] = useState(replay && reachableStepIndex > 0);
  const [position, setPosition] = useState<TargetPosition | null>(null);
  const calloutRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const step = GUIDED_TOUR_STEPS[displayStepIndex];
  const targetAvailable = position !== null;

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
  const canGoNext = displayStepIndex < reachableStepIndex;
  const canFinishReplay = replay && displayStepIndex === GUIDED_TOUR_STEPS.length - 1;

  const focusTarget = () => {
    visibleTarget(`[data-tour-target="${step.target}"]`)?.focus({ preventScroll: true });
  };

  const moveToStep = (nextStepIndex: number) => {
    onDisplayStepChange(nextStepIndex);
    setDisplayStepIndex(nextStepIndex);
    setReviewingEarlierStep(nextStepIndex < reachableStepIndex);
  };

  return createPortal(
    <div data-testid="contextual-spotlight-tour" data-tour-step={step.id} className="pointer-events-none fixed inset-0 z-[60] print:hidden" role="presentation">
      <div aria-hidden="true" className="pointer-events-none fixed left-0 right-0 top-0 bg-slate-950/35 backdrop-blur-[1px]" style={{ height: Math.max(0, rect.top - 6) }} />
      <div aria-hidden="true" className="pointer-events-none fixed bottom-0 left-0 right-0 bg-slate-950/35 backdrop-blur-[1px]" style={{ top: Math.min(window.innerHeight, rect.bottom + 6) }} />
      <div aria-hidden="true" className="pointer-events-none fixed left-0 bg-slate-950/35 backdrop-blur-[1px]" style={{ top: Math.max(0, rect.top - 6), bottom: Math.max(0, window.innerHeight - rect.bottom - 6), width: Math.max(0, rect.left - 6) }} />
      <div aria-hidden="true" className="pointer-events-none fixed right-0 bg-slate-950/35 backdrop-blur-[1px]" style={{ top: Math.max(0, rect.top - 6), bottom: Math.max(0, window.innerHeight - rect.bottom - 6), left: Math.min(window.innerWidth, rect.right + 6) }} />
      <div aria-hidden="true" data-testid="spotlight-target-ring" className="pointer-events-none fixed rounded-xl ring-2 ring-accent-primary ring-offset-4 ring-offset-canvas shadow-[0_0_0_1px_rgba(255,255,255,0.5),0_16px_50px_rgba(15,23,42,0.28)] motion-reduce:transition-none" style={{ left: rect.left, top: rect.top, width: rect.width, height: rect.height }} />

      <div
        ref={calloutRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="false"
        aria-labelledby="guided-tour-step-title"
        aria-describedby="guided-tour-step-position guided-tour-step-copy guided-tour-keyboard-note"
        className="pointer-events-auto fixed z-[70] max-h-[calc(100vh-24px)] overflow-y-auto rounded-xl border border-border-subtle bg-surface p-4 text-text-primary shadow-2xl outline-none ring-1 ring-black/5 focus:ring-2 focus:ring-accent-primary motion-reduce:transition-none"
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
        <p id="guided-tour-keyboard-note" className="mt-2 text-[10px] leading-relaxed text-text-muted">The highlighted control remains live and keyboard reachable. This tour never activates it for you.</p>

        <div className="mt-4 flex flex-wrap items-center gap-2">
          {canGoBack && <button type="button" onClick={() => moveToStep(displayStepIndex - 1)} className="inline-flex items-center gap-1 rounded-lg border border-border-subtle px-2.5 py-2 text-[10px] font-semibold text-text-secondary focus:outline-none focus:ring-2 focus:ring-accent-primary"><ArrowLeft aria-hidden="true" size={11} />Back</button>}
          {canGoNext && <button type="button" onClick={() => moveToStep(displayStepIndex + 1)} className="inline-flex items-center gap-1 rounded-lg border border-border-subtle px-2.5 py-2 text-[10px] font-semibold text-text-secondary focus:outline-none focus:ring-2 focus:ring-accent-primary">Next<ArrowRight aria-hidden="true" size={11} /></button>}
          <button type="button" onClick={focusTarget} className="inline-flex items-center gap-1 rounded-lg bg-accent-primary px-2.5 py-2 text-[10px] font-bold text-white hover:bg-accent-primary-hover focus:outline-none focus:ring-2 focus:ring-accent-primary focus:ring-offset-2"><Focus aria-hidden="true" size={11} />Focus highlighted control</button>
          {canFinishReplay ? (
            <button type="button" onClick={onComplete} className="ml-auto rounded-lg px-2.5 py-2 text-[10px] font-semibold text-accent-primary focus:outline-none focus:ring-2 focus:ring-accent-primary">Finish tour</button>
          ) : (
            <button type="button" onClick={onDismiss} className="ml-auto rounded-lg px-2.5 py-2 text-[10px] font-semibold text-text-muted hover:text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary">Skip tour</button>
          )}
        </div>
      </div>
    </div>,
    document.body,
  );
}
