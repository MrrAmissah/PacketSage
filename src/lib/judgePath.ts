import type { FlowSummary, PacketEvent, SuspiciousSignal } from '../types';

export type JudgePathDestination = 'signals' | 'capture-overview' | 'report';
export type JudgePathActionId = 'review-recommended-signal' | 'focus-investigation' | 'open-report';
export type GuidedSignalFocusTarget = 'signal-detail' | 'investigation';

export interface GuidedSignalAction {
  signalId: string;
  focusTarget: GuidedSignalFocusTarget;
  requestId: number;
}

export interface JudgePathState {
  evidenceLoaded: boolean;
  recommendedSignalId: string | null;
  selectedSignalId: string | null;
  includedInvestigationSignalIds: readonly string[];
  reportVisitedAfterInclusion: boolean;
}

export interface JudgePathStage {
  id: 'evidence' | 'signal' | 'investigation' | 'report';
  label: string;
  complete: boolean;
}

export interface JudgePathProgress {
  stages: JudgePathStage[];
  completedCount: number;
  nextAction: { id: JudgePathActionId; label: string; destination: JudgePathDestination };
}

export interface JudgePathSession {
  evidenceIdentity: string;
  dismissed: boolean;
  selectedSignalId: string | null;
  reportVisitedAfterInclusion: boolean;
}

export function createJudgePathSession(evidenceIdentity: string): JudgePathSession {
  return { evidenceIdentity, dismissed: false, selectedSignalId: null, reportVisitedAfterInclusion: false };
}

export function shouldShowGuidedJourney(parseMode: string, session: JudgePathSession | null): boolean {
  return parseMode === 'demo' && !!session && !session.dismissed;
}

const GUIDED_INVESTIGATION_CATEGORY = 'Repeated outbound activity';

export function findGuidedInvestigationSignal(
  parseMode: string,
  signals: readonly SuspiciousSignal[],
  flows: readonly FlowSummary[],
  events: readonly PacketEvent[],
): SuspiciousSignal | null {
  if (parseMode !== 'demo') return null;

  const flowIds = new Set(flows.map(flow => flow.id));
  const eventIds = new Set(events.map(event => event.id));
  const candidates = signals.filter(signal =>
    signal.category === GUIDED_INVESTIGATION_CATEGORY
    && Boolean(signal.relatedFlowIds?.length)
    && Boolean(signal.relatedEventIds?.length)
    && signal.relatedFlowIds!.every(id => flowIds.has(id))
    && signal.relatedEventIds!.every(id => eventIds.has(id)),
  );

  return [...candidates].sort((left, right) =>
    (right.relatedFlowIds?.length || 0) - (left.relatedFlowIds?.length || 0)
    || left.id.localeCompare(right.id),
  )[0] || null;
}

export function deriveJudgePathProgress(state: JudgePathState): JudgePathProgress {
  const recommendedSignalSelected = Boolean(state.recommendedSignalId && state.selectedSignalId === state.recommendedSignalId);
  const recommendedInvestigationIncluded = Boolean(
    state.recommendedSignalId && state.includedInvestigationSignalIds.includes(state.recommendedSignalId),
  );
  const reportComplete = recommendedInvestigationIncluded && state.reportVisitedAfterInclusion;
  const stages: JudgePathStage[] = [
    { id: 'evidence', label: 'Evidence loaded', complete: state.evidenceLoaded },
    { id: 'signal', label: 'Review recommended signal', complete: recommendedSignalSelected },
    { id: 'investigation', label: 'Run and include investigation', complete: recommendedInvestigationIncluded },
    { id: 'report', label: 'Build report', complete: reportComplete },
  ];

  let nextAction: JudgePathProgress['nextAction'];
  if (!recommendedSignalSelected) nextAction = { id: 'review-recommended-signal', label: 'Review recommended signal', destination: 'signals' };
  else if (!recommendedInvestigationIncluded) nextAction = { id: 'focus-investigation', label: 'Run and include investigation', destination: 'signals' };
  else nextAction = { id: 'open-report', label: reportComplete ? 'Review report' : 'Build report', destination: 'report' };

  return {
    stages,
    completedCount: stages.filter(stage => stage.complete).length,
    nextAction,
  };
}
