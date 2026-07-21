import type { FlowSummary, PacketEvent, SuspiciousSignal } from '../types';

export type JudgePathDestination = 'signals' | 'capture-overview' | 'report' | 'flows' | 'timeline' | 'import';
export type JudgePathActionId =
  | 'review-recommended-signal'
  | 'review-observed-signals'
  | 'review-decoded-evidence'
  | 'run-investigation'
  | 'review-and-include-assessment'
  | 'open-report';
export type GuidedSignalFocusTarget = 'signal-detail' | 'investigation' | 'assessment-summary' | 'open-assessment';

export interface JudgePathAction {
  id: JudgePathActionId;
  label: string;
  destination: JudgePathDestination;
}

export interface GuidedSignalAction {
  signalId: string;
  focusTarget: GuidedSignalFocusTarget;
  requestId: number;
}

export interface JudgePathState {
  evidenceLoaded: boolean;
  recommendedSignalId: string | null;
  selectedSignalId: string | null;
  completedInvestigationSignalIds?: readonly string[];
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
  nextAction: JudgePathAction;
  status: InvestigationStatus;
}

export type InvestigationStatusTone = 'blue' | 'indigo' | 'amber' | 'green' | 'slate';

export interface InvestigationStatusItem {
  id: 'evidence' | 'signal' | 'assessment' | 'report';
  label: string;
  value: string;
  tone: InvestigationStatusTone;
}

export interface InvestigationStatus {
  mode: 'guided' | 'general';
  items: InvestigationStatusItem[];
  nextAction: JudgePathAction;
}

export interface GeneralInvestigationStatusState {
  evidenceLoaded: boolean;
  signalCount: number;
  hasFlows: boolean;
  hasEvents: boolean;
  selectedSignalId: string | null;
  completedInvestigationSignalIds: readonly string[];
  includedInvestigationSignalIds: readonly string[];
  reportVisitedAfterInclusion: boolean;
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
  const recommendedInvestigationCompleted = recommendedInvestigationIncluded || Boolean(
    state.recommendedSignalId && state.completedInvestigationSignalIds?.includes(state.recommendedSignalId),
  );
  const reportComplete = recommendedInvestigationIncluded && state.reportVisitedAfterInclusion;
  const stages: JudgePathStage[] = [
    { id: 'evidence', label: 'Evidence loaded', complete: state.evidenceLoaded },
    { id: 'signal', label: 'Review recommended signal', complete: recommendedSignalSelected },
    { id: 'investigation', label: 'Investigate and include assessment', complete: recommendedInvestigationIncluded },
    { id: 'report', label: 'Build report', complete: reportComplete },
  ];

  let nextAction: JudgePathProgress['nextAction'];
  if (!recommendedSignalSelected) nextAction = { id: 'review-recommended-signal', label: 'Review recommended signal', destination: 'signals' };
  else if (!recommendedInvestigationCompleted) nextAction = { id: 'run-investigation', label: 'Run evidence-grounded investigation', destination: 'signals' };
  else if (!recommendedInvestigationIncluded) nextAction = { id: 'review-and-include-assessment', label: 'Review and include assessment', destination: 'signals' };
  else nextAction = { id: 'open-report', label: reportComplete ? 'Review report' : 'Build report', destination: 'report' };

  const status: InvestigationStatus = {
    mode: 'guided',
    items: [
      { id: 'evidence', label: 'Evidence decoded', value: state.evidenceLoaded ? 'Complete' : 'Pending', tone: state.evidenceLoaded ? 'blue' : 'slate' },
      { id: 'signal', label: 'Recommended signal review', value: recommendedSignalSelected ? 'Complete' : state.evidenceLoaded ? 'Current' : 'Pending', tone: recommendedSignalSelected ? 'green' : state.evidenceLoaded ? 'amber' : 'slate' },
      { id: 'assessment', label: 'Assessment included', value: recommendedInvestigationIncluded ? 'Complete' : recommendedInvestigationCompleted ? 'Review required' : recommendedSignalSelected ? 'Current' : 'Pending', tone: recommendedInvestigationIncluded ? 'green' : recommendedInvestigationCompleted ? 'amber' : recommendedSignalSelected ? 'indigo' : 'slate' },
      { id: 'report', label: 'Report ready', value: reportComplete ? 'Reviewed' : recommendedInvestigationIncluded ? 'Ready' : 'Not ready', tone: reportComplete || recommendedInvestigationIncluded ? 'green' : 'slate' },
    ],
    nextAction,
  };

  return {
    stages,
    completedCount: stages.filter(stage => stage.complete).length,
    nextAction,
    status,
  };
}

export function deriveGeneralInvestigationStatus(state: GeneralInvestigationStatusState): InvestigationStatus {
  const hasCompletedAssessment = state.completedInvestigationSignalIds.length > 0 || state.includedInvestigationSignalIds.length > 0;
  const hasIncludedAssessment = state.includedInvestigationSignalIds.length > 0;
  const reportReviewed = hasIncludedAssessment && state.reportVisitedAfterInclusion;

  let nextAction: JudgePathAction;
  if (!state.evidenceLoaded) {
    nextAction = { id: 'review-decoded-evidence', label: 'Import supported evidence', destination: 'import' };
  } else if (hasIncludedAssessment) {
    nextAction = { id: 'open-report', label: reportReviewed ? 'Review report' : 'Build report', destination: 'report' };
  } else if (state.signalCount > 0 && !state.selectedSignalId) {
    nextAction = { id: 'review-observed-signals', label: 'Review observed signals', destination: 'signals' };
  } else if (state.selectedSignalId && !state.completedInvestigationSignalIds.includes(state.selectedSignalId)) {
    nextAction = { id: 'run-investigation', label: 'Run evidence-grounded investigation', destination: 'signals' };
  } else if (state.selectedSignalId) {
    nextAction = { id: 'review-and-include-assessment', label: 'Review and include assessment', destination: 'signals' };
  } else {
    nextAction = {
      id: 'review-decoded-evidence',
      label: 'Review decoded evidence',
      destination: state.hasFlows ? 'flows' : state.hasEvents ? 'timeline' : 'import',
    };
  }

  return {
    mode: 'general',
    items: [
      { id: 'evidence', label: 'Evidence decoded', value: state.evidenceLoaded ? 'Complete' : 'Pending', tone: state.evidenceLoaded ? 'blue' : 'slate' },
      { id: 'signal', label: 'Signal review', value: state.signalCount === 0 ? 'Not available' : state.selectedSignalId ? 'Complete' : 'Current', tone: state.signalCount === 0 ? 'slate' : state.selectedSignalId ? 'green' : 'amber' },
      { id: 'assessment', label: 'Assessment included', value: hasIncludedAssessment ? 'Complete' : hasCompletedAssessment ? 'Review required' : state.selectedSignalId ? 'Current' : 'Pending', tone: hasIncludedAssessment ? 'green' : hasCompletedAssessment ? 'amber' : state.selectedSignalId ? 'indigo' : 'slate' },
      { id: 'report', label: 'Report ready', value: reportReviewed ? 'Reviewed' : hasIncludedAssessment ? 'Ready' : 'Not ready', tone: reportReviewed || hasIncludedAssessment ? 'green' : 'slate' },
    ],
    nextAction,
  };
}
