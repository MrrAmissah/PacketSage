export const GUIDED_TOUR_STORAGE_KEY = 'packet-sage-contextual-tour-v1';
export const GUIDED_TOUR_COMPLETION_VALUE = 'completed';

export type GuidedTourStepId = 'signal' | 'investigation' | 'assessment' | 'inclusion';

export interface GuidedTourSession {
  evidenceIdentity: string;
  active: boolean;
  replay: boolean;
  requestId: number;
}

export interface GuidedTourWorkflowState {
  parseMode: string;
  evidenceIdentity: string | null;
  recommendedSignalId: string | null;
  selectedSignalId: string | null;
  completedInvestigationSignalIds: readonly string[];
  includedInvestigationSignalIds: readonly string[];
  assessmentWorkspaceSignalId: string | null;
}

export interface GuidedTourProgressControl {
  label: 'Review signal and continue' | 'Next after assessment' | 'Open assessment and continue' | 'Finish tour';
  enabled: boolean;
  requirement: string | null;
}

export const GUIDED_TOUR_STEPS: ReadonlyArray<{
  id: GuidedTourStepId;
  target: string;
  title: string;
  copy: string;
}> = [
  {
    id: 'signal',
    target: 'recommended-signal-action',
    title: 'Start with a deterministic signal',
    copy: 'PacketSage has linked this signal to exact flows and events. Review the evidence before asking AI to assist.',
  },
  {
    id: 'investigation',
    target: 'investigation-trigger',
    title: 'Investigate referenced evidence',
    copy: 'AI investigation is optional and may use your configured paid API. Only this signal and its exact referenced evidence are submitted if you choose Investigate with AI.',
  },
  {
    id: 'assessment',
    target: 'open-full-assessment',
    title: 'Review the complete assessment',
    copy: 'Open the full workspace to inspect observed evidence, inference, uncertainty, investigative steps and exact citations.',
  },
  {
    id: 'inclusion',
    target: 'assessment-report-inclusion',
    title: 'You control the report',
    copy: 'Nothing enters the report automatically. Review the assessment and citations before explicitly including it.',
  },
] as const;

export function createGuidedTourSession(
  parseMode: string,
  evidenceIdentity: string,
  completionPreference: string | null,
  requestId = 1,
): GuidedTourSession | null {
  if (parseMode !== 'demo') return null;
  return {
    evidenceIdentity,
    active: completionPreference !== GUIDED_TOUR_COMPLETION_VALUE,
    replay: false,
    requestId,
  };
}

export function replayGuidedTourSession(evidenceIdentity: string, requestId: number): GuidedTourSession {
  return { evidenceIdentity, active: true, replay: true, requestId };
}

export function shouldShowGuidedTour(
  session: GuidedTourSession | null,
  parseMode: string,
  evidenceIdentity: string | null,
): boolean {
  return Boolean(
    session?.active
    && parseMode === 'demo'
    && evidenceIdentity
    && session.evidenceIdentity === evidenceIdentity,
  );
}

export function deriveGuidedTourWorkflowIndex(state: GuidedTourWorkflowState): number | null {
  if (state.parseMode !== 'demo' || !state.evidenceIdentity || !state.recommendedSignalId) return null;
  if (state.selectedSignalId !== state.recommendedSignalId) return 0;
  if (!state.completedInvestigationSignalIds.includes(state.recommendedSignalId)) return 1;
  if (state.assessmentWorkspaceSignalId !== state.recommendedSignalId) return 2;
  if (!state.includedInvestigationSignalIds.includes(state.recommendedSignalId)) return 3;
  return 4;
}

export function guidedTourProgressControl(
  displayStepIndex: number,
  workflowIndex: number,
): GuidedTourProgressControl {
  if (displayStepIndex === 0) {
    return { label: 'Review signal and continue', enabled: true, requirement: null };
  }
  if (displayStepIndex === 1) {
    return {
      label: 'Next after assessment',
      enabled: workflowIndex >= 2,
      requirement: workflowIndex >= 2
        ? null
        : 'Run the investigation only when you choose, or finish this tour without AI and return later. Assessment steps unlock only after a valid response.',
    };
  }
  if (displayStepIndex === 2) {
    return { label: 'Open assessment and continue', enabled: workflowIndex >= 2, requirement: null };
  }
  return {
    label: 'Finish tour',
    enabled: workflowIndex >= 4,
    requirement: workflowIndex >= 4
      ? null
      : 'Include the assessment with the highlighted control before finishing the tour.',
  };
}
