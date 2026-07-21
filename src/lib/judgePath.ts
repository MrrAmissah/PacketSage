export type JudgePathDestination = 'signals' | 'capture-overview' | 'report';

export interface JudgePathState {
  evidenceLoaded: boolean;
  signalSelected: boolean;
  investigationIncluded: boolean;
  reportVisited: boolean;
}

export interface JudgePathStage {
  id: 'evidence' | 'signal' | 'investigation' | 'report';
  label: string;
  complete: boolean;
}

export interface JudgePathProgress {
  stages: JudgePathStage[];
  completedCount: number;
  nextAction: { label: string; destination: JudgePathDestination };
}

export interface JudgePathSession {
  evidenceIdentity: string;
  dismissed: boolean;
  signalSelected: boolean;
  reportVisited: boolean;
}

export function createJudgePathSession(evidenceIdentity: string): JudgePathSession {
  return { evidenceIdentity, dismissed: false, signalSelected: false, reportVisited: false };
}

export function shouldShowGuidedJourney(parseMode: string, session: JudgePathSession | null): boolean {
  return parseMode === 'demo' && !!session && !session.dismissed;
}

export function deriveJudgePathProgress(state: JudgePathState): JudgePathProgress {
  const stages: JudgePathStage[] = [
    { id: 'evidence', label: 'Evidence loaded', complete: state.evidenceLoaded },
    { id: 'signal', label: 'Review a signal', complete: state.signalSelected },
    { id: 'investigation', label: 'Run and include an investigation', complete: state.investigationIncluded },
    { id: 'report', label: 'Build the report', complete: state.reportVisited },
  ];

  let nextAction: JudgePathProgress['nextAction'];
  if (!state.signalSelected) nextAction = { label: 'Review signals', destination: 'signals' };
  else if (!state.investigationIncluded) nextAction = { label: 'Continue investigation', destination: 'signals' };
  else nextAction = { label: state.reportVisited ? 'Review report' : 'Build report', destination: 'report' };

  return {
    stages,
    completedCount: stages.filter(stage => stage.complete).length,
    nextAction,
  };
}
