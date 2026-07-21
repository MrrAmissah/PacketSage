import type { InvestigationAssessment, InvestigationRecord } from '../types';
import {
  evidenceIds,
  investigationPacketIdentity,
  validateInvestigationApiResult,
  validateInvestigationRequest,
} from './investigation';
import { currentInvestigationRecord } from './investigationRecords';

export interface AssessmentWorkspaceContext {
  selectedEvidenceId: string;
  signalId: string;
  packetIdentity: string;
}

export function assessmentCitationIds(assessment: InvestigationAssessment): string[] {
  return Array.from(new Set([
    ...assessment.observedEvidence.flatMap(item => item.evidenceIds),
    ...assessment.inferences.flatMap(item => item.evidenceIds),
  ]));
}

export function isValidRetainedAssessment(
  record: InvestigationRecord | null | undefined,
  context: AssessmentWorkspaceContext,
): record is InvestigationRecord {
  if (!record
    || record.generationState !== 'completed'
    || record.selectedEvidenceId !== context.selectedEvidenceId
    || record.signalId !== context.signalId
    || record.packetIdentity !== context.packetIdentity
    || record.packet?.signal?.id !== context.signalId
    || typeof record.includedInReport !== 'boolean'
    || !Number.isFinite(new Date(record.createdAt).getTime())) return false;

  try {
    const packet = validateInvestigationRequest({ evidence: record.packet });
    if (investigationPacketIdentity(packet) !== record.packetIdentity) return false;
    const validated = validateInvestigationApiResult({
      schemaVersion: record.schemaVersion,
      provider: record.provider,
      model: record.model,
      assessment: record.assessment,
    }, evidenceIds(packet));
    return JSON.stringify(validated.assessment) === JSON.stringify(record.assessment);
  } catch {
    return false;
  }
}

export function retainedAssessmentForContext(
  records: readonly InvestigationRecord[],
  context: AssessmentWorkspaceContext,
): InvestigationRecord | null {
  const record = currentInvestigationRecord(records, context);
  return isValidRetainedAssessment(record, context) ? record : null;
}
