import type { InvestigationAssessment, InvestigationEvidencePacket, InvestigationRecord } from '../types.js';

export function completedInvestigationRecord(input: {
  selectedEvidenceId: string;
  signalId: string;
  packetIdentity: string;
  packet: InvestigationEvidencePacket;
  assessment: InvestigationAssessment;
}): InvestigationRecord {
  return {
    schemaVersion: '1',
    provider: 'OpenAI',
    model: 'gpt-5.6-sol',
    generationState: 'completed',
    createdAt: new Date().toISOString(),
    ...input,
    includedInReport: false,
  };
}

export function upsertInvestigationRecord(
  records: readonly InvestigationRecord[],
  record: InvestigationRecord,
): InvestigationRecord[] {
  return [...records.filter(item => item.signalId !== record.signalId), record];
}

export function removeInvestigationRecord(
  records: readonly InvestigationRecord[],
  signalId: string,
): InvestigationRecord[] {
  return records.filter(record => record.signalId !== signalId);
}

export function setInvestigationReportInclusion(
  records: readonly InvestigationRecord[],
  context: { selectedEvidenceId: string; signalId: string; packetIdentity: string },
  includedInReport: boolean,
): InvestigationRecord[] {
  return records.map(record => (
    record.selectedEvidenceId === context.selectedEvidenceId
    && record.signalId === context.signalId
    && record.packetIdentity === context.packetIdentity
      ? { ...record, includedInReport }
      : record
  ));
}

export function currentInvestigationRecord(
  records: readonly InvestigationRecord[],
  context: { selectedEvidenceId: string; signalId: string; packetIdentity: string },
): InvestigationRecord | null {
  return records.find(record => (
    record.selectedEvidenceId === context.selectedEvidenceId
    && record.signalId === context.signalId
    && record.packetIdentity === context.packetIdentity
  )) || null;
}

export function includedInvestigationRecords(
  records: readonly InvestigationRecord[],
  selectedEvidenceId: string,
): InvestigationRecord[] {
  return records.filter(record => record.selectedEvidenceId === selectedEvidenceId && record.includedInReport);
}

export function clearInvestigationRecords(): InvestigationRecord[] {
  return [];
}
