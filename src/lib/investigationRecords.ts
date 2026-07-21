import type { InvestigationApiResult, InvestigationEvidencePacket, InvestigationRecord } from '../types.js';
import { evidenceIds, validateInvestigationApiResult } from './investigation.js';

export function completedInvestigationRecord(input: {
  selectedEvidenceId: string;
  signalId: string;
  packetIdentity: string;
  packet: InvestigationEvidencePacket;
  apiResult: InvestigationApiResult;
}): InvestigationRecord {
  const apiResult = validateInvestigationApiResult(input.apiResult, evidenceIds(input.packet));
  return {
    schemaVersion: apiResult.schemaVersion,
    provider: apiResult.provider,
    model: apiResult.model,
    generationState: 'completed',
    createdAt: new Date().toISOString(),
    selectedEvidenceId: input.selectedEvidenceId,
    signalId: input.signalId,
    packetIdentity: input.packetIdentity,
    packet: input.packet,
    assessment: apiResult.assessment,
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
