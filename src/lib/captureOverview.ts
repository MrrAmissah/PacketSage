import type { AiAnalysisResult, CaptureOverviewRecord } from '../types.js';

const FIELDS: Array<keyof Omit<AiAnalysisResult, 'confidence'>> = [
  'executiveSummary', 'whatHappened', 'normalActivity', 'suspiciousActivity',
  'analystQuestions', 'recommendedChecks', 'beginnerExplanation',
  'technicalExplanation', 'limitations',
];

export function validateCaptureOverviewResponse(value: unknown): { provider: 'Google'; model: string; result: AiAnalysisResult } {
  if (!value || typeof value !== 'object') throw new Error('Capture overview returned an invalid response.');
  const root = value as Record<string, unknown>;
  if (root.provider !== 'Google' || typeof root.model !== 'string' || !root.model.trim()) {
    throw new Error('Capture overview returned invalid model provenance.');
  }
  if (!root.result || typeof root.result !== 'object') throw new Error('Capture overview returned an invalid response.');
  const result = root.result as Record<string, unknown>;
  const normalized: Partial<AiAnalysisResult> = {};
  for (const field of FIELDS) {
    if (typeof result[field] !== 'string' || !result[field].trim()) throw new Error('Capture overview returned an invalid response.');
    (normalized as Record<string, string>)[field] = result[field].trim().slice(0, 8_000);
  }
  if (!['low', 'medium', 'high'].includes(String(result.confidence))) throw new Error('Capture overview returned an invalid confidence value.');
  normalized.confidence = result.confidence as AiAnalysisResult['confidence'];
  return { provider: 'Google', model: root.model.trim().slice(0, 100), result: normalized as AiAnalysisResult };
}

export function completedCaptureOverview(
  captureIdentity: string,
  response: ReturnType<typeof validateCaptureOverviewResponse>,
): CaptureOverviewRecord {
  return {
    schemaVersion: '1',
    provider: response.provider,
    model: response.model,
    captureIdentity,
    generationState: 'completed',
    createdAt: new Date().toISOString(),
    includedInReport: false,
    result: response.result,
  };
}

export function setCaptureOverviewInclusion(
  record: CaptureOverviewRecord | null,
  captureIdentity: string,
  includedInReport: boolean,
): CaptureOverviewRecord | null {
  if (!record || record.captureIdentity !== captureIdentity || record.generationState !== 'completed') return record;
  return { ...record, includedInReport };
}

export function includedCaptureOverview(
  record: CaptureOverviewRecord | null,
  captureIdentity: string,
): CaptureOverviewRecord | null {
  return record?.captureIdentity === captureIdentity && record.includedInReport ? record : null;
}
