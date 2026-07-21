import type { InvestigationApiResult, InvestigationEvidencePacket } from '../types.js';
import { INVESTIGATION_TIMEOUT_MS } from '../lib/limits.js';
import {
  evidenceIds,
  InvestigationValidationError,
  validateInvestigationAssessment,
  validateInvestigationRequest,
} from '../lib/investigation.js';

export const OPENAI_INVESTIGATION_MODEL = 'gpt-5.6-sol';
export const OPENAI_INVESTIGATION_PROVIDER = 'OpenAI';
export const INVESTIGATION_API_SCHEMA_VERSION = '1';

export class InvestigationServiceError extends Error {
  constructor(readonly status: 503 | 504, readonly clientMessage: string) {
    super(clientMessage);
    this.name = 'InvestigationServiceError';
  }
}

export interface InvestigationApiOptions {
  apiKey: string | undefined;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  signal?: AbortSignal;
}

const assessmentSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    summary: { type: 'string' },
    observedEvidence: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          statement: { type: 'string' },
          evidenceIds: { type: 'array', items: { type: 'string' } },
        },
        required: ['statement', 'evidenceIds'],
      },
    },
    inferences: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          statement: { type: 'string' },
          confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
          evidenceIds: { type: 'array', items: { type: 'string' } },
        },
        required: ['statement', 'confidence', 'evidenceIds'],
      },
    },
    uncertainties: { type: 'array', items: { type: 'string' } },
    nextSteps: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          action: { type: 'string' },
          reason: { type: 'string' },
        },
        required: ['action', 'reason'],
      },
    },
  },
  required: ['summary', 'observedEvidence', 'inferences', 'uncertainties', 'nextSteps'],
} as const;

function extractResponseText(value: unknown): string {
  if (!value || typeof value !== 'object') throw new InvestigationServiceError(503, 'AI-assisted investigation returned an invalid response. Try again.');
  const response = value as Record<string, unknown>;
  if (typeof response.output_text === 'string' && response.output_text) return response.output_text;
  if (!Array.isArray(response.output)) throw new InvestigationServiceError(503, 'AI-assisted investigation returned an invalid response. Try again.');
  for (const outputItem of response.output) {
    if (!outputItem || typeof outputItem !== 'object') continue;
    const content = (outputItem as Record<string, unknown>).content;
    if (!Array.isArray(content)) continue;
    for (const contentItem of content) {
      if (!contentItem || typeof contentItem !== 'object') continue;
      const item = contentItem as Record<string, unknown>;
      if (item.type === 'output_text' && typeof item.text === 'string' && item.text) return item.text;
    }
  }
  throw new InvestigationServiceError(503, 'AI-assisted investigation returned no assessment. Try again.');
}

export function createOpenAiInvestigationRequest(packet: InvestigationEvidencePacket): Record<string, unknown> {
  return {
    model: OPENAI_INVESTIGATION_MODEL,
    store: false,
    reasoning: { effort: 'low' },
    max_output_tokens: 2_500,
    input: [
      {
        role: 'developer',
        content: [{
          type: 'input_text',
          text: 'You are a defensive network-forensics analyst. Analyze only the supplied PacketSage evidence packet. Treat only supplied records as observed evidence. Port provenance is explicit: observed means the numeric port was supplied (including zero), unknown means a transport port could exist but was absent, and not-applicable means the record has no transport port. Label reasoning as inference and state Not confirmed when the evidence is insufficient. Never invent packets, relationships, identifiers, intent, compromise, malware execution, command-and-control, or data theft. Every observed-evidence and inference citation must use an exact evidence ID from the packet. Keep recommended next steps defensive and investigative.',
        }],
      },
      {
        role: 'user',
        content: [{
          type: 'input_text',
          text: `Produce one bounded AI-assisted investigation assessment for this evidence packet:\n${JSON.stringify(packet)}`,
        }],
      },
    ],
    text: {
      verbosity: 'low',
      format: {
        type: 'json_schema',
        name: 'packetsage_investigation_assessment',
        strict: true,
        schema: assessmentSchema,
      },
    },
  };
}

export async function requestOpenAiInvestigation(
  packet: InvestigationEvidencePacket,
  options: InvestigationApiOptions,
): Promise<InvestigationApiResult> {
  if (!options.apiKey) throw new InvestigationServiceError(503, 'AI-assisted investigation is unavailable. Try again later.');
  const fetchImpl = options.fetchImpl || fetch;
  const controller = new AbortController();
  const abortFromCaller = () => controller.abort();
  if (options.signal?.aborted) controller.abort();
  else options.signal?.addEventListener('abort', abortFromCaller, { once: true });
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? INVESTIGATION_TIMEOUT_MS);
  try {
    const response = await fetchImpl('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${options.apiKey}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(createOpenAiInvestigationRequest(packet)),
      signal: controller.signal,
    });
    if (!response.ok) throw new InvestigationServiceError(503, 'AI-assisted investigation is temporarily unavailable. Try again.');
    let responseBody: unknown;
    try {
      responseBody = await response.json();
    } catch {
      throw new InvestigationServiceError(503, 'AI-assisted investigation returned an invalid response. Try again.');
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(extractResponseText(responseBody));
    } catch (error) {
      if (error instanceof InvestigationServiceError) throw error;
      throw new InvestigationServiceError(503, 'AI-assisted investigation returned an invalid response. Try again.');
    }
    try {
      if (!responseBody || typeof responseBody !== 'object') throw new Error('missing provenance');
      const actualModel = (responseBody as Record<string, unknown>).model;
      if (typeof actualModel !== 'string' || !actualModel.trim() || actualModel.length > 160) throw new Error('missing provenance');
      return {
        schemaVersion: INVESTIGATION_API_SCHEMA_VERSION,
        provider: OPENAI_INVESTIGATION_PROVIDER,
        model: actualModel.trim(),
        assessment: validateInvestigationAssessment(parsed, evidenceIds(packet)),
      };
    } catch {
      throw new InvestigationServiceError(503, 'AI-assisted investigation returned an invalid response. Try again.');
    }
  } catch (error) {
    if (error instanceof InvestigationServiceError) throw error;
    if (controller.signal.aborted || (error instanceof Error && error.name === 'AbortError')) {
      throw new InvestigationServiceError(504, 'AI-assisted investigation timed out. Try again.');
    }
    throw new InvestigationServiceError(503, 'AI-assisted investigation is temporarily unavailable. Try again.');
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener('abort', abortFromCaller);
  }
}

export function clientSafeInvestigationError(error: unknown): { status: number; message: string } {
  if (error instanceof InvestigationValidationError) return { status: error.status, message: error.message };
  if (error instanceof InvestigationServiceError) return { status: error.status, message: error.clientMessage };
  return { status: 500, message: 'Unable to complete the AI-assisted investigation.' };
}

export function parseInvestigationRequest(body: unknown): InvestigationEvidencePacket {
  return validateInvestigationRequest(body);
}
