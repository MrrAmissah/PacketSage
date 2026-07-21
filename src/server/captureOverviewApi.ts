import { GoogleGenAI, Type } from '@google/genai';
import { validateCaptureOverviewResponse } from '../lib/captureOverview.js';

const MODELS = ['gemini-2.5-flash', 'gemini-3.5-flash'];
const MAX_REQUEST_CHARS = 180_000;
const MAX_TEXT = 260;
const TIMEOUT_MS = 45_000;

export class CaptureOverviewError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

const redact = (value: string) => value
  .replace(/(authorization:\s*basic\s+)[a-z0-9+/=]+/gi, '$1[redacted]')
  .replace(/\b(password|passwd|pwd|token|secret|api[_-]?key|cookie|session)\s*([=:])\s*[^\s&;,]+/gi, '$1$2[redacted]')
  .replace(/\bbearer\s+[a-z0-9._~+/-]+/gi, 'Bearer [redacted]');
const text = (value: unknown, limit = MAX_TEXT) => redact(String(value ?? '').replace(/\s+/g, ' ').trim()).slice(0, limit);
const list = (value: unknown) => Array.isArray(value) ? value : [];
const portState = (value: unknown) => ['observed', 'unknown', 'not-applicable'].includes(String(value)) ? String(value) : 'unknown';

export function boundedCaptureSummary(body: unknown) {
  if (!body || typeof body !== 'object') throw new CaptureOverviewError(400, 'Capture overview request is malformed.');
  if (JSON.stringify(body).length > MAX_REQUEST_CHARS) throw new CaptureOverviewError(413, 'Capture overview request is too large.');
  const root = body as Record<string, unknown>;
  const captureIdentity = text(root.captureIdentity, 160);
  if (!captureIdentity) throw new CaptureOverviewError(400, 'Capture identity is required.');
  return {
    captureIdentity,
    fileName: text(root.fileName, 120),
    perspective: ['balanced', 'beginner', 'technical', 'triage'].includes(String(root.perspective)) ? root.perspective : 'balanced',
    flows: list(root.flowSummary).slice(0, 15).map(value => {
      const item = (value || {}) as Record<string, unknown>;
      return { source: text(item.sourceIp, 48), sourcePort: Number(item.sourcePort) || 0, sourcePortState: portState(item.sourcePortState), destination: text(item.destinationIp, 48), destinationPort: Number(item.destinationPort) || 0, destinationPortState: portState(item.destinationPortState), protocol: text(item.protocol, 24), packets: Number(item.packetCount) || 0, bytes: Number(item.byteCount) || 0, direction: text(item.direction, 20) };
    }),
    dns: list(root.dnsRecords).slice(0, 20).map(value => { const item = (value || {}) as Record<string, unknown>; return { client: text(item.clientIp, 48), query: text(item.query, 120), type: text(item.queryType, 24), response: text(item.response, 120) }; }),
    http: list(root.httpRecords).slice(0, 10).map(value => { const item = (value || {}) as Record<string, unknown>; return { client: text(item.clientIp, 48), host: text(item.host, 120), method: text(item.method, 16), uri: text(item.uri, 120), status: Number(item.statusCode) || 0 }; }),
    tls: list(root.tlsRecords).slice(0, 10).map(value => { const item = (value || {}) as Record<string, unknown>; return { client: text(item.clientIp, 48), server: text(item.serverIp, 48), sni: text(item.sni, 120), version: text(item.version, 24) }; }),
    signals: list(root.suspiciousSignals).slice(0, 20).map(value => { const item = (value || {}) as Record<string, unknown>; return { title: text(item.title, 140), severity: text(item.severity, 20), observation: text(item.observedEvidence) }; }),
    protocols: list(root.protocolStats).slice(0, 12).map(value => { const item = (value || {}) as Record<string, unknown>; return { protocol: text(item.protocol, 40), percentage: Number(item.percentage) || 0 }; }),
  };
}

export async function requestGeminiCaptureOverview(body: unknown, options: { apiKey?: string; signal?: AbortSignal }) {
  const summary = boundedCaptureSummary(body);
  if (!options.apiKey) throw new CaptureOverviewError(503, 'Capture overview is unavailable. Try again later.');
  const configured = String(process.env.GEMINI_MODEL || '').split(',').map(item => item.trim()).filter(Boolean);
  const models = Array.from(new Set([...configured, ...MODELS]));
  const client = new GoogleGenAI({ apiKey: options.apiKey });
  let lastError: unknown;
  const startedAt = Date.now();
  for (const model of models) {
    const remainingMs = TIMEOUT_MS - (Date.now() - startedAt);
    if (remainingMs <= 0) break;
    const controller = new AbortController();
    const relay = () => controller.abort();
    options.signal?.addEventListener('abort', relay, { once: true });
    const timer = setTimeout(() => controller.abort(), remainingMs);
    try {
      const response = await client.models.generateContent({
        model,
        contents: `Create a whole-capture orientation overview from this bounded summary only:\n${JSON.stringify(summary)}`,
        config: {
          abortSignal: controller.signal,
          systemInstruction: 'You are a defensive network-analysis educator. Provide orientation, traffic-pattern explanation, beginner and technical perspectives, and triage questions. Never claim your output is observed evidence, never invent records, never imply model consensus, and state limitations. This output is contextual and not evidence-linked.',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              executiveSummary: { type: Type.STRING }, whatHappened: { type: Type.STRING }, normalActivity: { type: Type.STRING }, suspiciousActivity: { type: Type.STRING }, analystQuestions: { type: Type.STRING }, recommendedChecks: { type: Type.STRING }, beginnerExplanation: { type: Type.STRING }, technicalExplanation: { type: Type.STRING }, confidence: { type: Type.STRING, enum: ['low', 'medium', 'high'] }, limitations: { type: Type.STRING },
            },
            required: ['executiveSummary', 'whatHappened', 'normalActivity', 'suspiciousActivity', 'analystQuestions', 'recommendedChecks', 'beginnerExplanation', 'technicalExplanation', 'confidence', 'limitations'],
          },
        },
      });
      if (!response.text) throw new Error('empty response');
      return validateCaptureOverviewResponse({ provider: 'Google', model, result: JSON.parse(response.text) });
    } catch (error) {
      lastError = error;
      if (options.signal?.aborted) throw new CaptureOverviewError(499, 'Capture overview request was cancelled.');
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', relay);
    }
  }
  if ((lastError as { name?: string })?.name === 'AbortError') throw new CaptureOverviewError(504, 'Capture overview timed out. Try again.');
  throw new CaptureOverviewError(503, 'Capture overview is temporarily unavailable. Try again.');
}

export function clientSafeCaptureOverviewError(error: unknown) {
  if (error instanceof CaptureOverviewError) return { status: error.status, message: error.message };
  return { status: 500, message: 'Unable to generate the capture overview.' };
}
