import type { IncomingMessage, ServerResponse } from 'http';
import { clientSafeCaptureOverviewError, requestGeminiCaptureOverview } from '../src/server/captureOverviewApi.js';

export default async function handler(req: IncomingMessage & { body?: unknown }, res: ServerResponse & { status(code: number): typeof res; json(value: unknown): void }) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed.' });
  const controller = new AbortController();
  const abort = () => controller.abort();
  req.once('aborted', abort);
  try {
    return res.status(200).json(await requestGeminiCaptureOverview(req.body, { apiKey: process.env.GEMINI_API_KEY, signal: controller.signal }));
  } catch (error) {
    if (controller.signal.aborted) return;
    const safe = clientSafeCaptureOverviewError(error);
    return res.status(safe.status).json({ error: safe.message });
  } finally {
    req.removeListener('aborted', abort);
  }
}
