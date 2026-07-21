import {
  clientSafeInvestigationError,
  parseInvestigationRequest,
  requestOpenAiInvestigation,
} from "../src/server/investigationApi.js";

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const clientAbort = new AbortController();
  const abortUpstream = () => clientAbort.abort();
  const abortOnDisconnect = () => {
    if (!res.writableEnded) abortUpstream();
  };
  req.once?.("aborted", abortUpstream);
  res.once?.("close", abortOnDisconnect);

  try {
    const evidence = parseInvestigationRequest(req.body);
    const result = await requestOpenAiInvestigation(evidence, {
      apiKey: process.env.OPENAI_API_KEY,
      signal: clientAbort.signal,
    });
    return res.status(200).json(result);
  } catch (error) {
    if (clientAbort.signal.aborted || res.destroyed) return;
    const safe = clientSafeInvestigationError(error);
    return res.status(safe.status).json({ error: safe.message });
  } finally {
    req.removeListener?.("aborted", abortUpstream);
    res.removeListener?.("close", abortOnDisconnect);
  }
}
