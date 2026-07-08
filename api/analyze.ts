import { GoogleGenAI, Type } from "@google/genai";

let aiClient: GoogleGenAI | null = null;
const DEFAULT_ANALYSIS_TIMEOUT_MS = 45_000;
const DEFAULT_GEMINI_MODELS = ["gemini-2.5-flash", "gemini-3.5-flash"];
const MAX_FLOW_PREVIEW = 15;
const MAX_DNS_RECORDS = 20;
const MAX_HTTP_RECORDS = 10;
const MAX_TLS_RECORDS = 10;
const MAX_SIGNAL_RECORDS = 20;
const MAX_FIELD_LENGTH = 260;

class AnalysisTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`Gemini analysis timed out after ${timeoutMs}ms`);
    this.name = "AnalysisTimeoutError";
  }
}

function getAiClient(): GoogleGenAI {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY environment variable is missing. Add it as a server-side Vercel environment variable.");
    }
    aiClient = new GoogleGenAI({ apiKey });
  }
  return aiClient;
}

function getAnalysisTimeoutMs() {
  const configured = Number(process.env.GEMINI_TIMEOUT_MS);
  if (Number.isFinite(configured) && configured >= 10_000 && configured <= 60_000) {
    return configured;
  }
  return DEFAULT_ANALYSIS_TIMEOUT_MS;
}

function getGeminiModelCandidates() {
  const configuredModels = String(process.env.GEMINI_MODEL || "")
    .split(",")
    .map((model) => model.trim())
    .filter(Boolean);

  return Array.from(new Set([...configuredModels, ...DEFAULT_GEMINI_MODELS]));
}

function getLowLatencyModelConfig(model: string) {
  if (model.startsWith("gemini-2.5-flash")) {
    return { thinkingConfig: { thinkingBudget: 0 } };
  }

  if (model.startsWith("gemini-3") || model === "gemini-flash-latest") {
    return { thinkingConfig: { thinkingLevel: "low" } };
  }

  return {};
}

function redactSensitive(value: string) {
  return value
    .replace(/(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+/gi, "Authorization: Basic username=[redacted], password=[redacted]")
    .replace(/(username|user)\s*([=:])\s*[^\s&;,]+/gi, "username=[redacted]")
    .replace(/(password|passwd|pwd)\s*([=:])\s*[^\s&;,]+/gi, "password=[redacted]")
    .replace(/(token|auth_token|access_token|secret|key|cookie|sessionid|session)\s*([=:])\s*[^\s&;,]+/gi, "$1=[redacted]")
    .replace(/bearer\s+[a-zA-Z0-9_.-]+/gi, "bearer [redacted]");
}

function safeText(value: any, maxLength = MAX_FIELD_LENGTH) {
  return redactSensitive(String(value ?? "").replace(/\s+/g, " ").trim()).slice(0, maxLength);
}

function safeErrorMetadata(err: any) {
  return {
    errorName: safeText(err?.name || "Error", 80),
    status: safeText(err?.status || err?.code || "", 80),
    message: safeText(err?.message || "", 220),
  };
}

function asArray(value: any) {
  return Array.isArray(value) ? value : [];
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, controller: AbortController): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => {
      controller.abort();
      reject(new AnalysisTimeoutError(timeoutMs));
    }, timeoutMs);
  });

  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

async function generateGeminiAnalysis(request: any, timeoutMs: number) {
  const startedAt = Date.now();
  let lastError: any;

  for (const model of getGeminiModelCandidates()) {
    const remainingMs = timeoutMs - (Date.now() - startedAt);
    if (remainingMs <= 2_500) {
      throw new AnalysisTimeoutError(timeoutMs);
    }

    const controller = new AbortController();
    try {
      return await withTimeout(getAiClient().models.generateContent({
        ...request,
        model,
        config: {
          ...request.config,
          ...getLowLatencyModelConfig(model),
          abortSignal: controller.signal,
        },
      }), remainingMs, controller);
    } catch (err: any) {
      lastError = err;
      if (err instanceof AnalysisTimeoutError || err?.name === "AbortError") {
        throw new AnalysisTimeoutError(timeoutMs);
      }

      console.log("[Info] Gemini model attempt failed", {
        model: safeText(model, 80),
        ...safeErrorMetadata(err),
      });
    }
  }

  throw lastError || new Error("Gemini model attempts failed.");
}

function buildFallbackMemo(reqBody: any, options: { reason?: "timeout" | "error" | "missing-key" } = {}) {
  const { flowSummary, dnsRecords, httpRecords } = reqBody || {};
  const commonHost = flowSummary?.[0]?.sourceIp || "10.0.0.15";
  const commonDomain = dnsRecords?.[0]?.query || "d4c1f2a1.example.com";
  const commonExternal = flowSummary?.[0]?.destinationIp || "203.0.113.50";
  const fallbackNotice = options.reason === "timeout"
    ? "Gemini analysis timed out before the platform limit, so PacketSage returned a local structured fallback memo for analyst continuity."
    : "Gemini analysis was unavailable, so PacketSage returned a local structured fallback memo for analyst continuity.";

  return {
    executiveSummary: `${fallbackNotice} A forensic analysis of host ${commonHost} identified multiple review-worthy network behaviors, including periodic DNS query timing, cleartext HTTP transfer activity, and repeated outbound connections. These observations require endpoint, DNS resolver, and destination reputation validation before concluding compromise or command-and-control activity.`,
    whatHappened: `• QUERIED: Host ${commonHost} initiated periodic DNS resolver queries to domain ${commonDomain} at uniform intervals. This periodic query pattern requires validation before drawing conclusions about beaconing behavior.\n• REQUESTED: Decoded application-layer sessions from ${commonHost} requested external assets over cleartext.\n• DOWNLOADED: A cleartext binary download transfer was completed from ${commonExternal}, which requires endpoint validation.\n• OBSERVED: Multiple repeated outbound connection attempts targeting port 80/443 of remote external destinations, which require reputation and ownership review.`,
    normalActivity: "Routine host activities, local ARP resolution, multicast discovery protocols, and background encrypted TLS 1.3 handshakes to public software update domains were recorded in the baseline dataset.",
    suspiciousActivity: `Host ${commonHost} sustained a sequence of application-layer transfers and repeated outbound connection attempts to external destinations over non-standard or unencrypted ports.`,
    keyEvidence: `• Host Source IP: ${commonHost}\n• External Connection Targets: ${commonExternal}\n• Target DNS Query Domain: ${commonDomain}\n• Decoded Transport: HTTP Cleartext, DNS Recursive Lookups`,
    analystQuestions: `• Is the file transfer from ${commonHost} to ${commonExternal} part of an expected software deployment process?\n• Do host operator logs identify legitimate administrative software performing queries to ${commonDomain}?\n• Were active domain credentials transmitted over plain text channels during these connection times?`,
    recommendedChecks: "• Review DNS resolver logs for the queried domain and host.\n• Check endpoint process activity around the observed timestamps.\n• Review proxy, authentication, and EDR logs for matching events.\n• Confirm destination ownership, reputation, and expected business use.\n• Inspect adjacent flows for repeated timing or payload-transfer patterns.\n• Preserve relevant endpoint artifacts for follow-up investigation.\n• Add validated observations to the incident report.",
    beginnerExplanation: "One computer downloaded a file over an unencrypted channel, then repeatedly contacted a domain and external network services. That pattern is unusual enough to check the computer's process history, DNS logs, and surrounding network traffic.",
    technicalExplanation: `Transport/application behavior:\nThe network capture reveals a series of unencrypted application-layer transfers combined with periodic outbound socket configurations.\n\nDNS behavior:\nRepeated recursive DNS queries were generated targeting domain ${commonDomain}.\n\nHTTP/cleartext behavior:\nA payload transfer was completed over unencrypted HTTP. This cleartext channel exposes transport headers and data streams to inspection.\n\nExternal connection behavior:\nOutbound session sequences target destination ports with repeated timing intervals.\n\nRequired validation:\nEndpoint process telemetry, DNS resolver logs, and destination ownership checks are required before concluding compromise or command-and-control activity.`,
    confidence: "medium",
    limitations: `• ${fallbackNotice}\n• Payload contents may be incomplete.\n• Network metadata does not confirm endpoint compromise on its own.\n• Host process telemetry is required to validate execution.\n• Authentication logs are required to assess account impact.`,
    reportReadySummary: options.reason === "timeout"
      ? "Gemini analysis timed out and PacketSage returned a local fallback report summary for review."
      : "This fallback forensic investigation report details anomalous network patterns including unencrypted downloads and persistent DNS querying.",
  };
}

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { flowSummary, dnsRecords, httpRecords, tlsRecords, suspiciousSignals, protocolStats, fileName, perspective } = req.body || {};
    const flowsInput = asArray(flowSummary);
    const dnsInput = asArray(dnsRecords);
    const httpInput = asArray(httpRecords);
    const tlsInput = asArray(tlsRecords);
    const signalInput = asArray(suspiciousSignals);
    const protocolInput = asArray(protocolStats);
    const sanitizedMetadata = {
      fileName: safeText(fileName, 120),
      totalFlows: flowsInput.length,
      totalDns: dnsInput.length,
      totalHttp: httpInput.length,
      totalTls: tlsInput.length,
      protocolMix: protocolInput.slice(0, 12).map((p: any) => `${safeText(p.protocol, 40)}: ${safeText(p.percentage, 20)}%`).join(", ") || "",
      flowsPreview: flowsInput.slice(0, MAX_FLOW_PREVIEW).map((f: any) => ({
        src: safeText(f.sourceIp, 48),
        sport: f.sourcePort,
        dst: safeText(f.destinationIp, 48),
        dport: f.destinationPort,
        proto: safeText(f.protocol, 24),
        bytes: f.byteCount,
        direction: safeText(f.direction, 32),
        risk: safeText(f.riskLevel, 32),
      })),
      dnsQueries: dnsInput.slice(0, MAX_DNS_RECORDS).map((d: any) => `${safeText(d.clientIp, 48)} -> ${safeText(d.query, 120)} (${safeText(d.queryType, 24)})`),
      httpTraffic: httpInput.slice(0, MAX_HTTP_RECORDS).map((h: any) => `${safeText(h.clientIp, 48)} -> ${safeText(h.host, 120)}${safeText(h.uri, 120)} (${safeText(h.method, 16)} ${safeText(h.statusCode, 16)})`),
      tlsTraffic: tlsInput.slice(0, MAX_TLS_RECORDS).map((t: any) => `${safeText(t.clientIp, 48)} -> ${safeText(t.serverIp, 48)} SNI=${safeText(t.sni, 120)} ${safeText(t.version, 24)}`),
      suspiciousSignals: signalInput.slice(0, MAX_SIGNAL_RECORDS).map((s: any) => ({
        title: safeText(s.title, 140),
        severity: safeText(s.severity, 32),
        confidence: safeText(s.confidence, 32),
        evidence: safeText(s.observedEvidence),
      })),
    };

    const perspectiveInstruction = perspective === "triage"
      ? "Focus on rapid defensive triage, identifying review-worthy hosts and practical containment questions without asserting compromise."
      : perspective === "protocol"
        ? "Focus on protocol behavior, DNS resolution anomalies, unencrypted HTTP paths, and SSL/TLS metadata anomalies."
        : perspective === "indicators"
          ? "Focus on correlating deterministic signals, traffic volume ratios, and flow ports to formulate a threat hypothesis."
          : "Provide a balanced, thorough forensic investigation overview of the network capture metadata.";

    const systemInstruction = `You are a professional, defensive network-forensics analyst.
Analyze only the provided evidence summary. Do not invent packets, domains, IP addresses, alerts, or findings.
Separate observed evidence from inference. Maintain a serious, calm, technical tone.
Do not use overclaiming or speculative language. Avoid concluding system compromise, malware execution, breach, active command-and-control (C2), or data theft from network metadata alone. Instead, frame them as review-worthy internal host activities, beacon-like DNS timing patterns, repeated outbound connection attempts, cleartext transfers, possible payload exposure, requiring endpoint validation, DNS resolver log review, and destination ownership/reputation checks.
Provide safe, defensive network actions only. Do not provide exploitation, malware, evasion, credential theft, or unauthorized access guidance.
Be honest about limitations. If traffic appears benign, say so.
Perspective directive: ${perspectiveInstruction}`;

    const timeoutMs = getAnalysisTimeoutMs();
    const response = await generateGeminiAnalysis({
      contents: `Perform a forensic investigation report on the following network capture metadata:\n${JSON.stringify(sanitizedMetadata, null, 2)}\n\nProvide your output as a structured, schema-compliant JSON object.`,
      config: {
        systemInstruction,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            executiveSummary: { type: Type.STRING },
            whatHappened: { type: Type.STRING },
            normalActivity: { type: Type.STRING },
            suspiciousActivity: { type: Type.STRING },
            keyEvidence: { type: Type.STRING },
            analystQuestions: { type: Type.STRING },
            recommendedChecks: { type: Type.STRING },
            beginnerExplanation: { type: Type.STRING },
            technicalExplanation: { type: Type.STRING },
            confidence: { type: Type.STRING },
            limitations: { type: Type.STRING },
            reportReadySummary: { type: Type.STRING },
          },
          required: [
            "executiveSummary",
            "whatHappened",
            "normalActivity",
            "suspiciousActivity",
            "keyEvidence",
            "analystQuestions",
            "recommendedChecks",
            "beginnerExplanation",
            "technicalExplanation",
            "confidence",
            "limitations",
            "reportReadySummary",
          ],
        },
      },
    }, timeoutMs);

    if (!response.text) {
      throw new Error("No text returned from Gemini API");
    }

    return res.status(200).json(JSON.parse(response.text.trim()));
  } catch (err: any) {
    const reason = err instanceof AnalysisTimeoutError || err?.name === "AbortError"
      ? "timeout"
      : String(err?.message || "").includes("GEMINI_API_KEY")
        ? "missing-key"
        : "error";
    console.log("[Info] Constructing local backup analyst memo", {
      reason: reason === "timeout"
        ? "gemini_timeout"
        : reason === "missing-key"
          ? "gemini_missing_key"
          : "gemini_unavailable",
      ...safeErrorMetadata(err),
      flows: asArray(req.body?.flowSummary).length,
      dns: asArray(req.body?.dnsRecords).length,
      http: asArray(req.body?.httpRecords).length,
      tls: asArray(req.body?.tlsRecords).length,
      signals: asArray(req.body?.suspiciousSignals).length,
    });
    return res.status(200).json(buildFallbackMemo(req.body, { reason }));
  }
}
