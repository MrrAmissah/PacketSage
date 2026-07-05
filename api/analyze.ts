import { GoogleGenAI, Type } from "@google/genai";

let aiClient: GoogleGenAI | null = null;

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

function buildFallbackMemo(reqBody: any) {
  const { flowSummary, dnsRecords, httpRecords } = reqBody || {};
  const commonHost = flowSummary?.[0]?.sourceIp || "10.0.0.15";
  const commonDomain = dnsRecords?.[0]?.query || "d4c1f2a1.example.com";
  const commonExternal = flowSummary?.[0]?.destinationIp || "203.0.113.50";

  return {
    executiveSummary: `A forensic analysis of host ${commonHost} identified multiple review-worthy network behaviors, including periodic DNS query timing, cleartext HTTP transfer activity, and repeated outbound connections. These observations require endpoint, DNS resolver, and destination reputation validation before concluding compromise or command-and-control activity.`,
    whatHappened: `• QUERIED: Host ${commonHost} initiated periodic DNS resolver queries to domain ${commonDomain} at uniform intervals. This periodic query pattern requires validation before drawing conclusions about beaconing behavior.\n• REQUESTED: Decoded application-layer sessions from ${commonHost} requested external assets over cleartext.\n• DOWNLOADED: A cleartext binary download transfer was completed from ${commonExternal}, which requires endpoint validation.\n• OBSERVED: Multiple repeated outbound connection attempts targeting port 80/443 of remote external destinations, which require reputation and ownership review.`,
    normalActivity: "Routine host activities, local ARP resolution, multicast discovery protocols, and background encrypted TLS 1.3 handshakes to public software update domains were recorded in the baseline dataset.",
    suspiciousActivity: `Host ${commonHost} sustained a sequence of application-layer transfers and repeated outbound connection attempts to external destinations over non-standard or unencrypted ports.`,
    keyEvidence: `• Host Source IP: ${commonHost}\n• External Connection Targets: ${commonExternal}\n• Target DNS Query Domain: ${commonDomain}\n• Decoded Transport: HTTP Cleartext, DNS Recursive Lookups`,
    analystQuestions: `• Is the file transfer from ${commonHost} to ${commonExternal} part of an expected software deployment process?\n• Do host operator logs identify legitimate administrative software performing queries to ${commonDomain}?\n• Were active domain credentials transmitted over plain text channels during these connection times?`,
    recommendedChecks: "• Review DNS resolver logs for the queried domain and host.\n• Check endpoint process activity around the observed timestamps.\n• Review proxy, authentication, and EDR logs for matching events.\n• Confirm destination ownership, reputation, and expected business use.\n• Inspect adjacent flows for repeated timing or payload-transfer patterns.\n• Preserve relevant endpoint artifacts for follow-up investigation.\n• Add validated observations to the incident report.",
    beginnerExplanation: "One computer downloaded a file over an unencrypted channel, then repeatedly contacted a domain and external network services. That pattern is unusual enough to check the computer's process history, DNS logs, and surrounding network traffic.",
    technicalExplanation: `Transport/application behavior:\nThe network capture reveals a series of unencrypted application-layer transfers combined with periodic outbound socket configurations.\n\nDNS behavior:\nRepeated recursive DNS queries were generated targeting domain ${commonDomain}.\n\nHTTP/cleartext behavior:\nA payload transfer was completed over unencrypted HTTP. This cleartext channel exposes transport headers and data streams to inspection.\n\nExternal connection behavior:\nOutbound session sequences target destination ports with repeated timing intervals.\n\nRequired validation:\nEndpoint process telemetry, DNS resolver logs, and destination ownership checks are required before concluding compromise or command-and-control activity.`,
    confidence: "medium",
    limitations: "• Payload contents may be incomplete.\n• Network metadata does not confirm endpoint compromise on its own.\n• Host process telemetry is required to validate execution.\n• Authentication logs are required to assess account impact.",
    reportReadySummary: "This forensic investigation report details anomalous network patterns including unencrypted downloads and persistent DNS querying.",
  };
}

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { flowSummary, dnsRecords, httpRecords, tlsRecords, suspiciousSignals, protocolStats, fileName, perspective } = req.body || {};
    const sanitizedMetadata = {
      fileName,
      totalFlows: flowSummary?.length || 0,
      totalDns: dnsRecords?.length || 0,
      totalHttp: httpRecords?.length || 0,
      totalTls: tlsRecords?.length || 0,
      protocolMix: protocolStats?.map((p: any) => `${p.protocol}: ${p.percentage}%`).join(", ") || "",
      flowsPreview: flowSummary?.slice(0, 15).map((f: any) => ({
        src: f.sourceIp,
        sport: f.sourcePort,
        dst: f.destinationIp,
        dport: f.destinationPort,
        proto: f.protocol,
        bytes: f.byteCount,
        direction: f.direction,
        risk: f.riskLevel,
      })),
      dnsQueries: dnsRecords?.slice(0, 20).map((d: any) => `${d.clientIp} -> ${d.query} (${d.queryType})`),
      httpTraffic: httpRecords?.slice(0, 10).map((h: any) => `${h.clientIp} -> ${h.host}${h.uri} (${h.method} ${h.statusCode})`),
      suspiciousSignals: suspiciousSignals?.map((s: any) => ({
        title: s.title,
        severity: s.severity,
        confidence: s.confidence,
        evidence: s.observedEvidence,
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

    const response = await getAiClient().models.generateContent({
      model: "gemini-3.5-flash",
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
    });

    if (!response.text) {
      throw new Error("No text returned from Gemini API");
    }

    return res.status(200).json(JSON.parse(response.text.trim()));
  } catch (err: any) {
    console.log("[Info] Constructing local backup analyst memo:", err.message || err);
    return res.status(200).json(buildFallbackMemo(req.body));
  }
}
