/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from "express";
import path from "path";
import dotenv from "dotenv";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import {
  parseDemoData,
  parseCsv,
  parseSuricataEve,
  parseZeekLog,
  parseTsharkJson,
  parseTextLog
} from "./src/lib/parser.js";
import { clientSafeParseError, validateParsedResult, validateParseRequest } from "./src/lib/parseRequest.js";
import {
  clientSafeInvestigationError,
  parseInvestigationRequest,
  requestOpenAiInvestigation,
} from "./src/server/investigationApi.js";

// Load environment variables
dotenv.config();

const app = express();
const PORT = 3000;

// Body parser limits increased for packet capture log transfers
app.use(express.json({ limit: "3mb" }));
app.use(express.urlencoded({ limit: "3mb", extended: true }));
app.use((error: any, _req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (error?.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body is too large.' });
  }
  if (error instanceof SyntaxError) {
    return res.status(400).json({ error: 'Request body must contain valid JSON.' });
  }
  return next(error);
});

// Lazily initialize Gemini client to avoid crashes if API key is not set at load time
let aiClient: GoogleGenAI | null = null;

function getAiClient(): GoogleGenAI {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY environment variable is missing. Please set it in Settings > Secrets.");
    }
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return aiClient;
}

// API Route: Health Check
app.get("/api/health", (req, res) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// API Route: Parsing Endpoint
app.post("/api/parse", (req, res) => {
  try {
    const { fileName, fileContent, parseMode } = validateParseRequest(req.body);

    if (parseMode === "demo") {
      return res.json(validateParsedResult(parseDemoData()));
    }

    let parsedResult;

    switch (parseMode) {
      case "csv":
        parsedResult = parseCsv(fileName, fileContent);
        break;
      case "suricata":
        parsedResult = parseSuricataEve(fileName, fileContent);
        break;
      case "zeek":
        parsedResult = parseZeekLog(fileName, fileContent);
        break;
      case "tshark":
        parsedResult = parseTsharkJson(fileName, fileContent);
        break;
      case "txt":
        parsedResult = parseTextLog(fileName, fileContent);
        break;
    }

    return res.json(validateParsedResult(parsedResult));
  } catch (error) {
    const safe = clientSafeParseError(error);
    return res.status(safe.status).json({ error: safe.message });
  }
});

app.post("/api/investigate", async (req, res) => {
  const clientAbort = new AbortController();
  const abortUpstream = () => clientAbort.abort();
  const abortOnDisconnect = () => {
    if (!res.writableEnded) abortUpstream();
  };
  req.once('aborted', abortUpstream);
  res.once('close', abortOnDisconnect);
  try {
    const evidence = parseInvestigationRequest(req.body);
    const assessment = await requestOpenAiInvestigation(evidence, {
      apiKey: process.env.OPENAI_API_KEY,
      signal: clientAbort.signal,
    });
    return res.json(assessment);
  } catch (error) {
    if (clientAbort.signal.aborted || res.destroyed) return;
    const safe = clientSafeInvestigationError(error);
    return res.status(safe.status).json({ error: safe.message });
  } finally {
    req.removeListener('aborted', abortUpstream);
    res.removeListener('close', abortOnDisconnect);
  }
});

// API Route: Gemini Analysis Endpoint
app.post("/api/analyze", async (req, res) => {
  try {
    const { flowSummary, dnsRecords, httpRecords, tlsRecords, suspiciousSignals, protocolStats, fileName, perspective } = req.body;

    // Create a compact, sanitized summary of metadata to send to Gemini
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
        risk: f.riskLevel
      })),
      dnsQueries: dnsRecords?.slice(0, 20).map((d: any) => `${d.clientIp} -> ${d.query} (${d.queryType})`),
      httpTraffic: httpRecords?.slice(0, 10).map((h: any) => `${h.clientIp} -> ${h.host}${h.uri} (${h.method} ${h.statusCode})`),
      suspiciousSignals: suspiciousSignals?.map((s: any) => ({
        title: s.title,
        severity: s.severity,
        confidence: s.confidence,
        evidence: s.observedEvidence
      }))
    };

    const ai = getAiClient();

    let perspectiveInstruction = "";
    if (perspective === "triage") {
      perspectiveInstruction = "Focus heavily on rapid threat containment, identifying key compromise hosts and critical threat actors, mapping immediate containment steps.";
    } else if (perspective === "protocol") {
      perspectiveInstruction = "Focus heavily on network protocol compliance, diving deep into DNS resolution anomalies, unencrypted HTTP paths, and SSL/TLS cipher/JA3 fingerprint anomalies.";
    } else if (perspective === "indicators") {
      perspectiveInstruction = "Focus heavily on correlating deterministic signals, traffic volume ratios, and flow ports to formulate a threat hypothesis.";
    } else {
      perspectiveInstruction = "Provide a balanced, highly thorough, executive-ready forensic investigation overview of all network captures.";
    }

    const systemInstruction = `You are a professional, defensive network-forensics analyst. 
Analyze only the provided evidence summary. Do not invent packets, domains, IP addresses, alerts, or findings.
Separate observed evidence from inference. Maintain a serious, calm, technical tone.
Do not use overclaiming or speculative language. Avoid concluding system compromise, malware execution, breach, active command-and-control (C2), or data theft from network metadata alone. Instead, frame them as review-worthy internal host activities, beacon-like DNS timing patterns, repeated outbound connection attempts, cleartext transfers, possible payload exposure, requiring endpoint validation, DNS resolver log review, and destination ownership/reputation checks.
Provide safe, defensive network actions only. Do not provide exploitation, malware, evasion, credential theft, or unauthorized access guidance.
Be honest about limitations. If traffic appears benign, say so.
Perspective directive: ${perspectiveInstruction}`;

    const prompt = `Perform a forensic investigation report on the following network capture metadata:
${JSON.stringify(sanitizedMetadata, null, 2)}

Provide your output as a highly structured, schema-compliant JSON object containing the specified fields. Translate the evidence into actionable defensive cyber intelligence.`;

    let response = null;
    let lastApiError: any = null;
    const modelsToTry = ["gemini-3.5-flash", "gemini-3.1-flash-lite"];

    for (const modelName of modelsToTry) {
      let attempts = 2;
      for (let attempt = 1; attempt <= attempts; attempt++) {
        try {
          console.log(`[Info] Attempting Gemini analysis using model: ${modelName} (Attempt ${attempt}/${attempts})...`);
          const resObj = await ai.models.generateContent({
            model: modelName,
            contents: prompt,
            config: {
              systemInstruction,
              responseMimeType: "application/json",
              responseSchema: {
                type: Type.OBJECT,
                properties: {
                  executiveSummary: {
                    type: Type.STRING,
                    description: "A concise 2-3 sentence overview of the investigation, summarizing what was analyzed and if critical threats were detected."
                  },
                  whatHappened: {
                    type: Type.STRING,
                    description: "A clear, evidence-based chronological narrative of the suspicious or observed activities. Explain the causal chains."
                  },
                  normalActivity: {
                    type: Type.STRING,
                    description: "A summary of the observed activity that appears to be routine, legitimate, or baseline network noise."
                  },
                  suspiciousActivity: {
                    type: Type.STRING,
                    description: "A detailed breakdown of anomalous behaviors, such as potential port scans, command and control beaconing, or unencrypted binary transfers."
                  },
                  keyEvidence: {
                    type: Type.STRING,
                    description: "A list of specific IP addresses, domain names, timestamps, and protocols that represent concrete evidence for the anomalies."
                  },
                  analystQuestions: {
                    type: Type.STRING,
                    description: "Strategic questions an investigator should ask the operations team or endpoint owner to confirm findings."
                  },
                  recommendedChecks: {
                    type: Type.STRING,
                    description: "Step-by-step defensive, diagnostic investigations to run on the endpoint or active host."
                  },
                  beginnerExplanation: {
                    type: Type.STRING,
                    description: "A simple, highly educational analogy and simple terminology explaining what happened for non-technical learners."
                  },
                  technicalExplanation: {
                    type: Type.STRING,
                    description: "A detailed, technical explanation including protocols, service mappings, and architectural impact for junior SOC analysts."
                  },
                  confidence: {
                    type: Type.STRING,
                    description: "The level of analyst confidence (high, medium, or low) in the threat assessment, justifying why."
                  },
                  limitations: {
                    type: Type.STRING,
                    description: "The specific limitations of the current analysis, emphasizing that we are looking at metadata and not deep packet payloads."
                  },
                  reportReadySummary: {
                    type: Type.STRING,
                    description: "A summary designed for a formal Incident Response Report, suitable for management review."
                  }
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
                  "reportReadySummary"
                ]
              }
            }
          });
          if (resObj && resObj.text) {
            response = resObj;
            break;
          }
        } catch (err: any) {
          lastApiError = err;
          const errMsg = err.message || String(err);
          console.log(`[Info] Gemini attempt with model ${modelName} failed on try ${attempt}: ${errMsg}`);
          if (errMsg.includes("400") || errMsg.includes("invalid") || errMsg.includes("schema")) {
            break;
          }
          if (attempt < attempts) {
            await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
          }
        }
      }
      if (response) {
        break;
      }
    }

    if (!response) {
      throw lastApiError || new Error("All active Gemini model paths exhausted.");
    }

    const text = response.text;
    if (!text) {
      throw new Error("No text returned from Gemini API");
    }

    const jsonResponse = JSON.parse(text.trim());
    return res.json(jsonResponse);
  } catch (err: any) {
    console.log("[Info] Gemini analysis unavailable:", err?.name || "Error");
    return res.status(503).json({ error: 'AI analysis is unavailable. No fallback findings were generated.' });
  }
});

// Mount Vite middleware or static server
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    console.log("Starting server in development mode with Vite middleware...");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    console.log("Starting server in production mode...");
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`PacketSage Server is running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
