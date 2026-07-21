/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from "express";
import path from "path";
import dotenv from "dotenv";
import { createServer as createViteServer } from "vite";
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
import { clientSafeCaptureOverviewError, requestGeminiCaptureOverview } from "./src/server/captureOverviewApi.js";

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
    const result = await requestOpenAiInvestigation(evidence, {
      apiKey: process.env.OPENAI_API_KEY,
      signal: clientAbort.signal,
    });
    return res.json(result);
  } catch (error) {
    if (clientAbort.signal.aborted || res.destroyed) return;
    const safe = clientSafeInvestigationError(error);
    return res.status(safe.status).json({ error: safe.message });
  } finally {
    req.removeListener('aborted', abortUpstream);
    res.removeListener('close', abortOnDisconnect);
  }
});

app.post('/api/analyze', async (req, res) => {
  const controller = new AbortController();
  const abort = () => controller.abort();
  req.once('aborted', abort);
  try {
    return res.json(await requestGeminiCaptureOverview(req.body, { apiKey: process.env.GEMINI_API_KEY, signal: controller.signal }));
  } catch (error) {
    if (controller.signal.aborted || res.destroyed) return;
    const safe = clientSafeCaptureOverviewError(error);
    return res.status(safe.status).json({ error: safe.message });
  } finally {
    req.removeListener('aborted', abort);
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
