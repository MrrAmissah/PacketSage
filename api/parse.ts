const parserBundlePath = "../dist/parser.mjs";
import { clientSafeParseError, validateParsedResult, validateParseRequest } from "../src/lib/parseRequest.js";
import { MAX_REQUEST_BYTES } from "../src/lib/limits.js";

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const contentLength = Number(req.headers?.['content-length'] || 0);
    if (contentLength > MAX_REQUEST_BYTES) {
      return res.status(413).json({ error: 'Request body is too large.' });
    }
    const {
      parseCsv,
      parseDemoData,
      parseSuricataEve,
      parseTextLog,
      parseTsharkJson,
      parseZeekLog,
    } = await import(parserBundlePath);
    const { fileName, fileContent, parseMode } = validateParseRequest(req.body);

    if (parseMode === "demo") {
      return res.status(200).json(validateParsedResult(parseDemoData()));
    }

    let parsed;
    switch (parseMode) {
      case "csv":
        parsed = parseCsv(fileName, fileContent);
        break;
      case "suricata":
        parsed = parseSuricataEve(fileName, fileContent);
        break;
      case "zeek":
        parsed = parseZeekLog(fileName, fileContent);
        break;
      case "tshark":
        parsed = parseTsharkJson(fileName, fileContent);
        break;
      case "txt":
        parsed = parseTextLog(fileName, fileContent);
        break;
    }
    return res.status(200).json(validateParsedResult(parsed));
  } catch (error) {
    const safe = clientSafeParseError(error);
    return res.status(safe.status).json({ error: safe.message });
  }
}
