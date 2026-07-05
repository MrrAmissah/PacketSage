import {
  parseCsv,
  parseDemoData,
  parsePcapPlaceholder,
  parseSuricataEve,
  parseTextLog,
  parseTsharkJson,
  parseZeekLog,
} from "../src/lib/parser.ts";

export default function handler(req: any, res: any) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { fileName, fileContent, parseMode, fileSize } = req.body || {};

    if (parseMode === "demo") {
      return res.status(200).json(parseDemoData());
    }

    if (!fileContent) {
      return res.status(400).json({ error: "Missing fileContent payload for non-demo parse mode." });
    }

    switch (parseMode) {
      case "csv":
        return res.status(200).json(parseCsv(fileName, fileContent));
      case "suricata":
        return res.status(200).json(parseSuricataEve(fileName, fileContent));
      case "zeek":
        return res.status(200).json(parseZeekLog(fileName, fileContent));
      case "tshark":
        return res.status(200).json(parseTsharkJson(fileName, fileContent));
      case "txt":
        return res.status(200).json(parseTextLog(fileName, fileContent));
      case "pcap":
        return res.status(200).json(parsePcapPlaceholder(fileName, fileSize || fileContent.length));
      default:
        return res.status(200).json(parseTextLog(fileName, fileContent));
    }
  } catch (err: any) {
    console.error("Parsing failed on serverless function:", err);
    return res.status(500).json({ error: "Parser failed: " + err.message });
  }
}
