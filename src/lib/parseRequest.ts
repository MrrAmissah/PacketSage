import type { ParsedResult } from './parser';
import { MAX_FILE_NAME_CHARACTERS, MAX_PARSED_RECORDS, MAX_TEXT_CHARACTERS } from './limits';

export const TEXT_PARSE_MODES = ['csv', 'suricata', 'zeek', 'tshark', 'txt'] as const;
export type TextParseMode = typeof TEXT_PARSE_MODES[number];

export class ParseRequestError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = 'ParseRequestError';
  }
}

export interface ValidatedParseRequest {
  fileName: string;
  fileContent: string;
  parseMode: TextParseMode | 'demo';
}

export function validateParseRequest(body: unknown): ValidatedParseRequest {
  if (!body || typeof body !== 'object') throw new ParseRequestError('Request body must be a JSON object.', 400);
  const value = body as Record<string, unknown>;
  const parseMode = value.parseMode;
  if (parseMode === 'pcap') {
    throw new ParseRequestError('Raw PCAP/PCAPNG captures must be decoded locally in the browser.', 415);
  }
  if (parseMode !== 'demo' && !TEXT_PARSE_MODES.includes(parseMode as TextParseMode)) {
    throw new ParseRequestError('Unsupported parse mode.', 400);
  }

  const fileName = typeof value.fileName === 'string' && value.fileName.trim() ? value.fileName.trim() : 'unnamed-evidence';
  if (fileName.length > MAX_FILE_NAME_CHARACTERS) throw new ParseRequestError('File name is too long.', 400);
  if (parseMode === 'demo') return { fileName, fileContent: '', parseMode };
  if (typeof value.fileContent !== 'string' || value.fileContent.length === 0) {
    throw new ParseRequestError('Missing text evidence content.', 400);
  }
  if (value.fileContent.length > MAX_TEXT_CHARACTERS) {
    throw new ParseRequestError(`Text evidence exceeds the ${MAX_TEXT_CHARACTERS.toLocaleString()} character limit.`, 413);
  }
  if (parseMode !== 'tshark') {
    const nonEmptyRecords = value.fileContent.split(/\r?\n/).reduce((count, line) => count + (line.trim() ? 1 : 0), 0);
    if (nonEmptyRecords > MAX_PARSED_RECORDS) {
      throw new ParseRequestError(`Evidence exceeds the ${MAX_PARSED_RECORDS.toLocaleString()}-record limit.`, 413);
    }
  }
  return { fileName, fileContent: value.fileContent, parseMode: parseMode as TextParseMode };
}

export function validateParsedResult(result: ParsedResult): ParsedResult {
  const collections = [result.events, result.flows, result.dns, result.http, result.tls, result.signals];
  if (collections.some(records => records.length > MAX_PARSED_RECORDS)) {
    throw new ParseRequestError(`Parsed output exceeds the ${MAX_PARSED_RECORDS.toLocaleString()}-record limit.`, 413);
  }
  return result;
}

export function clientSafeParseError(error: unknown): { status: number; message: string } {
  if (error instanceof ParseRequestError) return { status: error.status, message: error.message };
  if (error instanceof Error && error.name === 'EvidenceParseError') return { status: 400, message: error.message };
  return { status: 500, message: 'Unable to parse the supplied evidence.' };
}
