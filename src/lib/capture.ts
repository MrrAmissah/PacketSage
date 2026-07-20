import { PCAPNGParser, type Packet } from '@cto.af/pcap-ng-parser';
import type { DnsRecord, PacketEvent, UploadedEvidence } from '../types';
import { finalizeEvidenceIds } from './deterministic';
import { MAX_CAPTURE_BYTES, MAX_CAPTURE_PACKETS } from './limits';
import {
  buildFlowsFromEvents,
  computeProtocolStats,
  runRuleEngine,
  type ParsedResult,
} from './parser';

export class CaptureParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CaptureParseError';
  }
}

interface NetworkPacket {
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  service?: string;
  info: string;
  dns?: Omit<DnsRecord, 'id' | 'timestamp'>;
}

function requireBytes(data: Uint8Array, offset: number, length: number): void {
  if (offset < 0 || length < 0 || offset + length > data.length) {
    throw new CaptureParseError('Capture contains a truncated packet record.');
  }
}

function ipv4(data: Uint8Array, offset: number): string {
  requireBytes(data, offset, 4);
  return `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
}

export function formatIpv6Hextets(hextets: readonly number[]): string {
  if (hextets.length !== 8 || hextets.some(value => !Number.isInteger(value) || value < 0 || value > 0xffff)) {
    throw new CaptureParseError('Capture contains an invalid IPv6 address.');
  }

  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < hextets.length;) {
    if (hextets[start] !== 0) {
      start += 1;
      continue;
    }

    let end = start + 1;
    while (end < hextets.length && hextets[end] === 0) end += 1;
    const length = end - start;
    if (length >= 2 && length > bestLength) {
      bestStart = start;
      bestLength = length;
    }
    start = end;
  }

  const formatted = hextets.map(value => value.toString(16));
  if (bestStart === -1) return formatted.join(':');

  const left = formatted.slice(0, bestStart).join(':');
  const right = formatted.slice(bestStart + bestLength).join(':');
  if (!left && !right) return '::';
  if (!left) return `::${right}`;
  if (!right) return `${left}::`;
  return `${left}::${right}`;
}

function ipv6(data: Uint8Array, offset: number): string {
  requireBytes(data, offset, 16);
  const hextets: number[] = [];
  for (let index = 0; index < 16; index += 2) {
    hextets.push((data[offset + index] << 8) | data[offset + index + 1]);
  }
  return formatIpv6Hextets(hextets);
}

function readU16(data: Uint8Array, offset: number): number {
  requireBytes(data, offset, 2);
  return (data[offset] << 8) | data[offset + 1];
}

function parseDnsName(data: Uint8Array, start: number, dnsStart: number): { name: string; next: number } {
  const labels: string[] = [];
  let offset = start;
  let next = start;
  let jumped = false;
  const visited = new Set<number>();

  for (let count = 0; count < 64; count += 1) {
    requireBytes(data, offset, 1);
    const length = data[offset];
    if (length === 0) {
      if (!jumped) next = offset + 1;
      return { name: labels.join('.'), next };
    }
    if ((length & 0xc0) === 0xc0) {
      requireBytes(data, offset, 2);
      const pointer = dnsStart + (((length & 0x3f) << 8) | data[offset + 1]);
      if (visited.has(pointer)) throw new CaptureParseError('Capture contains a malformed DNS name pointer.');
      visited.add(pointer);
      if (!jumped) next = offset + 2;
      jumped = true;
      offset = pointer;
      continue;
    }
    if (length > 63) throw new CaptureParseError('Capture contains an invalid DNS label.');
    requireBytes(data, offset + 1, length);
    let label = '';
    for (let index = 0; index < length; index += 1) {
      const byte = data[offset + 1 + index];
      label += byte >= 0x21 && byte <= 0x7e ? String.fromCharCode(byte) : '?';
    }
    labels.push(label);
    offset += length + 1;
    if (!jumped) next = offset;
  }
  throw new CaptureParseError('Capture contains an excessively nested DNS name.');
}

function parseDns(data: Uint8Array, offset: number, clientIp: string): NetworkPacket['dns'] | undefined {
  requireBytes(data, offset, 12);
  const flags = readU16(data, offset + 2);
  const questionCount = readU16(data, offset + 4);
  if (questionCount === 0) return undefined;
  const { name, next } = parseDnsName(data, offset + 12, offset);
  requireBytes(data, next, 4);
  const queryTypeCode = readU16(data, next);
  const queryTypes: Record<number, string> = { 1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS' };
  const isResponse = (flags & 0x8000) !== 0;
  return {
    clientIp,
    query: name || '(root)',
    queryType: queryTypes[queryTypeCode] ?? `TYPE${queryTypeCode}`,
    response: isResponse ? 'Response observed (answers not decoded)' : 'Pending',
    rcode: String(flags & 0x000f),
    riskLevel: 'info',
  };
}

function parseTransport(
  data: Uint8Array,
  offset: number,
  nextHeader: number,
  sourceIp: string,
  destinationIp: string,
): NetworkPacket {
  if (nextHeader === 6) {
    requireBytes(data, offset, 20);
    const sourcePort = readU16(data, offset);
    const destinationPort = readU16(data, offset + 2);
    const flags = data[offset + 13];
    const names = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG'].filter((_, bit) => (flags & (1 << bit)) !== 0);
    return { sourceIp, destinationIp, sourcePort, destinationPort, protocol: 'TCP', service: destinationPort === 53 || sourcePort === 53 ? 'DNS' : undefined, info: `TCP${names.length ? ` [${names.join(', ')}]` : ''}` };
  }
  if (nextHeader === 17) {
    requireBytes(data, offset, 8);
    const sourcePort = readU16(data, offset);
    const destinationPort = readU16(data, offset + 2);
    const dnsOffset = offset + 8;
    const isDns = sourcePort === 53 || destinationPort === 53;
    const clientIp = sourcePort === 53 ? destinationIp : sourceIp;
    const dns = isDns ? parseDns(data, dnsOffset, clientIp) : undefined;
    return { sourceIp, destinationIp, sourcePort, destinationPort, protocol: 'UDP', service: dns ? 'DNS' : undefined, info: dns ? `DNS ${dns.queryType} ${dns.query}` : 'UDP datagram', dns };
  }
  if (nextHeader === 1 || nextHeader === 58) {
    requireBytes(data, offset, 4);
    return { sourceIp, destinationIp, sourcePort: 0, destinationPort: 0, protocol: nextHeader === 58 ? 'ICMPv6' : 'ICMP', info: `ICMP type ${data[offset]} code ${data[offset + 1]}` };
  }
  return { sourceIp, destinationIp, sourcePort: 0, destinationPort: 0, protocol: `IP-${nextHeader}`, info: `IP protocol ${nextHeader}` };
}

function dissectPacket(data: Uint8Array, linkType: number): NetworkPacket | null {
  let offset = 0;
  let etherType: number;
  if (linkType === 1) {
    requireBytes(data, 0, 14);
    etherType = readU16(data, 12);
    offset = 14;
    while (etherType === 0x8100 || etherType === 0x88a8) {
      requireBytes(data, offset, 4);
      etherType = readU16(data, offset + 2);
      offset += 4;
    }
  } else if (linkType === 101) {
    requireBytes(data, 0, 1);
    etherType = data[0] >> 4 === 6 ? 0x86dd : 0x0800;
  } else {
    return null;
  }

  if (etherType === 0x0800) {
    requireBytes(data, offset, 20);
    const headerLength = (data[offset] & 0x0f) * 4;
    if ((data[offset] >> 4) !== 4 || headerLength < 20) throw new CaptureParseError('Capture contains an invalid IPv4 header.');
    requireBytes(data, offset, headerLength);
    const fragmentOffset = readU16(data, offset + 6) & 0x1fff;
    const sourceIp = ipv4(data, offset + 12);
    const destinationIp = ipv4(data, offset + 16);
    if (fragmentOffset !== 0) return { sourceIp, destinationIp, sourcePort: 0, destinationPort: 0, protocol: 'IPv4 fragment', info: 'Non-initial IPv4 fragment' };
    return parseTransport(data, offset + headerLength, data[offset + 9], sourceIp, destinationIp);
  }

  if (etherType === 0x86dd) {
    requireBytes(data, offset, 40);
    if ((data[offset] >> 4) !== 6) throw new CaptureParseError('Capture contains an invalid IPv6 header.');
    const sourceIp = ipv6(data, offset + 8);
    const destinationIp = ipv6(data, offset + 24);
    let nextHeader = data[offset + 6];
    let transportOffset = offset + 40;
    for (let count = 0; count < 8 && [0, 43, 44, 60].includes(nextHeader); count += 1) {
      requireBytes(data, transportOffset, 8);
      const current = nextHeader;
      nextHeader = data[transportOffset];
      if (current === 44) {
        const fragmentOffset = readU16(data, transportOffset + 2) >> 3;
        transportOffset += 8;
        if (fragmentOffset !== 0) return { sourceIp, destinationIp, sourcePort: 0, destinationPort: 0, protocol: 'IPv6 fragment', info: 'Non-initial IPv6 fragment' };
      } else {
        transportOffset += (data[transportOffset + 1] + 1) * 8;
      }
    }
    return parseTransport(data, transportOffset, nextHeader, sourceIp, destinationIp);
  }

  return null;
}

export async function parseCapture(fileName: string, buffer: ArrayBuffer): Promise<ParsedResult> {
  if (buffer.byteLength === 0) throw new CaptureParseError('Capture file is empty.');
  if (buffer.byteLength > MAX_CAPTURE_BYTES) {
    throw new CaptureParseError(`Capture exceeds the ${MAX_CAPTURE_BYTES / 1024 / 1024} MB browser-decoding limit.`);
  }

  const parser = new PCAPNGParser();
  const packets: Packet[] = [];
  let parserError: unknown;
  let packetLimitExceeded = false;
  parser.on('data', packet => {
    if (packets.length >= MAX_CAPTURE_PACKETS) {
      packetLimitExceeded = true;
      return;
    }
    packets.push(packet);
  });
  parser.on('error', error => { parserError = error; });

  try {
    const parsingComplete = new Promise<void>(resolve => parser.once('close', () => resolve()));
    const writer = parser.getWriter();
    await writer.write(new Uint8Array(buffer));
    await writer.close();
    await parsingComplete;
  } catch (error) {
    parserError = error;
  }
  if (packetLimitExceeded) throw new CaptureParseError(`Capture exceeds the ${MAX_CAPTURE_PACKETS.toLocaleString()}-packet limit.`);
  if (parserError) throw new CaptureParseError('Capture container is malformed, truncated, or unsupported.');
  if (packets.length === 0) throw new CaptureParseError('Capture contains no supported packet records.');

  const events: PacketEvent[] = [];
  const dns: DnsRecord[] = [];
  packets.forEach((packet, index) => {
    const linkType = parser.interfaces[packet.interfaceId]?.linkType;
    if (linkType === undefined) return;
    const decoded = dissectPacket(packet.data, linkType);
    if (!decoded) return;
    const timestamp = packet.timestamp?.toISOString() ?? '1970-01-01T00:00:00.000Z';
    const capturedLength = packet.data.byteLength;
    const originalLength = packet.originalPacketLength;
    events.push({
      id: `capture-${index + 1}`,
      timestamp,
      sourceIp: decoded.sourceIp,
      sourcePort: decoded.sourcePort,
      destinationIp: decoded.destinationIp,
      destinationPort: decoded.destinationPort,
      protocol: decoded.protocol,
      service: decoded.service,
      length: originalLength,
      capturedLength,
      originalLength,
      info: `${decoded.info}; captured ${capturedLength} bytes, original ${originalLength} bytes`,
      sourceType: parser.ng ? 'pcapng' : 'pcap',
    });
    if (decoded.dns) dns.push({ id: '', timestamp, ...decoded.dns });
  });
  if (events.length === 0) throw new CaptureParseError('Capture link type or network protocols are unsupported.');

  const flows = buildFlowsFromEvents(events);
  const protocolStats = computeProtocolStats(events);
  const signals = runRuleEngine(events, flows, dns, [], []);
  const evidence: UploadedEvidence = {
    id: '',
    name: fileName,
    type: parser.ng ? 'pcapng' : 'pcap',
    size: buffer.byteLength,
    uploadedAt: new Date().toISOString(),
    parseMode: 'pcap',
    sourceFormat: parser.ng ? 'PCAPNG (browser-decoded)' : 'PCAP (browser-decoded)',
    retentionMode: 'Browser memory only',
    status: 'completed',
  };

  return finalizeEvidenceIds({ evidence, events, flows, dns, http: [], tls: [], signals, protocolStats });
}
