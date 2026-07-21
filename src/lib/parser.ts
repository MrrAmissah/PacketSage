/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import type {
  UploadedEvidence,
  PacketEvent,
  FlowSummary,
  ProtocolStat,
  DnsRecord,
  HttpRecord,
  TlsRecord,
  SuspiciousSignal,
  PortState,
} from '../types';
import { deterministicId, finalizeEvidenceIds } from './deterministic';
import { MAX_PARSED_RECORDS } from './limits';
import { formatEndpoint, isPortlessProtocol, portFlowKey, portStateFor } from './ports';

const FALLBACK_TIMESTAMP = '1970-01-01T00:00:00.000Z';

export class EvidenceParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EvidenceParseError';
  }
}

interface NormalizedPort {
  port: number;
  state: PortState;
}

function suppliedPort(protocol: string, raw: unknown): NormalizedPort {
  if (isPortlessProtocol(protocol)) return { port: 0, state: 'not-applicable' };
  const supplied = raw !== undefined && raw !== null && String(raw).trim() !== '' && String(raw).trim() !== '-';
  if (!supplied) return { port: 0, state: 'unknown' };
  const text = String(raw).trim();
  const port = Number(text);
  if (!/^\d+$/.test(text) || !Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new EvidenceParseError('Imported evidence contains an invalid explicit transport port.');
  }
  return { port, state: 'observed' };
}

function firstPresent(record: Record<string, string>, keys: readonly string[]): string | undefined {
  const key = keys.find(candidate => Object.prototype.hasOwnProperty.call(record, candidate));
  return key === undefined ? undefined : record[key];
}

// Helper: Determine Direction
function getDirection(srcIp: string, dstIp: string): 'inbound' | 'outbound' | 'internal' {
  const isPrivate = (ip: string) => {
    return (
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      ip.startsWith('172.16.') ||
      ip.startsWith('172.17.') ||
      ip.startsWith('172.18.') ||
      ip.startsWith('172.19.') ||
      ip.startsWith('172.20.') ||
      ip.startsWith('172.21.') ||
      ip.startsWith('172.22.') ||
      ip.startsWith('172.23.') ||
      ip.startsWith('172.24.') ||
      ip.startsWith('172.25.') ||
      ip.startsWith('172.26.') ||
      ip.startsWith('172.27.') ||
      ip.startsWith('172.28.') ||
      ip.startsWith('172.29.') ||
      ip.startsWith('172.30.') ||
      ip.startsWith('172.31.') ||
      ip === '127.0.0.1' ||
      ip === '::1'
    );
  };

  const srcPriv = isPrivate(srcIp);
  const dstPriv = isPrivate(dstIp);

  if (srcPriv && dstPriv) return 'internal';
  if (srcPriv && !dstPriv) return 'outbound';
  return 'inbound';
}

export interface ParsedResult {
  evidence: UploadedEvidence;
  events: PacketEvent[];
  flows: FlowSummary[];
  dns: DnsRecord[];
  http: HttpRecord[];
  tls: TlsRecord[];
  signals: SuspiciousSignal[];
  protocolStats: ProtocolStat[];
}

// --- Adapters ---

// 1. DemoDataAdapter
export function parseDemoData(): ParsedResult {
  const baseTime = new Date('2024-05-21T10:00:00Z');
  
  const eventRecords: Array<Omit<PacketEvent, 'sourcePortState' | 'destinationPortState'>> = [
    // DNS Queries
    {
      id: 'evt-1',
      timestamp: new Date(baseTime.getTime()).toISOString(),
      sourceIp: '10.0.0.15',
      sourcePort: 51234,
      destinationIp: '10.0.0.1',
      destinationPort: 53,
      protocol: 'UDP',
      service: 'DNS',
      length: 74,
      info: 'Standard query 0x12a3 A portal.example'
    },
    {
      id: 'evt-2',
      timestamp: new Date(baseTime.getTime() + 100).toISOString(),
      sourceIp: '10.0.0.1',
      sourcePort: 53,
      destinationIp: '10.0.0.15',
      destinationPort: 51234,
      protocol: 'UDP',
      service: 'DNS',
      length: 120,
      info: 'Standard query response 0x12a3 A portal.example A 203.0.113.15'
    },
    // SSL Connection to portal
    {
      id: 'evt-3',
      timestamp: new Date(baseTime.getTime() + 1000).toISOString(),
      sourceIp: '10.0.0.15',
      sourcePort: 49152,
      destinationIp: '203.0.113.15',
      destinationPort: 443,
      protocol: 'TCP',
      service: 'HTTPS',
      length: 74,
      info: '[SYN] Seq=0 Win=64240 Len=0'
    },
    {
      id: 'evt-4',
      timestamp: new Date(baseTime.getTime() + 1015).toISOString(),
      sourceIp: '203.0.113.15',
      sourcePort: 443,
      destinationIp: '10.0.0.15',
      destinationPort: 49152,
      protocol: 'TCP',
      service: 'HTTPS',
      length: 74,
      info: '[SYN, ACK] Seq=0 Ack=1 Win=64240 Len=0'
    },
    {
      id: 'evt-5',
      timestamp: new Date(baseTime.getTime() + 1016).toISOString(),
      sourceIp: '10.0.0.15',
      sourcePort: 49152,
      destinationIp: '203.0.113.15',
      destinationPort: 443,
      protocol: 'TCP',
      service: 'HTTPS',
      length: 66,
      info: '[ACK] Seq=1 Ack=1 Win=64240 Len=0'
    },
    {
      id: 'evt-6',
      timestamp: new Date(baseTime.getTime() + 1200).toISOString(),
      sourceIp: '10.0.0.15',
      sourcePort: 49152,
      destinationIp: '203.0.113.15',
      destinationPort: 443,
      protocol: 'TLSv1.3',
      service: 'HTTPS',
      length: 512,
      info: 'Client Hello, SNI: portal.example'
    },
    // Cleartext HTTP (Suspicious cleartext binary download)
    {
      id: 'evt-7',
      timestamp: new Date(baseTime.getTime() + 5000).toISOString(),
      sourceIp: '10.0.0.15',
      sourcePort: 49155,
      destinationIp: '203.0.113.50',
      destinationPort: 80,
      protocol: 'HTTP',
      service: 'HTTP',
      length: 350,
      info: 'GET /assets/patch.bin HTTP/1.1 (Host: updates.example)'
    },
    {
      id: 'evt-8',
      timestamp: new Date(baseTime.getTime() + 5120).toISOString(),
      sourceIp: '203.0.113.50',
      sourcePort: 80,
      destinationIp: '10.0.0.15',
      destinationPort: 49155,
      protocol: 'HTTP',
      service: 'HTTP',
      length: 1514,
      info: 'HTTP/1.1 200 OK (application/octet-stream)'
    },
    // Beaconing Domain Lookups (Suspicious Domain)
    ...Array.from({ length: 18 }).map((_, index) => ({
      id: `evt-beacon-dns-${index}`,
      timestamp: new Date(baseTime.getTime() + 10000 + index * 15000).toISOString(), // queried every 15 seconds
      sourceIp: '10.0.0.15',
      sourcePort: 52000 + index,
      destinationIp: '10.0.0.1',
      destinationPort: 53,
      protocol: 'UDP',
      service: 'DNS',
      length: 82,
      info: `Standard query 0x${(1000 + index).toString(16)} A suspicious-lab.test`
    })),
    // Repeated outbound connections on a review-worthy destination port
    ...Array.from({ length: 10 }).map((_, index) => ({
      id: `evt-beacon-conn-${index}`,
      timestamp: new Date(baseTime.getTime() + 12000 + index * 15000).toISOString(),
      sourceIp: '10.0.0.15',
      sourcePort: 53000 + index,
      destinationIp: '203.0.113.80',
      destinationPort: 4444,
      protocol: 'TCP',
      service: 'Unknown',
      length: 74,
      info: `Outbound connection sequence [SYN] (Beacon-like timing pattern #${index + 1})`
    })),
    // High Traffic volume spikes
    {
      id: 'evt-heavy-1',
      timestamp: new Date(baseTime.getTime() + 60000).toISOString(),
      sourceIp: '10.0.0.15',
      sourcePort: 49200,
      destinationIp: '203.0.113.150',
      destinationPort: 443,
      protocol: 'TLSv1.3',
      service: 'HTTPS',
      length: 1450,
      info: 'Client Key Exchange, SNI: backup.example'
    },
    {
      id: 'evt-heavy-2',
      timestamp: new Date(baseTime.getTime() + 61000).toISOString(),
      sourceIp: '10.0.0.15',
      sourcePort: 49200,
      destinationIp: '203.0.113.150',
      destinationPort: 443,
      protocol: 'TCP',
      service: 'HTTPS',
      length: 1514,
      info: 'Segment 1 of massive outbound transmission (14,500,000 bytes overall)'
    },
    // Network Noise Retransmissions
    {
      id: 'evt-noise-1',
      timestamp: new Date(baseTime.getTime() + 1500).toISOString(),
      sourceIp: '10.0.0.15',
      sourcePort: 49152,
      destinationIp: '203.0.113.15',
      destinationPort: 443,
      protocol: 'TCP',
      service: 'HTTPS',
      length: 74,
      info: '[TCP Retransmission] Client Hello'
    },
    // Generated alert-like metadata for a repeated timing pattern
    {
      id: 'evt-alert-1',
      timestamp: new Date(baseTime.getTime() + 12000).toISOString(),
      sourceIp: '203.0.113.80',
      sourcePort: 4444,
      destinationIp: '10.0.0.15',
      destinationPort: 53000,
      protocol: 'TCP',
      service: 'Suricata Alert',
      length: 0,
      info: 'Generated alert metadata: repeated outbound timing pattern requiring validation'
    }
  ];

  const events: PacketEvent[] = eventRecords.map(event => ({
    ...event,
    sourcePortState: 'observed',
    destinationPortState: 'observed',
  }));
  events.sort((left, right) => left.timestamp.localeCompare(right.timestamp));

  const dns: DnsRecord[] = [
    {
      relatedEventIds: ['evt-1', 'evt-2'],
      timestamp: baseTime.toISOString(),
      clientIp: '10.0.0.15',
      query: 'portal.example',
      queryType: 'A',
      response: '203.0.113.15',
      rcode: 'NOERROR',
      riskLevel: 'info',
      notes: 'Standard lookup'
    },
    ...Array.from({ length: 18 }).map((_, index) => ({
      relatedEventIds: [`evt-beacon-dns-${index}`],
      timestamp: new Date(baseTime.getTime() + 10000 + index * 15000).toISOString(),
      clientIp: '10.0.0.15',
      query: 'suspicious-lab.test',
      queryType: 'A',
      response: '203.0.113.80',
      rcode: 'NOERROR',
      riskLevel: 'high' as const,
      notes: 'Repeated query volume requiring validation against expected resolver and application activity.'
    }))
  ];

  const http: HttpRecord[] = [
    {
      relatedEventIds: ['evt-7', 'evt-8'],
      timestamp: new Date(baseTime.getTime() + 5000).toISOString(),
      clientIp: '10.0.0.15',
      host: 'updates.example',
      method: 'GET',
      uri: '/assets/patch.bin',
      statusCode: 200,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) curl/7.83.1',
      cleartext: true,
      riskLevel: 'medium',
      notes: 'Cleartext download of binary file (.bin) from unusual update host. Highly susceptible to MitM interception.'
    }
  ];

  const tls: TlsRecord[] = [
    {
      relatedEventIds: ['evt-6'],
      timestamp: new Date(baseTime.getTime() + 1200).toISOString(),
      clientIp: '10.0.0.15',
      serverIp: '203.0.113.15',
      sni: 'portal.example',
      version: 'TLSv1.3',
      ja3: '771,4865-4866-4867,0-23-65281-10-11-16-18-51-43-45-21',
      certificateSubject: 'CN=portal.example, O=Fictional Corp, C=US',
      riskLevel: 'info',
      notes: 'Secure TLS session.'
    },
    {
      relatedEventIds: ['evt-heavy-1'],
      timestamp: new Date(baseTime.getTime() + 60000).toISOString(),
      clientIp: '10.0.0.15',
      serverIp: '203.0.113.150',
      sni: 'backup.example',
      version: 'TLSv1.3',
      ja3: '771,4865-4866-4867,0-23-65281-10-11-16-18-51-43-45-21',
      certificateSubject: 'CN=backup.example, O=Fictional Corp, C=US',
      riskLevel: 'low',
      notes: 'TLS connection associated with high outbound payload.'
    }
  ];

  const flows = buildFlowsFromEvents(events);
  const protocolStats = computeProtocolStats(events);
  const signals = runRuleEngine(events, flows, dns, http, tls);

  const evidence: UploadedEvidence = {
    id: 'ev-demo-1',
    name: 'guided_defensive_analysis_sample.json',
    type: 'generated sample',
    size: 45670,
    uploadedAt: new Date().toISOString(),
    parseMode: 'demo',
    sourceFormat: 'Generated defensive-analysis dataset',
    retentionMode: 'Ephemeral Memory',
    status: 'completed',
    checksumStatus: 'demo-not-applicable',
  };

  return finalizeEvidenceIds({
    evidence,
    events,
    flows,
    dns,
    http,
    tls,
    signals,
    protocolStats
  });
}

// 2. CsvPacketAdapter
export function parseCsv(fileName: string, content: string): ParsedResult {
  const events: PacketEvent[] = [];
  const lines = content.split('\n');
  let headers: string[] = [];
  
  let idCounter = 1;
  const baseTime = new Date(FALLBACK_TIMESTAMP);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    // Handle quote commas inside CSV fields securely
    const fields = parseCsvLine(line);

    if (i === 0 || headers.length === 0) {
      if (line.toLowerCase().includes('source') || line.toLowerCase().includes('protocol')) {
        headers = fields.map(h => h.trim().replace(/^["']|["']$/g, '').toLowerCase());
        continue;
      } else {
        // Fallback default headers if no header found
        headers = ['no', 'time', 'source', 'destination', 'protocol', 'length', 'info'];
      }
    }

    const row: Record<string, string> = {};
    headers.forEach((header, idx) => {
      if (idx < fields.length) {
        row[header] = fields[idx].replace(/^["']|["']$/g, '').trim();
      }
    });

    const src = row['source'] || row['src_ip'] || '0.0.0.0';
    const dst = row['destination'] || row['dst_ip'] || '0.0.0.0';
    const proto = row['protocol'] || row['proto'] || 'TCP';
    const lenStr = row['length'] || row['len'] || '64';
    const info = row['info'] || row['summary'] || 'CSV Imported Event';
    const timeStr = row['time'] || String(idCounter);
    const sourcePort = suppliedPort(proto, firstPresent(row, ['source port', 'src_port']));
    const destinationPort = suppliedPort(proto, firstPresent(row, ['destination port', 'dst_port']));

    // Compute synthetic timestamp
    let ts: string;
    const offsetSeconds = parseFloat(timeStr);
    if (!isNaN(offsetSeconds)) {
      ts = new Date(baseTime.getTime() + offsetSeconds * 1000).toISOString();
    } else {
      ts = FALLBACK_TIMESTAMP;
    }

    events.push({
      id: `evt-csv-${idCounter++}`,
      timestamp: ts,
      sourceIp: src,
      sourcePort: sourcePort.port,
      sourcePortState: sourcePort.state,
      destinationIp: dst,
      destinationPort: destinationPort.port,
      destinationPortState: destinationPort.state,
      protocol: proto.toUpperCase(),
      service: row['service'] || row['app'] || guessService(proto, destinationPort.state === 'observed' ? destinationPort.port : 0),
      length: parseInt(lenStr) || 64,
      info: info,
      sourceType: 'csv'
    });
  }

  // Generate flows & protocols
  const flows = buildFlowsFromEvents(events);
  const protocolStats = computeProtocolStats(events);

  // Generate protocol-specific metadata records based on keywords in CSV row details
  const dns: DnsRecord[] = [];
  const http: HttpRecord[] = [];
  const tls: TlsRecord[] = [];

  events.forEach(evt => {
    const infoLower = evt.info.toLowerCase();
    const serviceLower = (evt.service || '').toLowerCase();

    if (serviceLower === 'dns' || evt.protocol === 'DNS' || infoLower.includes('dns query') || infoLower.includes('standard query')) {
      const isResponse = infoLower.includes('response') || evt.sourcePort === 53;
      const queryMatch = evt.info.match(/A ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      const query = queryMatch ? queryMatch[1] : 'unknown';
      dns.push({
        relatedEventIds: [evt.id],
        timestamp: evt.timestamp,
        clientIp: isResponse ? evt.destinationIp : evt.sourceIp,
        query: query,
        queryType: 'A',
        response: isResponse ? (evt.info.split(' ').pop() || '0.0.0.0') : 'Pending',
        rcode: 'NOERROR',
        riskLevel: query.includes('suspicious') || query.includes('test') ? 'high' : 'info'
      });
    } else if (evt.protocol === 'HTTP' || serviceLower === 'http' || infoLower.includes('get ') || infoLower.includes('post ')) {
      const hostMatch = evt.info.match(/host:\s*([a-zA-Z0-9.-]+)/i) || evt.info.match(/\(([^)]+)\)/);
      const host = hostMatch ? hostMatch[1] : 'unknown';
      const pathMatch = evt.info.match(/(GET|POST)\s+(\/[^\s]*)/);
      const uri = pathMatch ? pathMatch[2] : '/';
      http.push({
        relatedEventIds: [evt.id],
        timestamp: evt.timestamp,
        clientIp: evt.sourceIp,
        host: host,
        method: evt.info.includes('POST') ? 'POST' : 'GET',
        uri: uri,
        statusCode: evt.info.includes('200') ? 200 : 0,
        cleartext: true,
        riskLevel: 'low'
      });
    } else if (evt.protocol.startsWith('TLS') || serviceLower === 'https' || infoLower.includes('client hello') || infoLower.includes('sni')) {
      const sniMatch = evt.info.match(/sni:\s*([a-zA-Z0-9.-]+)/i) || evt.info.match(/Client Hello, ([a-zA-Z0-9.-]+)/);
      const sni = sniMatch ? sniMatch[1] : 'unknown';
      tls.push({
        relatedEventIds: [evt.id],
        timestamp: evt.timestamp,
        clientIp: evt.sourceIp,
        serverIp: evt.destinationIp,
        sni: sni,
        version: 'TLSv1.3',
        riskLevel: 'info'
      });
    }
  });

  const signals = runRuleEngine(events, flows, dns, http, tls);

  const evidence: UploadedEvidence = {
    id: '',
    name: fileName,
    type: 'csv',
    size: content.length,
    uploadedAt: new Date().toISOString(),
    parseMode: 'csv',
    sourceFormat: 'CSV Log Export',
    retentionMode: 'Ephemeral Memory',
    status: 'completed'
  };

  return finalizeEvidenceIds({
    evidence,
    events,
    flows,
    dns,
    http,
    tls,
    signals,
    protocolStats
  });
}

// 3. SuricataEveAdapter
export function parseSuricataEve(fileName: string, content: string): ParsedResult {
  const events: PacketEvent[] = [];
  const dns: DnsRecord[] = [];
  const http: HttpRecord[] = [];
  const tls: TlsRecord[] = [];
  const alerts: { msg: string; category: string; severity: number; src: string; dst: string; timestamp: string }[] = [];

  const lines = content.split('\n');
  let idCounter = 1;

  lines.forEach(line => {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const data = JSON.parse(trimmed);
      const ts = data.timestamp || FALLBACK_TIMESTAMP;
      const src = data.src_ip || '0.0.0.0';
      const dst = data.dest_ip || '0.0.0.0';
      const proto = data.proto || 'TCP';
      const sourcePort = suppliedPort(proto, Object.prototype.hasOwnProperty.call(data, 'src_port') ? data.src_port : undefined);
      const destinationPort = suppliedPort(proto, Object.prototype.hasOwnProperty.call(data, 'dest_port') ? data.dest_port : undefined);
      const eventType = data.event_type;
      const eventId = `evt-eve-${idCounter++}`;

      let info = `Suricata EVE: ${eventType || 'flow'}`;
      if (eventType === 'alert') {
        info = `ALERT: ${data.alert?.signature || 'Security Violation Detected'}`;
        alerts.push({
          msg: data.alert?.signature || 'Threat Blocked',
          category: data.alert?.category || 'Malware',
          severity: data.alert?.severity || 3,
          src,
          dst,
          timestamp: ts
        });
      } else if (eventType === 'dns') {
        const query = data.dns?.rrname || data.dns?.query?.[0]?.rrname || 'query.domain';
        info = `DNS ${data.dns?.type || 'A'} query for ${query}`;
        dns.push({
          relatedEventIds: [eventId],
          timestamp: ts,
          clientIp: src,
          query: query,
          queryType: data.dns?.type || 'A',
          response: data.dns?.rdata || 'Parsed',
          rcode: data.dns?.rcode || 'NOERROR',
          riskLevel: data.dns?.rcode === 'NXDOMAIN' ? 'low' : 'info'
        });
      } else if (eventType === 'http') {
        info = `HTTP ${data.http?.http_method || 'GET'} http://${data.http?.hostname || 'host'}${data.http?.url || '/'}`;
        http.push({
          relatedEventIds: [eventId],
          timestamp: ts,
          clientIp: src,
          host: data.http?.hostname || 'unknown',
          method: data.http?.http_method || 'GET',
          uri: data.http?.url || '/',
          statusCode: data.http?.status || 200,
          userAgent: data.http?.http_user_agent,
          cleartext: true,
          riskLevel: 'info'
        });
      } else if (eventType === 'tls') {
        info = `TLS SNI: ${data.tls?.sni || 'encrypted'}`;
        tls.push({
          relatedEventIds: [eventId],
          timestamp: ts,
          clientIp: src,
          serverIp: dst,
          sni: data.tls?.sni || 'unknown',
          version: data.tls?.version,
          certificateSubject: data.tls?.subject,
          riskLevel: 'info'
        });
      }

      events.push({
        id: eventId,
        timestamp: ts,
        sourceIp: src,
        sourcePort: sourcePort.port,
        sourcePortState: sourcePort.state,
        destinationIp: dst,
        destinationPort: destinationPort.port,
        destinationPortState: destinationPort.state,
        protocol: proto.toUpperCase(),
        service: eventType?.toUpperCase(),
        length: data.flow?.bytes_toclient || 100,
        info: info,
        sourceType: 'suricata'
      });
    } catch {
      // Skip malformed lines
    }
  });

  const flows = buildFlowsFromEvents(events);
  const protocolStats = computeProtocolStats(events);
  const signals = runRuleEngine(events, flows, dns, http, tls);

  // Inject Suricata alerts as high severity signals
  alerts.forEach((alert, idx) => {
    let sev: 'info' | 'low' | 'medium' | 'high' = 'high';
    if (alert.severity === 3) sev = 'low';
    if (alert.severity === 2) sev = 'medium';

    signals.push({
      id: `sig-suricata-${idx}`,
      title: `Suricata Intrusion Detection: ${alert.msg}`,
      severity: sev,
      confidence: 'high',
      category: alert.category || 'Intrusion Alert',
      observedEvidence: `Source: ${alert.src} -> Destination: ${alert.dst} at ${alert.timestamp}`,
      interpretation: 'The imported Suricata record reports a signature match for this traffic.',
      whatItDoesNotProve: 'A signature alert does not by itself prove exploitation, compromise, execution, or malicious intent.',
      recommendedDefensiveCheck: 'Validate the signature, packet context, rule revision, and matching endpoint telemetry before taking containment action.'
    });
  });

  const evidence: UploadedEvidence = {
    id: '',
    name: fileName,
    type: 'suricata',
    size: content.length,
    uploadedAt: new Date().toISOString(),
    parseMode: 'suricata',
    sourceFormat: 'Suricata EVE JSON',
    retentionMode: 'Ephemeral Memory',
    status: 'completed'
  };

  return finalizeEvidenceIds({
    evidence,
    events,
    flows,
    dns,
    http,
    tls,
    signals,
    protocolStats
  });
}

// 4. ZeekLogAdapter
export function parseZeekLog(fileName: string, content: string): ParsedResult {
  const events: PacketEvent[] = [];
  const dns: DnsRecord[] = [];
  const http: HttpRecord[] = [];
  const tls: TlsRecord[] = [];

  const lines = content.split('\n');
  let fields: string[] = [];
  let path = 'unknown';

  let idCounter = 1;

  lines.forEach(line => {
    const trimmed = line.trim();
    if (!trimmed) return;

    if (trimmed.startsWith('#path')) {
      path = trimmed.split(/\s+/)[1] || 'unknown';
      return;
    }

    if (trimmed.startsWith('#fields')) {
      fields = trimmed.split(/\s+/).slice(1);
      return;
    }

    if (trimmed.startsWith('#')) {
      return; // Skip other comment/metadata lines
    }

    const values = trimmed.split(/\t/);
    if (values.length < fields.length) return;

    const row: Record<string, string> = {};
    fields.forEach((field, idx) => {
      if (idx < values.length) {
        row[field] = values[idx];
      }
    });

    const ts = row['ts'] ? new Date(parseFloat(row['ts']) * 1000).toISOString() : FALLBACK_TIMESTAMP;
    const src = row['id.orig_h'] || '0.0.0.0';
    const dst = row['id.resp_h'] || '0.0.0.0';
    const proto = row['proto'] || 'TCP';
    const sourcePort = suppliedPort(proto, firstPresent(row, ['id.orig_p']));
    const destinationPort = suppliedPort(proto, firstPresent(row, ['id.resp_p']));
    const eventId = `evt-zeek-${idCounter++}`;

    let info = `Zeek ${path} Log entry`;

    if (path === 'conn') {
      const state = row['conn_state'] || 'S0';
      const bytes = parseInt(row['orig_bytes'] || '0') + parseInt(row['resp_bytes'] || '0');
      info = `Connection seen. State: ${state}, Bytes Transferred: ${bytes}`;
    } else if (path === 'dns') {
      const query = row['query'] || 'domain';
      info = `DNS query: ${query} (${row['qtype_name'] || 'A'})`;
      dns.push({
        relatedEventIds: [eventId],
        timestamp: ts,
        clientIp: src,
        query: query,
        queryType: row['qtype_name'] || 'A',
        response: row['answers'] || 'See answers',
        rcode: row['rcode_name'] || 'NOERROR',
        riskLevel: query.includes('suspicious') ? 'high' : 'info'
      });
    } else if (path === 'http') {
      info = `HTTP ${row['method'] || 'GET'} http://${row['host'] || 'host'}${row['uri'] || '/'}`;
      http.push({
        relatedEventIds: [eventId],
        timestamp: ts,
        clientIp: src,
        host: row['host'] || 'unknown',
        method: row['method'] || 'GET',
        uri: row['uri'] || '/',
        statusCode: parseInt(row['status_code'] || '200') || 200,
        userAgent: row['user_agent'],
        cleartext: true,
        riskLevel: 'info'
      });
    } else if (path === 'ssl') {
      info = `SSL Client SNI: ${row['server_name'] || 'encrypted'}`;
      tls.push({
        relatedEventIds: [eventId],
        timestamp: ts,
        clientIp: src,
        serverIp: dst,
        sni: row['server_name'] || 'unknown',
        version: row['version'],
        riskLevel: 'info'
      });
    }

    events.push({
      id: eventId,
      timestamp: ts,
      sourceIp: src,
      sourcePort: sourcePort.port,
      sourcePortState: sourcePort.state,
      destinationIp: dst,
      destinationPort: destinationPort.port,
      destinationPortState: destinationPort.state,
      protocol: proto.toUpperCase(),
      service: path.toUpperCase(),
      length: parseInt(row['orig_bytes'] || '100') || 100,
      info: info,
      sourceType: 'zeek'
    });
  });

  const flows = buildFlowsFromEvents(events);
  const protocolStats = computeProtocolStats(events);
  const signals = runRuleEngine(events, flows, dns, http, tls);

  const evidence: UploadedEvidence = {
    id: '',
    name: fileName,
    type: 'zeek',
    size: content.length,
    uploadedAt: new Date().toISOString(),
    parseMode: 'zeek',
    sourceFormat: `Zeek ${path.toUpperCase()} Log`,
    retentionMode: 'Ephemeral Memory',
    status: 'completed'
  };

  return finalizeEvidenceIds({
    evidence,
    events,
    flows,
    dns,
    http,
    tls,
    signals,
    protocolStats
  });
}

// 5. TsharkJsonAdapter
export function parseTsharkJson(fileName: string, content: string): ParsedResult {
  const events: PacketEvent[] = [];
  const dns: DnsRecord[] = [];
  const http: HttpRecord[] = [];
  const tls: TlsRecord[] = [];
  let rawEvents: unknown;
  try {
    rawEvents = JSON.parse(content);
  } catch {
    throw new EvidenceParseError('Malformed TShark JSON input.');
  }
  const packetList = Array.isArray(rawEvents) ? rawEvents : [rawEvents];
  if (packetList.length > MAX_PARSED_RECORDS) {
    throw new EvidenceParseError(`TShark input exceeds the ${MAX_PARSED_RECORDS.toLocaleString()}-record limit.`);
  }

  packetList.forEach((packet, packetIndex) => {
      if (!packet || typeof packet !== 'object') {
        throw new EvidenceParseError(`Invalid TShark packet at record ${packetIndex + 1}.`);
      }
      const packetData = packet as Record<string, any>;
      const source = packetData._source || {};
      const layers = source.layers || {};

      const frame = layers.frame || {};
      const ip = layers.ip || {};
      const ipv6 = layers.ipv6 || {};
      const tcp = layers.tcp || {};
      const udp = layers.udp || {};
      const dnsLayer = layers.dns;
      const httpLayer = layers.http;
      const tlsLayer = layers.ssl || layers.tls;

      const timestamp = frame['frame.time_iso'] || frame['frame.time'] || FALLBACK_TIMESTAMP;
      const sourceIp = ip['ip.src'] || ipv6['ipv6.src'] || '0.0.0.0';
      const destinationIp = ip['ip.dst'] || ipv6['ipv6.dst'] || '0.0.0.0';
      const hasTcpLayer = Object.prototype.hasOwnProperty.call(layers, 'tcp');
      const hasUdpLayer = Object.prototype.hasOwnProperty.call(layers, 'udp');
      const fragmentOffset = Number(ip['ip.frag_offset'] ?? ipv6['ipv6.frag.offset'] ?? 0);
      let protocol = hasUdpLayer ? 'UDP' : hasTcpLayer ? 'TCP' : 'IP';
      if (layers.icmp) protocol = 'ICMP';
      if (layers.icmpv6) protocol = 'ICMPv6';
      if (fragmentOffset > 0) protocol = ipv6['ipv6.src'] ? 'IPv6 fragment' : 'IPv4 fragment';
      const sourcePort = suppliedPort(
        protocol,
        hasTcpLayer && Object.prototype.hasOwnProperty.call(tcp, 'tcp.srcport')
          ? tcp['tcp.srcport']
          : hasUdpLayer && Object.prototype.hasOwnProperty.call(udp, 'udp.srcport')
            ? udp['udp.srcport']
            : undefined,
      );
      const destinationPort = suppliedPort(
        protocol,
        hasTcpLayer && Object.prototype.hasOwnProperty.call(tcp, 'tcp.dstport')
          ? tcp['tcp.dstport']
          : hasUdpLayer && Object.prototype.hasOwnProperty.call(udp, 'udp.dstport')
            ? udp['udp.dstport']
            : undefined,
      );

      const length = parseInt(frame['frame.len'] || '64');
      let info = `TShark Parsed Packet`;
      const eventId = `evt-tshark-${packetIndex + 1}`;

      if (dnsLayer) {
        const query = dnsLayer['dns.qry.name'] || 'query.domain';
        info = `DNS query: ${query}`;
        dns.push({
          relatedEventIds: [eventId],
          timestamp,
          clientIp: sourceIp,
          query,
          queryType: dnsLayer['dns.qry.type'] || 'A',
          response: dnsLayer['dns.resp.name'] || 'Pending',
          rcode: 'NOERROR',
          riskLevel: 'info'
        });
      } else if (httpLayer) {
        info = `HTTP: ${httpLayer['http.request.method'] || 'GET'} ${httpLayer['http.request.uri'] || '/'}`;
        http.push({
          relatedEventIds: [eventId],
          timestamp,
          clientIp: sourceIp,
          host: httpLayer['http.host'] || 'unknown',
          method: httpLayer['http.request.method'] || 'GET',
          uri: httpLayer['http.request.uri'] || '/',
          statusCode: parseInt(httpLayer['http.response.code'] || '200') || 200,
          cleartext: true,
          riskLevel: 'info'
        });
      } else if (tlsLayer) {
        info = `TLS Client Hello SNI: ${tlsLayer['tls.handshake.extensions_server_name'] || 'encrypted'}`;
        tls.push({
          relatedEventIds: [eventId],
          timestamp,
          clientIp: sourceIp,
          serverIp: destinationIp,
          sni: tlsLayer['tls.handshake.extensions_server_name'] || 'unknown',
          version: 'TLSv1.3',
          riskLevel: 'info'
        });
      }

      events.push({
        id: eventId,
        timestamp,
        sourceIp,
        sourcePort: sourcePort.port,
        sourcePortState: sourcePort.state,
        destinationIp,
        destinationPort: destinationPort.port,
        destinationPortState: destinationPort.state,
        protocol,
        service: dnsLayer ? 'DNS' : (httpLayer ? 'HTTP' : (tlsLayer ? 'TLS' : 'Unknown')),
        length,
        info,
        sourceType: 'tshark'
      });
    });

  const flows = buildFlowsFromEvents(events);
  const protocolStats = computeProtocolStats(events);
  const signals = runRuleEngine(events, flows, dns, http, tls);

  const evidence: UploadedEvidence = {
    id: '',
    name: fileName,
    type: 'tshark',
    size: content.length,
    uploadedAt: new Date().toISOString(),
    parseMode: 'tshark',
    sourceFormat: 'TShark JSON Export',
    retentionMode: 'Ephemeral Memory',
    status: 'completed'
  };

  return finalizeEvidenceIds({
    evidence,
    events,
    flows,
    dns,
    http,
    tls,
    signals,
    protocolStats
  });
}

// 6. TextLogAdapter / PastedStructuredLog
export function parseTextLog(fileName: string, content: string): ParsedResult {
  const events: PacketEvent[] = [];
  const lines = content.split('\n');
  const errors: string[] = [];

  const isValidIpv4 = (value: string): boolean => {
    const octets = value.split('.');
    return octets.length === 4 && octets.every(octet => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
  };
  const parsePort = (value: string | undefined, field: string, lineNumber: number): number | null => {
    if (value === undefined) return field === 'src_port' ? 0 : null;
    if (!/^\d+$/.test(value)) {
      errors.push(`Line ${lineNumber}: ${field} must be an integer from 0 to 65535.`);
      return null;
    }
    const parsed = Number(value);
    if (parsed < 0 || parsed > 65535) {
      errors.push(`Line ${lineNumber}: ${field} must be an integer from 0 to 65535.`);
      return null;
    }
    return parsed;
  };

  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const lineNumber = index + 1;
    const match = trimmed.match(/^(\S+)\s+(\S+)\s+->\s+(\S+)(?:\s+(.*))?$/);
    if (!match) {
      errors.push(`Line ${lineNumber}: expected "<ISO timestamp> <source IP> -> <destination IP> dst_port=<port> protocol=<TCP|UDP> length=<bytes>".`);
      return;
    }

    const [, timestampText, srcIp, dstIp, fieldText = ''] = match;
    const timestamp = new Date(timestampText);
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(timestampText) || Number.isNaN(timestamp.getTime())) {
      errors.push(`Line ${lineNumber}: timestamp must be a valid UTC ISO-8601 value.`);
      return;
    }
    if (!isValidIpv4(srcIp) || !isValidIpv4(dstIp)) {
      errors.push(`Line ${lineNumber}: source and destination must be valid IPv4 addresses.`);
      return;
    }

    const fields = new Map<string, string>();
    for (const token of fieldText.split(/\s+/).filter(Boolean)) {
      const fieldMatch = token.match(/^([a-z_]+)=(\S+)$/i);
      if (!fieldMatch) {
        errors.push(`Line ${lineNumber}: unsupported token "${token}"; use explicit key=value fields.`);
        return;
      }
      const key = fieldMatch[1].toLowerCase();
      if (!['src_port', 'dst_port', 'protocol', 'length'].includes(key) || fields.has(key)) {
        errors.push(`Line ${lineNumber}: unsupported or duplicate field "${key}".`);
        return;
      }
      fields.set(key, fieldMatch[2]);
    }

    const protocolValue = fields.get('protocol')?.toUpperCase();
    if (!protocolValue || !['TCP', 'UDP'].includes(protocolValue)) {
      errors.push(`Line ${lineNumber}: protocol must be explicitly set to TCP or UDP.`);
      return;
    }
    const lengthValue = fields.get('length');
    if (!lengthValue || !/^\d+$/.test(lengthValue) || Number(lengthValue) < 0 || Number(lengthValue) > 65_535) {
      errors.push(`Line ${lineNumber}: length must be an integer from 0 to 65535.`);
      return;
    }
    const srcPort = parsePort(fields.get('src_port'), 'src_port', lineNumber);
    const dstPort = parsePort(fields.get('dst_port'), 'dst_port', lineNumber);
    if (srcPort === null || dstPort === null) {
      if (fields.get('dst_port') === undefined) errors.push(`Line ${lineNumber}: dst_port is required.`);
      return;
    }

    events.push({
      id: `evt-txt-${events.length + 1}`,
      timestamp: timestamp.toISOString(),
      sourceIp: srcIp,
      sourcePort: srcPort,
      sourcePortState: portStateFor(protocolValue, fields.has('src_port')),
      destinationIp: dstIp,
      destinationPort: dstPort,
      destinationPortState: 'observed',
      protocol: protocolValue,
      length: Number(lengthValue),
      info: `${formatEndpoint(srcIp, srcPort, portStateFor(protocolValue, fields.has('src_port')))} -> ${formatEndpoint(dstIp, dstPort, 'observed')} ${protocolValue} ${lengthValue} bytes`,
      sourceType: 'text'
    });
  });

  if (errors.length) throw new EvidenceParseError(errors.join(' '));
  if (!events.length) throw new EvidenceParseError('No supported structured text records were found.');

  const flows = buildFlowsFromEvents(events);
  const protocolStats = computeProtocolStats(events);
  const signals = runRuleEngine(events, flows, [], [], []);

  const evidence: UploadedEvidence = {
    id: '',
    name: fileName,
    type: 'txt',
    size: content.length,
    uploadedAt: new Date().toISOString(),
    parseMode: 'txt',
    sourceFormat: 'Pasted Logs / Text Upload',
    retentionMode: 'Ephemeral Memory',
    status: 'completed'
  };

  return finalizeEvidenceIds({
    evidence,
    events,
    flows,
    dns: [],
    http: [],
    tls: [],
    signals,
    protocolStats
  });
}

// Raw captures are decoded locally in the browser by capture.ts.
export function parsePcapPlaceholder(fileName: string, fileSize: number): ParsedResult {
  void fileName;
  void fileSize;
  throw new EvidenceParseError('Raw captures must be decoded locally in a supported browser.');
}

// --- Rule Engine ---
export function runRuleEngine(
  events: PacketEvent[],
  flows: FlowSummary[],
  dns: DnsRecord[],
  http: HttpRecord[],
  tls: TlsRecord[]
): SuspiciousSignal[] {
  const signals: SuspiciousSignal[] = [];

  // 1. Port Scan Detection (Reconnaissance)
  const sourcePortsMap: Record<string, Set<number>> = {};
  events.forEach(evt => {
    if (evt.destinationPortState !== 'observed') return;
    if (!sourcePortsMap[evt.sourceIp]) {
      sourcePortsMap[evt.sourceIp] = new Set();
    }
    sourcePortsMap[evt.sourceIp].add(evt.destinationPort);
  });

  Object.entries(sourcePortsMap).forEach(([srcIp, ports]) => {
    if (ports.size >= 8) {
      signals.push({
        id: `sig-portscan-${srcIp}`,
      title: 'High destination-port diversity observed',
        severity: 'medium',
        confidence: 'high',
        category: 'Connection pattern',
        observedEvidence: `Host ${srcIp} connected to ${ports.size} unique destination ports.`,
        interpretation: 'Contact with many destination ports can result from scanning, service discovery, testing, or normal multi-service applications.',
        whatItDoesNotProve: 'This count alone does not prove scanning, malicious intent, or compromise.',
        recommendedDefensiveCheck: 'Review the destination sequence, timing, authorized scanner inventory, and source process telemetry.'
      });
    }
  });

  // 2. High DNS Query Volume (Tunneling / Data Exfiltration)
  const dnsQueriesMap: Record<string, Record<string, number>> = {};
  dns.forEach(rec => {
    if (!dnsQueriesMap[rec.clientIp]) {
      dnsQueriesMap[rec.clientIp] = {};
    }
    dnsQueriesMap[rec.clientIp][rec.query] = (dnsQueriesMap[rec.clientIp][rec.query] || 0) + 1;
  });

  Object.entries(dnsQueriesMap).forEach(([clientIp, domains]) => {
    Object.entries(domains).forEach(([domain, count]) => {
      if (count > 12) {
        const relatedEventIds = dns
          .filter(record => record.clientIp === clientIp && record.query === domain)
          .flatMap(record => record.relatedEventIds || []);
        signals.push({
          id: `sig-dnsbeacon-${clientIp}-${domain.replace(/[^a-zA-Z0-9]/g, '_')}`,
          title: 'Repeated DNS query volume observed',
          severity: 'high',
          confidence: 'high',
          category: 'DNS activity',
          observedEvidence: `Client ${clientIp} made ${count} DNS queries for domain "${domain}".`,
          interpretation: 'Repeated queries can reflect automated software, retry behavior, resolver issues, or scheduled communication. This count does not establish timing regularity.',
          whatItDoesNotProve: 'It does not prove data is being exfiltrated; this can occasionally be caused by standard software update mechanisms or malformed DNS resolution software.',
          recommendedDefensiveCheck: 'Review the DNS response contents and correlate the query timestamps with expected application activity.',
          relatedEventIds,
        });
      }
    });
  });

  // 3. Cleartext Protocol over HTTP (Plaintext download warning)
  http.forEach((rec, idx) => {
    if (rec.cleartext && (rec.uri.endsWith('.bin') || rec.uri.endsWith('.exe') || rec.uri.endsWith('.sh') || rec.uri.endsWith('.bat'))) {
      signals.push({
        id: `sig-cleartext-download-${idx}`,
        title: 'Cleartext HTTP request for binary-like path observed',
        severity: 'medium',
        confidence: 'high',
        category: 'Cleartext transfer',
        observedEvidence: `Host ${rec.clientIp} requested "${rec.uri}" over cleartext HTTP (Host: ${rec.host}).`,
        interpretation: 'A binary-like path requested over HTTP may expose content to observation or modification in transit.',
        whatItDoesNotProve: 'It does not prove a file was returned, saved, executed, or malicious.',
        recommendedDefensiveCheck: 'Validate the requested resource through authorized file and endpoint telemetry, and prefer TLS-protected distribution.',
        relatedEventIds: rec.relatedEventIds || [],
      });
    }
  });

  // 4. Connection to Unusual Port (Unusual port check)
  flows.forEach(flow => {
    const maliciousPorts = [4444, 6667, 8000, 1337];
    if (flow.destinationPortState === 'observed' && maliciousPorts.includes(flow.destinationPort) && flow.direction === 'outbound') {
      signals.push({
        id: `sig-unusualport-${flow.id}`,
        title: 'Outbound connection on selected high port observed',
        severity: 'high',
        confidence: 'medium',
        category: 'Port review',
        observedEvidence: `Internal IP ${flow.sourceIp} initiated direct socket session with external ${flow.destinationIp} on port ${flow.destinationPort}.`,
        interpretation: 'Sustained outbound connections to ports such as 4444 or 1337 require validation as they can be associated with custom network services, debugging, or reverse shell activity.',
        whatItDoesNotProve: 'It does not guarantee the connection is malicious; standard development environments occasionally use ports like 8000 or 1337.',
        recommendedDefensiveCheck: 'Identify the owning process and validate the destination service against approved application activity.',
        relatedFlowIds: [flow.id],
        relatedEventIds: flow.relatedEvents || [],
      });
    }
  });

  // 5. Repeated outbound connections to the same external service
  const repeatedOutboundGroups: Record<string, FlowSummary[]> = {};
  flows.forEach(flow => {
    if (flow.direction !== 'outbound' || flow.destinationPortState === 'not-applicable') return;
    const key = `${flow.sourceIp}->${flow.destinationIp}:${portFlowKey(flow.destinationPort, flow.destinationPortState)}:${flow.protocol}`;
    repeatedOutboundGroups[key] = repeatedOutboundGroups[key] || [];
    repeatedOutboundGroups[key].push(flow);
  });

  Object.values(repeatedOutboundGroups).forEach(group => {
    if (group.length < 4) return;

    const [firstFlow] = group;
    const relatedFlowIds = group.map(flow => flow.id);
    const relatedEventIds = group.flatMap(flow => flow.relatedEvents || []);
    signals.push({
      id: `sig-repeated-connections-${firstFlow.sourceIp}-${firstFlow.destinationIp}-${portFlowKey(firstFlow.destinationPort, firstFlow.destinationPortState)}`.replace(/[^a-zA-Z0-9-_]/g, '_'),
      title: 'Repeated outbound connections',
      severity: 'medium',
      confidence: group.length >= 8 ? 'high' : 'medium',
      category: 'Repeated outbound activity',
      observedEvidence: `Internal IP ${firstFlow.sourceIp} made ${group.length} repeated outbound connection attempts to ${formatEndpoint(firstFlow.destinationIp, firstFlow.destinationPort, firstFlow.destinationPortState)}.`,
      interpretation: 'Multiple outbound sessions to the same external service may indicate application heartbeats, staged communication, polling, or repeated connection retries that require validation alongside endpoint context.',
      whatItDoesNotProve: 'It does not prove command-and-control, tunneling, or data theft. Normal client software, update services, and developer tools can produce repeated outbound connections.',
      recommendedDefensiveCheck: 'Review the destination reputation, destination service owner, process lineage on the source host, and whether these repeated sessions match expected application behavior.',
      relatedFlowIds,
      relatedEventIds,
    });
  });

  // 6. Massive Outbound Data Spike
  flows.forEach(flow => {
    if (flow.byteCount > 10 * 1024 * 1024 && flow.direction === 'outbound') {
      signals.push({
        id: `sig-dataspike-${flow.id}`,
        title: 'Large outbound byte count observed',
        severity: 'high',
        confidence: 'medium',
        category: 'Traffic volume',
        observedEvidence: `Flow summary shows ${flow.sourceIp} pushed ${(flow.byteCount / (1024 * 1024)).toFixed(2)} MB of raw TCP data to external endpoint ${flow.destinationIp}.`,
        interpretation: 'Large outbound byte counts can reflect backups, synchronization, uploads, exports, or other transfers that require business-context validation.',
        whatItDoesNotProve: 'It does not prove theft occurred; the user could be updating extensive legitimate code projects, downloading standard databases, or executing an approved backup.',
        recommendedDefensiveCheck: 'Cross-reference the transfer with approved backups, synchronization jobs, and endpoint file-access telemetry.',
        relatedFlowIds: [flow.id],
        relatedEventIds: flow.relatedEvents || [],
      });
    }
  });

  return signals;
}

// --- Utilities ---

function parseCsvLine(text: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const char = text[i];

    if (char === '"' || char === "'") {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current);
  return result;
}

export function buildFlowsFromEvents(events: PacketEvent[]): FlowSummary[] {
  const flowsMap: Record<string, FlowSummary> = {};

  events.forEach(evt => {
    // Unique Flow Key
    const key = `${evt.sourceIp}:${portFlowKey(evt.sourcePort, evt.sourcePortState)}->${evt.destinationIp}:${portFlowKey(evt.destinationPort, evt.destinationPortState)}:${evt.protocol}`;
    const reverseKey = `${evt.destinationIp}:${portFlowKey(evt.destinationPort, evt.destinationPortState)}->${evt.sourceIp}:${portFlowKey(evt.sourcePort, evt.sourcePortState)}:${evt.protocol}`;

    const dir = getDirection(evt.sourceIp, evt.destinationIp);

    if (flowsMap[key]) {
      const flow = flowsMap[key];
      flow.packetCount += 1;
      flow.byteCount += evt.length;
      if (new Date(evt.timestamp).getTime() > new Date(flow.lastSeen).getTime()) {
        flow.lastSeen = evt.timestamp;
      }
      flow.duration = (new Date(flow.lastSeen).getTime() - new Date(flow.firstSeen).getTime()) / 1000;
      flow.relatedEvents?.push(evt.id);
    } else if (flowsMap[reverseKey]) {
      // Treat reverse direction as part of the same conversational flow
      const flow = flowsMap[reverseKey];
      flow.packetCount += 1;
      flow.byteCount += evt.length;
      if (new Date(evt.timestamp).getTime() > new Date(flow.lastSeen).getTime()) {
        flow.lastSeen = evt.timestamp;
      }
      flow.duration = (new Date(flow.lastSeen).getTime() - new Date(flow.firstSeen).getTime()) / 1000;
      flow.relatedEvents?.push(evt.id);
    } else {
      // Identify risk level based on destination ports
      let risk: 'info' | 'low' | 'medium' | 'high' = 'info';
      if (evt.destinationPortState === 'observed' && [4444, 1337].includes(evt.destinationPort)) risk = 'high';
      else if (evt.destinationPortState === 'observed' && [21, 23, 80].includes(evt.destinationPort)) risk = 'medium';
      else if (evt.destinationPortState === 'observed' && dir === 'outbound' && ![80, 443].includes(evt.destinationPort)) risk = 'low';

      flowsMap[key] = {
        id: deterministicId('flow-pending', [key]),
        firstSeen: evt.timestamp,
        lastSeen: evt.timestamp,
        sourceIp: evt.sourceIp,
        sourcePort: evt.sourcePort,
        sourcePortState: evt.sourcePortState,
        destinationIp: evt.destinationIp,
        destinationPort: evt.destinationPort,
        destinationPortState: evt.destinationPortState,
        protocol: evt.protocol,
        service: evt.service,
        packetCount: 1,
        byteCount: evt.length,
        duration: 0,
        direction: dir,
        riskLevel: risk,
        relatedEvents: [evt.id]
      };
    }
  });

  return Object.values(flowsMap);
}

export function computeProtocolStats(events: PacketEvent[]): ProtocolStat[] {
  const counts: Record<string, { count: number; bytes: number }> = {};
  let totalCount = 0;

  events.forEach(evt => {
    const proto = evt.protocol || 'TCP';
    if (!counts[proto]) {
      counts[proto] = { count: 0, bytes: 0 };
    }
    counts[proto].count += 1;
    counts[proto].bytes += evt.length;
    totalCount += 1;
  });

  const explanations: Record<string, string> = {
    TCP: 'Transmission Control Protocol. Reliable, ordered connection-oriented byte streams utilized for web (HTTP/HTTPS), SSH, mail, and database connections.',
    UDP: 'User Datagram Protocol. Fast, connectionless datagram queries suited for lightweight lookups, streaming, and essential DNS queries.',
    ICMP: 'Internet Control Message Protocol. Control plane protocol used for error reporting, echo queries (ping), diagnostics, and network discovery.',
    DNS: 'Domain Name System. Responsible for converting human-readable hostnames to numerical IPs. Critical core for auditing C2 beacon targets.',
    HTTP: 'Hypertext Transfer Protocol. Plaintext, unsecured web communications representing potential data disclosure or payload delivery vectors.',
    TLS: 'Transport Layer Security. Secure encrypted wrappers ensuring cryptographic safety on top of TCP conversations.',
    SURICATA: 'Suricata Intrusion Detection events. Highlights matching sig patterns.',
    ZEEK: 'Zeek Security Observability events. Deep metadata telemetry.'
  };

  return Object.entries(counts).map(([proto, data]) => {
    return {
      protocol: proto,
      count: data.count,
      percentage: totalCount > 0 ? parseFloat(((data.count / totalCount) * 100).toFixed(1)) : 0,
      byteCount: data.bytes,
      explanation: explanations[proto] || 'Custom system network wrapper.'
    };
  });
}

function guessService(protocol: string, port: number): string {
  if (port === 53) return 'DNS';
  if (port === 80) return 'HTTP';
  if (port === 443) return 'HTTPS';
  if (port === 22) return 'SSH';
  if (port === 21) return 'FTP';
  if (port === 23) return 'Telnet';
  if (port === 1337 || port === 4444) return 'Unassigned high port';
  return protocol === 'UDP' ? 'UDP Service' : 'TCP Service';
}
