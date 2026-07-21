import type {
  DnsRecord,
  FlowSummary,
  HttpRecord,
  PacketEvent,
  SuspiciousSignal,
  TlsRecord,
  UploadedEvidence,
} from '../types.js';
import { portIdentityPart } from './ports.js';

export interface EvidenceCollections {
  evidence: UploadedEvidence;
  events: PacketEvent[];
  flows: FlowSummary[];
  dns: DnsRecord[];
  http: HttpRecord[];
  tls: TlsRecord[];
  signals: SuspiciousSignal[];
}

function stableHash(value: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(36).padStart(7, '0');
}

function canonicalPart(value: unknown): string {
  if (Array.isArray(value)) return value.map(canonicalPart).join(',');
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

export function deterministicId(prefix: string, fields: unknown[], occurrence = 0): string {
  return `${prefix}-${stableHash(fields.map(canonicalPart).join('\u001f'))}-${occurrence + 1}`;
}

function assignIds<T>(items: T[], prefix: string, fields: (item: T) => unknown[]): T[] {
  const occurrences = new Map<string, number>();
  return items.map(item => {
    const parts = fields(item);
    const key = parts.map(canonicalPart).join('\u001f');
    const occurrence = occurrences.get(key) ?? 0;
    occurrences.set(key, occurrence + 1);
    return { ...item, id: deterministicId(prefix, parts, occurrence) };
  });
}

export function finalizeEvidenceIds<T extends EvidenceCollections>(result: T): T {
  const originalEvents = result.events;
  const events = assignIds(originalEvents, 'evt', event => [
    event.timestamp,
    event.sourceIp,
    portIdentityPart(event.sourcePort, event.sourcePortState),
    event.destinationIp,
    portIdentityPart(event.destinationPort, event.destinationPortState),
    event.protocol,
    event.service,
    event.length,
    event.info,
    event.sourceType,
  ]);
  const eventIdMap = new Map(originalEvents.map((event, index) => [event.id, events[index].id]));

  const originalFlows = result.flows;
  const flowsWithEvents = originalFlows.map(flow => ({
    ...flow,
    relatedEvents: flow.relatedEvents?.map(id => eventIdMap.get(id) ?? id),
  }));
  const flows = assignIds(flowsWithEvents, 'flow', flow => [
    flow.firstSeen,
    flow.lastSeen,
    flow.sourceIp,
    portIdentityPart(flow.sourcePort, flow.sourcePortState),
    flow.destinationIp,
    portIdentityPart(flow.destinationPort, flow.destinationPortState),
    flow.protocol,
    flow.packetCount,
    flow.byteCount,
  ]);
  const flowIdMap = new Map(originalFlows.map((flow, index) => [flow.id, flows[index].id]));

  const dnsWithEvents = result.dns.map(record => ({
    ...record,
    relatedEventIds: record.relatedEventIds?.map(id => eventIdMap.get(id) ?? id),
  }));
  const dns = assignIds(dnsWithEvents, 'dns', record => [
    record.timestamp,
    record.clientIp,
    record.query,
    record.queryType,
    record.response,
    record.rcode,
  ]);
  const httpWithEvents = result.http.map(record => ({
    ...record,
    relatedEventIds: record.relatedEventIds?.map(id => eventIdMap.get(id) ?? id),
  }));
  const http = assignIds(httpWithEvents, 'http', record => [
    record.timestamp,
    record.clientIp,
    record.host,
    record.method,
    record.uri,
    record.statusCode,
    record.cleartext,
  ]);
  const tlsWithEvents = result.tls.map(record => ({
    ...record,
    relatedEventIds: record.relatedEventIds?.map(id => eventIdMap.get(id) ?? id),
  }));
  const tls = assignIds(tlsWithEvents, 'tls', record => [
    record.timestamp,
    record.clientIp,
    record.serverIp,
    record.sni,
    record.version,
    record.ja3,
    record.certificateSubject,
  ]);

  const signalsWithRelations = result.signals.map(signal => ({
    ...signal,
    relatedEventIds: signal.relatedEventIds?.map(id => eventIdMap.get(id) ?? id),
    relatedFlowIds: signal.relatedFlowIds?.map(id => flowIdMap.get(id) ?? id),
  }));
  const signals = assignIds(signalsWithRelations, 'sig', signal => [
    signal.title,
    signal.severity,
    signal.confidence,
    signal.category,
    signal.observedEvidence,
    signal.relatedEventIds,
    signal.relatedFlowIds,
  ]);

  return {
    ...result,
    evidence: {
      ...result.evidence,
      id: deterministicId('evidence', [
        result.evidence.name,
        result.evidence.type,
        result.evidence.size,
        result.evidence.parseMode,
        result.evidence.sourceFormat,
      ]),
    },
    events,
    flows,
    dns,
    http,
    tls,
    signals,
  };
}
