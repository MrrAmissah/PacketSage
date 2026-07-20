import type {
  DnsRecord,
  FlowSummary,
  HttpRecord,
  InvestigationAssessment,
  InvestigationDnsEvidence,
  InvestigationEvidencePacket,
  InvestigationEventEvidence,
  InvestigationFlowEvidence,
  InvestigationHttpEvidence,
  InvestigationSignalEvidence,
  InvestigationTlsEvidence,
  PacketEvent,
  SuspiciousSignal,
  TlsRecord,
} from '../types';
import {
  MAX_INVESTIGATION_EVENTS,
  MAX_INVESTIGATION_FLOWS,
  MAX_INVESTIGATION_ID_CHARACTERS,
  MAX_INVESTIGATION_OUTPUT_ITEMS,
  MAX_INVESTIGATION_PROTOCOL_RECORDS,
  MAX_INVESTIGATION_REQUEST_BYTES,
  MAX_INVESTIGATION_TEXT_CHARACTERS,
} from './limits';
import { deterministicId } from './deterministic';
import { resolveRelatedFlows } from './relatedFlows';

export interface InvestigationCollections {
  flows: readonly FlowSummary[];
  events: readonly PacketEvent[];
  dns: readonly DnsRecord[];
  http: readonly HttpRecord[];
  tls: readonly TlsRecord[];
}

export class InvestigationValidationError extends Error {
  constructor(message: string, readonly status: 400 | 413 = 400) {
    super(message);
    this.name = 'InvestigationValidationError';
  }
}

const severities = new Set(['info', 'low', 'medium', 'high']);
const confidences = new Set(['low', 'medium', 'high']);
const directions = new Set(['inbound', 'outbound', 'internal']);

function boundedText(value: string, max = MAX_INVESTIGATION_TEXT_CHARACTERS): string {
  return value.slice(0, max);
}

function validId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_INVESTIGATION_ID_CHARACTERS;
}

function orderedUnique<T>(items: readonly T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  return items.filter(item => {
    const id = key(item);
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

function normalizeFlow(flow: FlowSummary, includedEventIds: ReadonlySet<string>): InvestigationFlowEvidence {
  return {
    id: flow.id,
    firstSeen: boundedText(flow.firstSeen, 64),
    lastSeen: boundedText(flow.lastSeen, 64),
    sourceIp: boundedText(flow.sourceIp, 128),
    sourcePort: flow.sourcePort,
    destinationIp: boundedText(flow.destinationIp, 128),
    destinationPort: flow.destinationPort,
    protocol: boundedText(flow.protocol, 32),
    ...(flow.service ? { service: boundedText(flow.service, 64) } : {}),
    packetCount: flow.packetCount,
    byteCount: flow.byteCount,
    duration: flow.duration,
    direction: flow.direction,
    riskLevel: flow.riskLevel,
    relatedEventIds: (flow.relatedEvents || []).filter(id => includedEventIds.has(id)),
  };
}

function normalizeEvent(event: PacketEvent): InvestigationEventEvidence {
  return {
    id: event.id,
    timestamp: boundedText(event.timestamp, 64),
    sourceIp: boundedText(event.sourceIp, 128),
    sourcePort: event.sourcePort,
    destinationIp: boundedText(event.destinationIp, 128),
    destinationPort: event.destinationPort,
    protocol: boundedText(event.protocol, 32),
    ...(event.service ? { service: boundedText(event.service, 64) } : {}),
    length: event.length,
    ...(event.capturedLength === undefined ? {} : { capturedLength: event.capturedLength }),
    ...(event.originalLength === undefined ? {} : { originalLength: event.originalLength }),
    ...(event.sourceType ? { sourceType: boundedText(event.sourceType, 32) } : {}),
  };
}

export function buildInvestigationEvidencePacket(
  signal: SuspiciousSignal,
  collections: InvestigationCollections,
): InvestigationEvidencePacket | null {
  if (!validId(signal.id)) return null;

  const allRelatedFlows = resolveRelatedFlows(signal.relatedFlowIds, collections.flows);
  if (allRelatedFlows.length === 0) return null;
  const relatedFlows = allRelatedFlows.slice(0, MAX_INVESTIGATION_FLOWS);

  const eventById = new Map(collections.events.filter(event => validId(event.id)).map(event => [event.id, event]));
  const requestedEvents = orderedUnique(
    relatedFlows.flatMap(flow => flow.relatedEvents || []).map(id => eventById.get(id)).filter((event): event is PacketEvent => Boolean(event)),
    event => event.id,
  );
  const includedEvents = requestedEvents.slice(0, MAX_INVESTIGATION_EVENTS);
  const includedEventIds = new Set(includedEvents.map(event => event.id));
  const events = includedEvents.map(normalizeEvent);
  const flows = relatedFlows.map(flow => normalizeFlow(flow, includedEventIds));

  const exactRelatedEventIds = (ids: readonly string[] | undefined): string[] => orderedUnique(
    (ids || []).filter(id => includedEventIds.has(id)),
    id => id,
  );
  const dnsCandidates = collections.dns.flatMap(record => {
    if (!validId(record.id)) return [];
    const relatedEventIds = exactRelatedEventIds(record.relatedEventIds);
    return relatedEventIds.length > 0 ? [{ record: record as DnsRecord & { id: string }, relatedEventIds }] : [];
  });
  const httpCandidates = collections.http.flatMap(record => {
    if (!validId(record.id)) return [];
    const relatedEventIds = exactRelatedEventIds(record.relatedEventIds);
    return relatedEventIds.length > 0 ? [{ record: record as HttpRecord & { id: string }, relatedEventIds }] : [];
  });
  const tlsCandidates = collections.tls.flatMap(record => {
    if (!validId(record.id)) return [];
    const relatedEventIds = exactRelatedEventIds(record.relatedEventIds);
    return relatedEventIds.length > 0 ? [{ record: record as TlsRecord & { id: string }, relatedEventIds }] : [];
  });
  const protocolCandidates = [
    ...dnsCandidates.map(candidate => ({ kind: 'dns' as const, ...candidate })),
    ...httpCandidates.map(candidate => ({ kind: 'http' as const, ...candidate })),
    ...tlsCandidates.map(candidate => ({ kind: 'tls' as const, ...candidate })),
  ];
  const includedProtocolRecords = protocolCandidates.slice(0, MAX_INVESTIGATION_PROTOCOL_RECORDS);

  const dns: InvestigationDnsEvidence[] = includedProtocolRecords
    .filter((item): item is { kind: 'dns'; record: DnsRecord & { id: string }; relatedEventIds: string[] } => item.kind === 'dns')
    .map(({ record, relatedEventIds }) => ({
      id: record.id,
      relatedEventIds,
      timestamp: boundedText(record.timestamp, 64),
      clientIp: boundedText(record.clientIp, 128),
      query: boundedText(record.query),
      queryType: boundedText(record.queryType, 32),
      response: boundedText(record.response),
      rcode: boundedText(record.rcode, 32),
      riskLevel: record.riskLevel,
    }));
  const http: InvestigationHttpEvidence[] = includedProtocolRecords
    .filter((item): item is { kind: 'http'; record: HttpRecord & { id: string }; relatedEventIds: string[] } => item.kind === 'http')
    .map(({ record, relatedEventIds }) => ({
      id: record.id,
      relatedEventIds,
      timestamp: boundedText(record.timestamp, 64),
      clientIp: boundedText(record.clientIp, 128),
      host: boundedText(record.host),
      method: boundedText(record.method, 32),
      uri: boundedText(record.uri),
      statusCode: record.statusCode,
      cleartext: record.cleartext,
      riskLevel: record.riskLevel,
    }));
  const tls: InvestigationTlsEvidence[] = includedProtocolRecords
    .filter((item): item is { kind: 'tls'; record: TlsRecord & { id: string }; relatedEventIds: string[] } => item.kind === 'tls')
    .map(({ record, relatedEventIds }) => ({
      id: record.id,
      relatedEventIds,
      timestamp: boundedText(record.timestamp, 64),
      clientIp: boundedText(record.clientIp, 128),
      serverIp: boundedText(record.serverIp, 128),
      sni: boundedText(record.sni),
      ...(record.version ? { version: boundedText(record.version, 64) } : {}),
      ...(record.ja3 ? { ja3: boundedText(record.ja3, 256) } : {}),
      ...(record.certificateSubject ? { certificateSubject: boundedText(record.certificateSubject) } : {}),
      riskLevel: record.riskLevel,
    }));

  const signalEvidence: InvestigationSignalEvidence = {
    id: signal.id,
    title: boundedText(signal.title),
    severity: signal.severity,
    confidence: signal.confidence,
    category: boundedText(signal.category),
    observedEvidence: boundedText(signal.observedEvidence),
    interpretation: boundedText(signal.interpretation),
    whatItDoesNotProve: boundedText(signal.whatItDoesNotProve),
    recommendedDefensiveCheck: boundedText(signal.recommendedDefensiveCheck),
    relatedFlowIds: flows.map(flow => flow.id),
    relatedEventIds: events.map(event => event.id),
  };

  const packet: InvestigationEvidencePacket = {
    version: '1',
    signal: signalEvidence,
    flows,
    events,
    dns,
    http,
    tls,
    limitsApplied: {
      flowsTruncated: allRelatedFlows.length > relatedFlows.length,
      eventsTruncated: requestedEvents.length > includedEvents.length,
      protocolRecordsTruncated: protocolCandidates.length > includedProtocolRecords.length,
    },
  };
  if (new TextEncoder().encode(JSON.stringify({ evidence: packet })).byteLength > MAX_INVESTIGATION_REQUEST_BYTES) {
    throw new InvestigationValidationError('Investigation evidence exceeds the request limit.', 413);
  }
  return packet;
}

function objectValue(value: unknown, message: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new InvestigationValidationError(message);
  return value as Record<string, unknown>;
}

function stringValue(value: unknown, message: string, max = MAX_INVESTIGATION_TEXT_CHARACTERS): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) throw new InvestigationValidationError(message);
  return value;
}

function optionalStringValue(value: unknown, message: string, max = MAX_INVESTIGATION_TEXT_CHARACTERS): string | undefined {
  if (value === undefined) return undefined;
  return stringValue(value, message, max);
}

function numberValue(value: unknown, message: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new InvestigationValidationError(message);
  return value;
}

function stringArray(value: unknown, message: string, maxItems: number): string[] {
  if (!Array.isArray(value) || value.length > maxItems || value.some(item => !validId(item))) {
    throw new InvestigationValidationError(message);
  }
  return [...value] as string[];
}

function recordArray(value: unknown, message: string, maxItems: number): Record<string, unknown>[] {
  if (!Array.isArray(value)) throw new InvestigationValidationError(message);
  if (value.length > maxItems) throw new InvestigationValidationError(message, 413);
  return value.map(item => objectValue(item, message));
}

export function validateInvestigationRequest(body: unknown): InvestigationEvidencePacket {
  let bytes: number;
  try {
    bytes = new TextEncoder().encode(JSON.stringify(body)).byteLength;
  } catch {
    throw new InvestigationValidationError('Investigation request must be valid JSON.');
  }
  if (bytes > MAX_INVESTIGATION_REQUEST_BYTES) throw new InvestigationValidationError('Investigation request is too large.', 413);

  const root = objectValue(body, 'Investigation request must be a JSON object.');
  const evidence = objectValue(root.evidence, 'Investigation evidence is required.');
  if (evidence.version !== '1') throw new InvestigationValidationError('Unsupported investigation evidence version.');
  const signalValue = objectValue(evidence.signal, 'A selected signal is required.');

  const events: InvestigationEventEvidence[] = recordArray(evidence.events, 'Invalid investigation events.', MAX_INVESTIGATION_EVENTS).map(event => ({
    id: stringValue(event.id, 'Invalid event ID.', MAX_INVESTIGATION_ID_CHARACTERS),
    timestamp: stringValue(event.timestamp, 'Invalid event timestamp.', 64),
    sourceIp: stringValue(event.sourceIp, 'Invalid event source.', 128),
    sourcePort: numberValue(event.sourcePort, 'Invalid event source port.'),
    destinationIp: stringValue(event.destinationIp, 'Invalid event destination.', 128),
    destinationPort: numberValue(event.destinationPort, 'Invalid event destination port.'),
    protocol: stringValue(event.protocol, 'Invalid event protocol.', 32),
    ...(optionalStringValue(event.service, 'Invalid event service.', 64) ? { service: event.service as string } : {}),
    length: numberValue(event.length, 'Invalid event length.'),
    ...(event.capturedLength === undefined ? {} : { capturedLength: numberValue(event.capturedLength, 'Invalid captured length.') }),
    ...(event.originalLength === undefined ? {} : { originalLength: numberValue(event.originalLength, 'Invalid original length.') }),
    ...(optionalStringValue(event.sourceType, 'Invalid event source type.', 32) ? { sourceType: event.sourceType as string } : {}),
  }));
  const eventIds = new Set(events.map(event => event.id));

  const flows: InvestigationFlowEvidence[] = recordArray(evidence.flows, 'Invalid investigation flows.', MAX_INVESTIGATION_FLOWS).map(flow => {
    const direction = stringValue(flow.direction, 'Invalid flow direction.', 16);
    const riskLevel = stringValue(flow.riskLevel, 'Invalid flow risk level.', 16);
    if (!directions.has(direction) || !severities.has(riskLevel)) throw new InvestigationValidationError('Invalid flow classification.');
    const relatedEventIds = stringArray(flow.relatedEventIds, 'Invalid flow event references.', MAX_INVESTIGATION_EVENTS);
    if (relatedEventIds.some(id => !eventIds.has(id))) throw new InvestigationValidationError('Flow references unavailable event evidence.');
    const service = optionalStringValue(flow.service, 'Invalid flow service.', 64);
    return {
      id: stringValue(flow.id, 'Invalid flow ID.', MAX_INVESTIGATION_ID_CHARACTERS),
      firstSeen: stringValue(flow.firstSeen, 'Invalid flow start time.', 64),
      lastSeen: stringValue(flow.lastSeen, 'Invalid flow end time.', 64),
      sourceIp: stringValue(flow.sourceIp, 'Invalid flow source.', 128),
      sourcePort: numberValue(flow.sourcePort, 'Invalid flow source port.'),
      destinationIp: stringValue(flow.destinationIp, 'Invalid flow destination.', 128),
      destinationPort: numberValue(flow.destinationPort, 'Invalid flow destination port.'),
      protocol: stringValue(flow.protocol, 'Invalid flow protocol.', 32),
      ...(service ? { service } : {}),
      packetCount: numberValue(flow.packetCount, 'Invalid flow packet count.'),
      byteCount: numberValue(flow.byteCount, 'Invalid flow byte count.'),
      duration: numberValue(flow.duration, 'Invalid flow duration.'),
      direction: direction as InvestigationFlowEvidence['direction'],
      riskLevel: riskLevel as InvestigationFlowEvidence['riskLevel'],
      relatedEventIds,
    };
  });
  if (flows.length === 0) throw new InvestigationValidationError('No valid related flow evidence was supplied.');
  const flowIds = new Set(flows.map(flow => flow.id));
  const referencedEventIds = new Set(flows.flatMap(flow => flow.relatedEventIds));
  if (events.some(event => !referencedEventIds.has(event.id))) throw new InvestigationValidationError('Event evidence must be referenced by a related flow.');

  const signalFlowIds = stringArray(signalValue.relatedFlowIds, 'Invalid signal flow references.', MAX_INVESTIGATION_FLOWS);
  const signalEventIds = stringArray(signalValue.relatedEventIds, 'Invalid signal event references.', MAX_INVESTIGATION_EVENTS);
  if (signalFlowIds.length !== flows.length || signalFlowIds.some((id, index) => id !== flows[index].id)) {
    throw new InvestigationValidationError('Signal flow references do not match supplied flow evidence.');
  }
  if (signalEventIds.length !== events.length || signalEventIds.some((id, index) => id !== events[index].id)) {
    throw new InvestigationValidationError('Signal event references do not match supplied event evidence.');
  }

  const severity = stringValue(signalValue.severity, 'Invalid signal severity.', 16);
  const confidence = stringValue(signalValue.confidence, 'Invalid signal confidence.', 16);
  if (!severities.has(severity) || !confidences.has(confidence)) throw new InvestigationValidationError('Invalid signal classification.');
  const signal: InvestigationSignalEvidence = {
    id: stringValue(signalValue.id, 'Invalid signal ID.', MAX_INVESTIGATION_ID_CHARACTERS),
    title: stringValue(signalValue.title, 'Invalid signal title.'),
    severity: severity as InvestigationSignalEvidence['severity'],
    confidence: confidence as InvestigationSignalEvidence['confidence'],
    category: stringValue(signalValue.category, 'Invalid signal category.'),
    observedEvidence: stringValue(signalValue.observedEvidence, 'Invalid observed evidence.'),
    interpretation: stringValue(signalValue.interpretation, 'Invalid signal interpretation.'),
    whatItDoesNotProve: stringValue(signalValue.whatItDoesNotProve, 'Invalid signal limitation.'),
    recommendedDefensiveCheck: stringValue(signalValue.recommendedDefensiveCheck, 'Invalid defensive check.'),
    relatedFlowIds: signalFlowIds,
    relatedEventIds: signalEventIds,
  };

  const protocolLimit = MAX_INVESTIGATION_PROTOCOL_RECORDS;
  const protocolEventIds = (value: unknown, message: string): string[] => {
    const ids = orderedUnique(stringArray(value, message, MAX_INVESTIGATION_EVENTS), id => id);
    if (ids.length === 0 || ids.some(id => !eventIds.has(id))) throw new InvestigationValidationError(message);
    return ids;
  };
  const dns: InvestigationDnsEvidence[] = recordArray(evidence.dns, 'Invalid DNS evidence.', protocolLimit).map(record => ({
    id: stringValue(record.id, 'Invalid DNS evidence ID.', MAX_INVESTIGATION_ID_CHARACTERS),
    relatedEventIds: protocolEventIds(record.relatedEventIds, 'DNS evidence must reference supplied events.'),
    timestamp: stringValue(record.timestamp, 'Invalid DNS timestamp.', 64),
    clientIp: stringValue(record.clientIp, 'Invalid DNS client.', 128),
    query: stringValue(record.query, 'Invalid DNS query.'),
    queryType: stringValue(record.queryType, 'Invalid DNS query type.', 32),
    response: stringValue(record.response, 'Invalid DNS response.'),
    rcode: stringValue(record.rcode, 'Invalid DNS response code.', 32),
    riskLevel: (() => {
      const risk = stringValue(record.riskLevel, 'Invalid DNS risk level.', 16);
      if (!severities.has(risk)) throw new InvestigationValidationError('Invalid DNS risk level.');
      return risk as InvestigationDnsEvidence['riskLevel'];
    })(),
  }));
  const http: InvestigationHttpEvidence[] = recordArray(evidence.http, 'Invalid HTTP evidence.', protocolLimit).map(record => {
    if (typeof record.cleartext !== 'boolean') throw new InvestigationValidationError('Invalid HTTP encryption state.');
    const risk = stringValue(record.riskLevel, 'Invalid HTTP risk level.', 16);
    if (!severities.has(risk)) throw new InvestigationValidationError('Invalid HTTP risk level.');
    return {
      id: stringValue(record.id, 'Invalid HTTP evidence ID.', MAX_INVESTIGATION_ID_CHARACTERS),
      relatedEventIds: protocolEventIds(record.relatedEventIds, 'HTTP evidence must reference supplied events.'),
      timestamp: stringValue(record.timestamp, 'Invalid HTTP timestamp.', 64),
      clientIp: stringValue(record.clientIp, 'Invalid HTTP client.', 128),
      host: stringValue(record.host, 'Invalid HTTP host.'),
      method: stringValue(record.method, 'Invalid HTTP method.', 32),
      uri: stringValue(record.uri, 'Invalid HTTP URI.'),
      statusCode: numberValue(record.statusCode, 'Invalid HTTP status code.'),
      cleartext: record.cleartext,
      riskLevel: risk as InvestigationHttpEvidence['riskLevel'],
    };
  });
  const tls: InvestigationTlsEvidence[] = recordArray(evidence.tls, 'Invalid TLS evidence.', protocolLimit).map(record => ({
    id: stringValue(record.id, 'Invalid TLS evidence ID.', MAX_INVESTIGATION_ID_CHARACTERS),
    relatedEventIds: protocolEventIds(record.relatedEventIds, 'TLS evidence must reference supplied events.'),
    timestamp: stringValue(record.timestamp, 'Invalid TLS timestamp.', 64),
    clientIp: stringValue(record.clientIp, 'Invalid TLS client.', 128),
    serverIp: stringValue(record.serverIp, 'Invalid TLS server.', 128),
    sni: stringValue(record.sni, 'Invalid TLS SNI.'),
    ...(optionalStringValue(record.version, 'Invalid TLS version.', 64) ? { version: record.version as string } : {}),
    ...(optionalStringValue(record.ja3, 'Invalid TLS JA3.', 256) ? { ja3: record.ja3 as string } : {}),
    ...(optionalStringValue(record.certificateSubject, 'Invalid TLS certificate subject.') ? { certificateSubject: record.certificateSubject as string } : {}),
    riskLevel: (() => {
      const risk = stringValue(record.riskLevel, 'Invalid TLS risk level.', 16);
      if (!severities.has(risk)) throw new InvestigationValidationError('Invalid TLS risk level.');
      return risk as InvestigationTlsEvidence['riskLevel'];
    })(),
  }));
  if (dns.length + http.length + tls.length > protocolLimit) throw new InvestigationValidationError('Too many protocol evidence records.', 413);

  const limitsValue = objectValue(evidence.limitsApplied, 'Investigation limit metadata is required.');
  const limitsApplied = {
    flowsTruncated: limitsValue.flowsTruncated === true,
    eventsTruncated: limitsValue.eventsTruncated === true,
    protocolRecordsTruncated: limitsValue.protocolRecordsTruncated === true,
  };

  const allIds = [signal.id, ...flows.map(item => item.id), ...events.map(item => item.id), ...dns.map(item => item.id), ...http.map(item => item.id), ...tls.map(item => item.id)];
  if (new Set(allIds).size !== allIds.length || !flowIds.has(signalFlowIds[0])) {
    throw new InvestigationValidationError('Investigation evidence IDs must be unique and internally consistent.');
  }

  return { version: '1', signal, flows, events, dns, http, tls, limitsApplied };
}

export function evidenceIds(packet: InvestigationEvidencePacket): Set<string> {
  return new Set([
    packet.signal.id,
    ...packet.flows.map(item => item.id),
    ...packet.events.map(item => item.id),
    ...packet.dns.map(item => item.id),
    ...packet.http.map(item => item.id),
    ...packet.tls.map(item => item.id),
  ]);
}

export function investigationPacketIdentity(packet: InvestigationEvidencePacket): string {
  return deterministicId('investigation-packet', [JSON.stringify(packet)]);
}

function outputText(value: unknown, message: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_INVESTIGATION_TEXT_CHARACTERS) {
    throw new InvestigationValidationError(message);
  }
  return value;
}

export function validateInvestigationAssessment(value: unknown, allowedEvidenceIds: ReadonlySet<string>): InvestigationAssessment {
  const root = objectValue(value, 'AI investigation response is malformed.');
  const summary = outputText(root.summary, 'AI investigation summary is malformed.');
  const observed = recordArray(root.observedEvidence, 'AI observed evidence is malformed.', MAX_INVESTIGATION_OUTPUT_ITEMS)
    .map(item => ({
      statement: outputText(item.statement, 'AI observed evidence statement is malformed.'),
      evidenceIds: orderedUnique(
        stringArray(item.evidenceIds, 'AI evidence citations are malformed.', MAX_INVESTIGATION_OUTPUT_ITEMS).filter(id => allowedEvidenceIds.has(id)),
        id => id,
      ),
    }))
    .filter(item => item.evidenceIds.length > 0);
  const inferences = recordArray(root.inferences, 'AI inferences are malformed.', MAX_INVESTIGATION_OUTPUT_ITEMS)
    .map(item => {
      const confidence = stringValue(item.confidence, 'AI inference confidence is malformed.', 16);
      if (!confidences.has(confidence)) throw new InvestigationValidationError('AI inference confidence is malformed.');
      return {
        statement: outputText(item.statement, 'AI inference statement is malformed.'),
        confidence: confidence as 'low' | 'medium' | 'high',
        evidenceIds: orderedUnique(
          stringArray(item.evidenceIds, 'AI inference citations are malformed.', MAX_INVESTIGATION_OUTPUT_ITEMS).filter(id => allowedEvidenceIds.has(id)),
          id => id,
        ),
      };
    })
    .filter(item => item.evidenceIds.length > 0);
  if (!Array.isArray(root.uncertainties) || root.uncertainties.length > MAX_INVESTIGATION_OUTPUT_ITEMS) {
    throw new InvestigationValidationError('AI uncertainties are malformed.');
  }
  const uncertainties = root.uncertainties.map(item => outputText(item, 'AI uncertainty is malformed.'));
  const nextSteps = recordArray(root.nextSteps, 'AI next steps are malformed.', MAX_INVESTIGATION_OUTPUT_ITEMS).map(item => ({
    action: outputText(item.action, 'AI next-step action is malformed.'),
    reason: outputText(item.reason, 'AI next-step reason is malformed.'),
  }));
  return { summary, observedEvidence: observed, inferences, uncertainties, nextSteps };
}

export function resolveCitedFlow(evidenceId: string, packet: InvestigationEvidencePacket, flows: readonly FlowSummary[]): FlowSummary | undefined {
  if (!packet.flows.some(flow => flow.id === evidenceId)) return undefined;
  return flows.find(flow => flow.id === evidenceId);
}
