import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {
  buildInvestigationEvidencePacket,
  evidenceIds,
  InvestigationValidationError,
  resolveCitedFlow,
  validateInvestigationRequest,
} from '../src/lib/investigation';
import {
  MAX_INVESTIGATION_EVENTS,
  MAX_INVESTIGATION_FLOWS,
  MAX_INVESTIGATION_REQUEST_BYTES,
} from '../src/lib/limits';
import {
  clientSafeInvestigationError,
  createOpenAiInvestigationRequest,
  InvestigationServiceError,
  OPENAI_INVESTIGATION_MODEL,
  requestOpenAiInvestigation,
} from '../src/server/investigationApi';
import type { FlowSummary, InvestigationAssessment, PacketEvent, SuspiciousSignal } from '../src/types';

const timestamp = '2026-07-20T09:00:00.000Z';

function event(id: string, overrides: Partial<PacketEvent> = {}): PacketEvent {
  return {
    id,
    timestamp,
    sourceIp: '10.0.0.5',
    sourcePort: 50_000,
    destinationIp: '198.51.100.20',
    destinationPort: 443,
    protocol: 'TCP',
    service: 'HTTPS',
    length: 96,
    info: 'metadata omitted from investigation packet',
    sourceType: 'tshark',
    ...overrides,
  };
}

function flow(id: string, relatedEvents: string[] = [], overrides: Partial<FlowSummary> = {}): FlowSummary {
  return {
    id,
    firstSeen: timestamp,
    lastSeen: timestamp,
    sourceIp: '10.0.0.5',
    sourcePort: 50_000,
    destinationIp: '198.51.100.20',
    destinationPort: 443,
    protocol: 'TCP',
    service: 'HTTPS',
    packetCount: relatedEvents.length || 1,
    byteCount: 96,
    duration: 0,
    direction: 'outbound',
    riskLevel: 'medium',
    relatedEvents,
    ...overrides,
  };
}

function signal(relatedFlowIds?: string[]): SuspiciousSignal {
  return {
    id: 'sig-real-1',
    title: 'Repeated outbound connections',
    severity: 'medium',
    confidence: 'medium',
    category: 'Repeated outbound activity',
    observedEvidence: 'Four related connections were observed.',
    interpretation: 'The pattern requires validation against expected software behavior.',
    whatItDoesNotProve: 'This does not confirm malicious activity.',
    recommendedDefensiveCheck: 'Verify destination ownership and source process telemetry.',
    relatedFlowIds,
  };
}

function packetFixture() {
  const includedEvent = event('evt-related');
  const includedFlow = flow('flow-related', [includedEvent.id]);
  const packet = buildInvestigationEvidencePacket(signal([includedFlow.id]), {
    flows: [includedFlow],
    events: [includedEvent],
    dns: [],
    http: [],
    tls: [],
  });
  assert.ok(packet);
  return { packet, includedFlow, includedEvent };
}

function assessment(overrides: Partial<InvestigationAssessment> = {}): InvestigationAssessment {
  return {
    summary: 'The supplied records show a repeated outbound pattern. Intent is not confirmed.',
    observedEvidence: [{ statement: 'One related flow was supplied.', evidenceIds: ['flow-related'] }],
    inferences: [{ statement: 'The activity may be automated.', confidence: 'low', evidenceIds: ['flow-related'] }],
    uncertainties: ['The source process is not present in network metadata.'],
    nextSteps: [{ action: 'Review endpoint telemetry.', reason: 'Confirm which process opened the connection.' }],
    ...overrides,
  };
}

function openAiResponse(value: unknown): Response {
  return new Response(JSON.stringify({
    output: [{ type: 'message', content: [{ type: 'output_text', text: JSON.stringify(value) }] }],
  }), { status: 200, headers: { 'content-type': 'application/json' } });
}

test('evidence packet includes only the selected signal valid related flows', () => {
  const valid = flow('flow-real-capture-9', ['evt-valid']);
  const unrelated = flow('flow-unrelated', ['evt-unrelated']);
  const packet = buildInvestigationEvidencePacket(signal([valid.id]), {
    flows: [unrelated, valid],
    events: [event('evt-valid'), event('evt-unrelated')],
    dns: [],
    http: [],
    tls: [],
  });

  assert.deepEqual(packet?.flows.map(item => item.id), ['flow-real-capture-9']);
  assert.ok(!JSON.stringify(packet).includes('flow-unrelated'));
});

test('referenced events are included only through valid related flow relationships', () => {
  const valid = flow('flow-valid', ['evt-valid', 'evt-missing']);
  const packet = buildInvestigationEvidencePacket(signal([valid.id]), {
    flows: [valid, flow('flow-other', ['evt-other'])],
    events: [event('evt-valid'), event('evt-other')],
    dns: [],
    http: [],
    tls: [],
  });

  assert.deepEqual(packet?.events.map(item => item.id), ['evt-valid']);
  assert.deepEqual(packet?.flows[0].relatedEventIds, ['evt-valid']);
  assert.ok(!JSON.stringify(packet).includes('evt-other'));
  assert.ok(!JSON.stringify(packet).includes('evt-missing'));
});

test('missing relatedFlowIds produces no investigation packet', () => {
  assert.equal(buildInvestigationEvidencePacket(signal(undefined), { flows: [flow('flow-first')], events: [], dns: [], http: [], tls: [] }), null);
  assert.equal(buildInvestigationEvidencePacket(signal([]), { flows: [flow('flow-first')], events: [], dns: [], http: [], tls: [] }), null);
});

test('partially missing related flow IDs use only the ordered valid intersection', () => {
  const second = flow('flow-second');
  const first = flow('flow-first');
  const packet = buildInvestigationEvidencePacket(signal(['missing', second.id, first.id]), {
    flows: [first, second], events: [], dns: [], http: [], tls: [],
  });
  assert.deepEqual(packet?.flows.map(item => item.id), ['flow-second', 'flow-first']);
  assert.deepEqual(packet?.signal.relatedFlowIds, ['flow-second', 'flow-first']);
});

test('direct protocol records require an exact relationship to included events', () => {
  const dnsEvent = event('evt-dns', { destinationPort: 53, service: 'DNS', protocol: 'UDP' });
  const packet = buildInvestigationEvidencePacket(signal(['flow-dns']), {
    flows: [flow('flow-dns', [dnsEvent.id], { destinationPort: 53, service: 'DNS', protocol: 'UDP' })],
    events: [dnsEvent],
    dns: [
      { id: 'dns-valid', timestamp, clientIp: '10.0.0.5', query: 'example.test', queryType: 'A', response: 'Pending', rcode: '0', riskLevel: 'info' },
      { id: 'dns-unrelated', timestamp: '2026-07-20T10:00:00.000Z', clientIp: '10.0.0.5', query: 'unrelated.test', queryType: 'A', response: 'Pending', rcode: '0', riskLevel: 'info' },
    ],
    http: [],
    tls: [],
  });
  assert.deepEqual(packet?.dns.map(item => item.id), ['dns-valid']);
});

test('evidence packet record and byte limits are enforced', () => {
  const flows = Array.from({ length: MAX_INVESTIGATION_FLOWS + 3 }, (_, index) => flow(`flow-${index}`, [`evt-${index}`]));
  const events = Array.from({ length: MAX_INVESTIGATION_EVENTS + 3 }, (_, index) => event(`evt-${index}`));
  const packet = buildInvestigationEvidencePacket(signal(flows.map(item => item.id)), { flows, events, dns: [], http: [], tls: [] });
  assert.equal(packet?.flows.length, MAX_INVESTIGATION_FLOWS);
  assert.equal(packet?.limitsApplied.flowsTruncated, true);

  const oversized = { evidence: { padding: 'x'.repeat(MAX_INVESTIGATION_REQUEST_BYTES) } };
  assert.throws(
    () => validateInvestigationRequest(oversized),
    (error: unknown) => error instanceof InvestigationValidationError && error.status === 413,
  );
});

test('browser source does not reference the OpenAI credential name', () => {
  const roots = ['src/App.tsx', 'src/components', 'src/lib'];
  const files: string[] = [];
  const visit = (entry: string) => {
    const stats = statSync(entry);
    if (stats.isDirectory()) readdirSync(entry).forEach(name => visit(path.join(entry, name)));
    else if (/\.(ts|tsx)$/.test(entry)) files.push(entry);
  };
  roots.forEach(visit);
  files.forEach(file => assert.doesNotMatch(readFileSync(file, 'utf8'), /OPENAI_API_KEY/));
});

test('malformed and oversized investigation requests produce safe client errors', () => {
  for (const [body, status] of [[null, 400], [{ evidence: { padding: 'x'.repeat(MAX_INVESTIGATION_REQUEST_BYTES) } }, 413]] as const) {
    try {
      validateInvestigationRequest(body);
      assert.fail('Expected validation to fail.');
    } catch (error) {
      const safe = clientSafeInvestigationError(error);
      assert.equal(safe.status, status);
      assert.doesNotMatch(safe.message, /stack|environment|credential|api key/i);
    }
  }
});

test('OpenAI timeout and failure return safe errors with no fallback findings', async () => {
  const { packet } = packetFixture();
  const timeoutFetch: typeof fetch = async (_input, init) => new Promise<Response>((_resolve, reject) => {
    init?.signal?.addEventListener('abort', () => reject(new DOMException('timed out', 'AbortError')));
  });
  await assert.rejects(
    () => requestOpenAiInvestigation(packet, { apiKey: 'test-key', fetchImpl: timeoutFetch, timeoutMs: 5 }),
    (error: unknown) => error instanceof InvestigationServiceError && error.status === 504 && !('findings' in error),
  );

  const failureFetch: typeof fetch = async () => new Response(JSON.stringify({ error: { message: 'raw provider detail' } }), { status: 500 });
  try {
    await requestOpenAiInvestigation(packet, { apiKey: 'test-key', fetchImpl: failureFetch });
    assert.fail('Expected provider failure.');
  } catch (error) {
    const safe = clientSafeInvestigationError(error);
    assert.equal(safe.status, 503);
    assert.doesNotMatch(safe.message, /raw provider detail|fallback|finding/i);
  }
});

test('malformed model JSON is rejected safely', async () => {
  const { packet } = packetFixture();
  const fetchImpl: typeof fetch = async () => new Response(JSON.stringify({
    output: [{ content: [{ type: 'output_text', text: '{not-json' }] }],
  }), { status: 200 });
  await assert.rejects(
    () => requestOpenAiInvestigation(packet, { apiKey: 'test-key', fetchImpl }),
    (error: unknown) => error instanceof InvestigationServiceError && error.status === 503,
  );
});

test('unsupported model citations are removed without substituting evidence', async () => {
  const { packet } = packetFixture();
  const modelAssessment = assessment({
    observedEvidence: [
      { statement: 'Supported.', evidenceIds: ['flow-related', 'flow-unknown'] },
      { statement: 'Unsupported only.', evidenceIds: ['flow-unknown'] },
    ],
    inferences: [{ statement: 'Bounded inference.', confidence: 'low', evidenceIds: ['flow-unknown', 'evt-related'] }],
  });
  const result = await requestOpenAiInvestigation(packet, {
    apiKey: 'test-key',
    fetchImpl: async () => openAiResponse(modelAssessment),
  });
  assert.deepEqual(result.observedEvidence, [{ statement: 'Supported.', evidenceIds: ['flow-related'] }]);
  assert.deepEqual(result.inferences[0].evidenceIds, ['evt-related']);
  assert.ok(evidenceIds(packet).has(result.inferences[0].evidenceIds[0]));
});

test('OpenAI request uses the Responses API model contract without embedding credentials', () => {
  const { packet } = packetFixture();
  const request = createOpenAiInvestigationRequest(packet);
  assert.equal(request.model, OPENAI_INVESTIGATION_MODEL);
  assert.equal(request.model, 'gpt-5.6-sol');
  assert.equal((request.text as { format: { type: string } }).format.type, 'json_schema');
  assert.doesNotMatch(JSON.stringify(request), /test-key|OPENAI_API_KEY/);
});

test('cited flow resolution opens only an exact supplied flow ID', () => {
  const { packet, includedFlow } = packetFixture();
  const unrelated = flow('flow-first');
  assert.equal(resolveCitedFlow(includedFlow.id, packet, [unrelated, includedFlow])?.id, includedFlow.id);
  assert.equal(resolveCitedFlow('flow-unknown', packet, [unrelated, includedFlow]), undefined);
  assert.equal(resolveCitedFlow(unrelated.id, packet, [unrelated, includedFlow]), undefined);
});
