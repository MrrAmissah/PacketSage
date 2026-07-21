import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import InvestigationAssessmentPanel from '../src/components/InvestigationAssessment';
import {
  buildInvestigationEvidencePacket,
  evidenceIds,
  investigationPacketIdentity,
  InvestigationValidationError,
  resolveCitedFlow,
  validateInvestigationApiResult,
  validateInvestigationRequest,
} from '../src/lib/investigation';
import {
  InvestigationRequestCoordinator,
  runInvestigationRequest,
  type InvestigationRequestContext,
} from '../src/lib/investigationRequests';
import {
  MAX_INVESTIGATION_EVENTS,
  MAX_INVESTIGATION_FLOWS,
  MAX_INVESTIGATION_PROTOCOL_RECORDS,
  MAX_INVESTIGATION_REQUEST_BYTES,
} from '../src/lib/limits';
import { parseDemoData } from '../src/lib/parser';
import {
  clientSafeInvestigationError,
  createOpenAiInvestigationRequest,
  InvestigationServiceError,
  OPENAI_INVESTIGATION_MODEL,
  requestOpenAiInvestigation,
} from '../src/server/investigationApi';
import investigateHandler from '../api/investigate';
import type { FlowSummary, InvestigationAssessment, PacketEvent, SuspiciousSignal } from '../src/types';

const timestamp = '2026-07-20T09:00:00.000Z';

function event(id: string, overrides: Partial<PacketEvent> = {}): PacketEvent {
  return {
    id,
    timestamp,
    sourceIp: '10.0.0.5',
    sourcePort: 50_000,
    sourcePortState: 'observed',
    destinationIp: '198.51.100.20',
    destinationPort: 443,
    destinationPortState: 'observed',
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
    sourcePortState: 'observed',
    destinationIp: '198.51.100.20',
    destinationPort: 443,
    destinationPortState: 'observed',
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

function openAiResponse(value: unknown, model = 'gpt-5.6-sol-2026-07-01'): Response {
  return new Response(JSON.stringify({
    model,
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
      { id: 'dns-valid', relatedEventIds: [dnsEvent.id], timestamp, clientIp: '10.0.0.5', query: 'example.test', queryType: 'A', response: 'Pending', rcode: '0', riskLevel: 'info' },
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

test('browser source does not reference either server credential name', () => {
  const roots = ['src/App.tsx', 'src/components', 'src/lib'];
  const files: string[] = [];
  const visit = (entry: string) => {
    const stats = statSync(entry);
    if (stats.isDirectory()) readdirSync(entry).forEach(name => visit(path.join(entry, name)));
    else if (/\.(ts|tsx)$/.test(entry)) files.push(entry);
  };
  roots.forEach(visit);
  files.forEach(file => assert.doesNotMatch(readFileSync(file, 'utf8'), /OPENAI_API_KEY|GEMINI_API_KEY/));
});

test('investigation request cannot supply provider or model selection', () => {
  const { packet } = packetFixture();
  assert.throws(
    () => validateInvestigationRequest({ evidence: packet, provider: 'client-provider', model: 'client-model' }),
    /unsupported fields/,
  );
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

test('Vercel investigation handler exposes the validated server-only endpoint', async () => {
  const { packet } = packetFixture();
  const originalApiKey = process.env.OPENAI_API_KEY;
  delete process.env.OPENAI_API_KEY;
  let statusCode = 0;
  let responseBody: unknown;
  const req = {
    method: 'POST',
    body: { evidence: packet },
    once() {},
    removeListener() {},
  };
  const res = {
    destroyed: false,
    writableEnded: false,
    once() {},
    removeListener() {},
    status(value: number) {
      statusCode = value;
      return this;
    },
    json(value: unknown) {
      responseBody = value;
      this.writableEnded = true;
      return this;
    },
  };

  try {
    await investigateHandler(req, res);
  } finally {
    if (originalApiKey === undefined) delete process.env.OPENAI_API_KEY;
    else process.env.OPENAI_API_KEY = originalApiKey;
  }

  assert.equal(statusCode, 503, JSON.stringify(responseBody));
  assert.deepEqual(responseBody, { error: 'AI-assisted investigation is unavailable. Try again later.' });
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

test('client abort signal cancels the upstream OpenAI request', async () => {
  const { packet } = packetFixture();
  const clientAbort = new AbortController();
  let upstreamSignal: AbortSignal | null = null;
  const fetchImpl: typeof fetch = async (_input, init) => {
    upstreamSignal = init?.signal || null;
    return new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
    });
  };
  const request = requestOpenAiInvestigation(packet, {
    apiKey: 'test-key',
    fetchImpl,
    signal: clientAbort.signal,
  });
  clientAbort.abort();
  await assert.rejects(
    request,
    (error: unknown) => error instanceof InvestigationServiceError && error.status === 504,
  );
  assert.equal(upstreamSignal?.aborted, true);
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

test('missing or malformed investigation provenance is rejected', async () => {
  const { packet } = packetFixture();
  const withoutModel: typeof fetch = async () => new Response(JSON.stringify({
    output: [{ content: [{ type: 'output_text', text: JSON.stringify(assessment()) }] }],
  }), { status: 200 });
  await assert.rejects(
    () => requestOpenAiInvestigation(packet, { apiKey: 'test-key', fetchImpl: withoutModel }),
    (error: unknown) => error instanceof InvestigationServiceError && error.status === 503,
  );
  assert.throws(
    () => validateInvestigationApiResult({ schemaVersion: '1', provider: '', model: 'model', assessment: assessment() }, evidenceIds(packet)),
    /provider provenance/,
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
  assert.equal(result.schemaVersion, '1');
  assert.equal(result.provider, 'OpenAI');
  assert.equal(result.model, 'gpt-5.6-sol-2026-07-01');
  assert.deepEqual(result.assessment.observedEvidence, [{ statement: 'Supported.', evidenceIds: ['flow-related'] }]);
  assert.deepEqual(result.assessment.inferences[0].evidenceIds, ['evt-related']);
  assert.ok(evidenceIds(packet).has(result.assessment.inferences[0].evidenceIds[0]));
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

test('successful structured response renders all four investigation sections', () => {
  const { packet, includedFlow } = packetFixture();
  const markup = renderToStaticMarkup(React.createElement(InvestigationAssessmentPanel, {
    assessment: assessment(),
    packet,
    flows: [includedFlow],
    onNavigateToFlows: () => undefined,
  }));
  assert.match(markup, /Observed evidence/);
  assert.match(markup, /Analyst inference/);
  assert.match(markup, /Uncertainty \/ missing evidence/);
  assert.match(markup, /Recommended next investigative steps/);
  assert.match(markup, /Not confirmed/);
  assert.match(markup, /Open exact flow flow-related/);
});

test('simultaneous DNS records use only explicit event relationships', () => {
  const includedEvent = event('evt-dns-included', { destinationPort: 53, service: 'DNS' });
  const excludedEvent = event('evt-dns-excluded', { destinationPort: 53, service: 'DNS' });
  const packet = buildInvestigationEvidencePacket(signal(['flow-dns']), {
    flows: [flow('flow-dns', [includedEvent.id])],
    events: [includedEvent, excludedEvent],
    dns: [
      { id: 'dns-included', relatedEventIds: [includedEvent.id], timestamp, clientIp: includedEvent.sourceIp, query: 'included.test', queryType: 'A', response: 'Pending', rcode: 'NOERROR', riskLevel: 'info' },
      { id: 'dns-colliding-unrelated', relatedEventIds: [excludedEvent.id], timestamp, clientIp: includedEvent.sourceIp, query: 'unrelated.test', queryType: 'A', response: 'Pending', rcode: 'NOERROR', riskLevel: 'info' },
    ],
    http: [],
    tls: [],
  });

  assert.deepEqual(packet?.dns.map(record => record.id), ['dns-included']);
  const serialized = JSON.stringify(packet);
  assert.doesNotMatch(serialized, /dns-colliding-unrelated|unrelated\.test|metadata omitted from investigation packet/);
});

test('simultaneous HTTP records use only explicit event relationships', () => {
  const includedEvent = event('evt-http-included', { destinationPort: 80, service: 'HTTP' });
  const excludedEvent = event('evt-http-excluded', { destinationPort: 80, service: 'HTTP' });
  const packet = buildInvestigationEvidencePacket(signal(['flow-http']), {
    flows: [flow('flow-http', [includedEvent.id])],
    events: [includedEvent, excludedEvent],
    dns: [],
    http: [
      { id: 'http-included', relatedEventIds: [includedEvent.id], timestamp, clientIp: includedEvent.sourceIp, host: 'included.test', method: 'GET', uri: '/one', statusCode: 200, cleartext: true, riskLevel: 'info' },
      { id: 'http-colliding-unrelated', relatedEventIds: [excludedEvent.id], timestamp, clientIp: includedEvent.sourceIp, host: 'unrelated.test', method: 'GET', uri: '/two', statusCode: 200, cleartext: true, riskLevel: 'info' },
    ],
    tls: [],
  });
  assert.deepEqual(packet?.http.map(record => record.id), ['http-included']);
});

test('simultaneous TLS records use only explicit event relationships', () => {
  const includedEvent = event('evt-tls-included');
  const excludedEvent = event('evt-tls-excluded');
  const packet = buildInvestigationEvidencePacket(signal(['flow-tls']), {
    flows: [flow('flow-tls', [includedEvent.id])],
    events: [includedEvent, excludedEvent],
    dns: [],
    http: [],
    tls: [
      { id: 'tls-included', relatedEventIds: [includedEvent.id], timestamp, clientIp: includedEvent.sourceIp, serverIp: includedEvent.destinationIp, sni: 'included.test', riskLevel: 'info' },
      { id: 'tls-colliding-unrelated', relatedEventIds: [excludedEvent.id], timestamp, clientIp: includedEvent.sourceIp, serverIp: includedEvent.destinationIp, sni: 'unrelated.test', riskLevel: 'info' },
    ],
  });
  assert.deepEqual(packet?.tls.map(record => record.id), ['tls-included']);
});

test('protocol records without explicit event relationships are omitted', () => {
  const includedEvent = event('evt-related');
  const packet = buildInvestigationEvidencePacket(signal(['flow-related']), {
    flows: [flow('flow-related', [includedEvent.id])],
    events: [includedEvent],
    dns: [{ id: 'dns-no-relation', timestamp, clientIp: includedEvent.sourceIp, query: 'same.test', queryType: 'A', response: 'Pending', rcode: 'NOERROR', riskLevel: 'info' }],
    http: [],
    tls: [],
  });
  assert.deepEqual(packet?.dns, []);
});

test('protocol records referencing nonexistent events are omitted', () => {
  const includedEvent = event('evt-related');
  const packet = buildInvestigationEvidencePacket(signal(['flow-related']), {
    flows: [flow('flow-related', [includedEvent.id])],
    events: [includedEvent],
    dns: [{ id: 'dns-missing-event', relatedEventIds: ['evt-missing'], timestamp, clientIp: includedEvent.sourceIp, query: 'missing.test', queryType: 'A', response: 'Pending', rcode: 'NOERROR', riskLevel: 'info' }],
    http: [],
    tls: [],
  });
  assert.deepEqual(packet?.dns, []);
});

test('server validation rejects protocol evidence without a surviving explicit event reference', () => {
  const { packet } = packetFixture();
  const invalid = {
    ...packet,
    dns: [{ id: 'dns-invalid', relatedEventIds: ['evt-missing'], timestamp, clientIp: '10.0.0.5', query: 'invalid.test', queryType: 'A', response: 'Pending', rcode: 'NOERROR', riskLevel: 'info' }],
  };
  assert.throws(
    () => validateInvestigationRequest({ evidence: invalid }),
    /DNS evidence must reference supplied events/,
  );
});

test('protocol records related only to an unselected flow are omitted', () => {
  const includedEvent = event('evt-included');
  const excludedEvent = event('evt-excluded');
  const packet = buildInvestigationEvidencePacket(signal(['flow-included']), {
    flows: [flow('flow-included', [includedEvent.id]), flow('flow-excluded', [excludedEvent.id])],
    events: [includedEvent, excludedEvent],
    dns: [{ id: 'dns-excluded-flow', relatedEventIds: [excludedEvent.id], timestamp, clientIp: excludedEvent.sourceIp, query: 'excluded.test', queryType: 'A', response: 'Pending', rcode: 'NOERROR', riskLevel: 'info' }],
    http: [],
    tls: [],
  });
  assert.deepEqual(packet?.dns, []);
});

test('protocol records whose related event is truncated are omitted', () => {
  const events = Array.from({ length: MAX_INVESTIGATION_EVENTS + 1 }, (_, index) => event(`evt-${index}`));
  const packet = buildInvestigationEvidencePacket(signal(['flow-many-events']), {
    flows: [flow('flow-many-events', events.map(item => item.id))],
    events,
    dns: [{ id: 'dns-truncated-event', relatedEventIds: [events.at(-1)!.id], timestamp, clientIp: events[0].sourceIp, query: 'truncated.test', queryType: 'A', response: 'Pending', rcode: 'NOERROR', riskLevel: 'info' }],
    http: [],
    tls: [],
  });
  assert.equal(packet?.limitsApplied.eventsTruncated, true);
  assert.deepEqual(packet?.dns, []);
});

test('multiple protocol event relationships retain only the surviving exact intersection', () => {
  const first = event('evt-first');
  const second = event('evt-second');
  const packet = buildInvestigationEvidencePacket(signal(['flow-first']), {
    flows: [flow('flow-first', [first.id])],
    events: [first, second],
    dns: [{ id: 'dns-multiple', relatedEventIds: [second.id, first.id, 'evt-missing', first.id], timestamp, clientIp: first.sourceIp, query: 'multiple.test', queryType: 'A', response: 'Pending', rcode: 'NOERROR', riskLevel: 'info' }],
    http: [],
    tls: [],
  });
  assert.deepEqual(packet?.dns[0].relatedEventIds, [first.id]);
});

test('protocol record limits apply after exact relationship filtering', () => {
  const includedEvent = event('evt-related');
  const unrelated = Array.from({ length: 10 }, (_, index) => ({
    id: `dns-unrelated-${index}`,
    relatedEventIds: ['evt-other'],
    timestamp,
    clientIp: includedEvent.sourceIp,
    query: `unrelated-${index}.test`,
    queryType: 'A',
    response: 'Pending',
    rcode: 'NOERROR',
    riskLevel: 'info' as const,
  }));
  const related = Array.from({ length: MAX_INVESTIGATION_PROTOCOL_RECORDS + 1 }, (_, index) => ({
    id: `dns-related-${index}`,
    relatedEventIds: [includedEvent.id],
    timestamp,
    clientIp: includedEvent.sourceIp,
    query: `related-${index}.test`,
    queryType: 'A',
    response: 'Pending',
    rcode: 'NOERROR',
    riskLevel: 'info' as const,
  }));
  const packet = buildInvestigationEvidencePacket(signal(['flow-related']), {
    flows: [flow('flow-related', [includedEvent.id])], events: [includedEvent], dns: [...unrelated, ...related], http: [], tls: [],
  });
  assert.equal(packet?.dns.length, MAX_INVESTIGATION_PROTOCOL_RECORDS);
  assert.equal(packet?.dns[0].id, 'dns-related-0');
  assert.equal(packet?.limitsApplied.protocolRecordsTruncated, true);
});

test('normal protocol collections remain available and deterministic relationships are stable', () => {
  const first = parseDemoData();
  const second = parseDemoData();
  assert.equal(first.dns.length, 19);
  assert.equal(first.http.length, 1);
  assert.equal(first.tls.length, 2);
  assert.ok([...first.dns, ...first.http, ...first.tls].every(record => record.relatedEventIds?.length));
  assert.deepEqual(
    [first.dns, first.http, first.tls].map(records => records.map(record => ({ id: record.id, relatedEventIds: record.relatedEventIds }))),
    [second.dns, second.http, second.tls].map(records => records.map(record => ({ id: record.id, relatedEventIds: record.relatedEventIds }))),
  );
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function requestContext(signalId: string, packetIdentity: string): InvestigationRequestContext {
  return { signalId, packetIdentity };
}

test('packet identity deterministically changes with effective evidence and truncation state', () => {
  const { packet } = packetFixture();
  assert.equal(investigationPacketIdentity(packet), investigationPacketIdentity(structuredClone(packet)));
  const variants = [
    { ...packet, signal: { ...packet.signal, id: 'sig-changed' } },
    { ...packet, flows: [{ ...packet.flows[0], id: 'flow-changed' }] },
    { ...packet, events: [{ ...packet.events[0], id: 'evt-changed' }] },
    { ...packet, dns: [{ id: 'dns-changed', relatedEventIds: [packet.events[0].id], timestamp, clientIp: '10.0.0.5', query: 'changed.test', queryType: 'A', response: 'Pending', rcode: 'NOERROR', riskLevel: 'info' as const }] },
    { ...packet, http: [{ id: 'http-changed', relatedEventIds: [packet.events[0].id], timestamp, clientIp: '10.0.0.5', host: 'changed.test', method: 'GET', uri: '/', statusCode: 200, cleartext: true, riskLevel: 'info' as const }] },
    { ...packet, tls: [{ id: 'tls-changed', relatedEventIds: [packet.events[0].id], timestamp, clientIp: '10.0.0.5', serverIp: '198.51.100.20', sni: 'changed.test', riskLevel: 'info' as const }] },
    { ...packet, limitsApplied: { ...packet.limitsApplied, eventsTruncated: true } },
  ];
  variants.forEach(variant => assert.notEqual(investigationPacketIdentity(variant), investigationPacketIdentity(packet)));
});

test('late success from signal A cannot replace signal B success', async () => {
  const coordinator = new InvestigationRequestCoordinator();
  let current: InvestigationRequestContext | null = requestContext('signal-a', 'packet-a');
  const a = deferred<string>();
  const tokenA = coordinator.begin(current)!;
  const outcomeA = runInvestigationRequest(coordinator, tokenA, () => current, () => a.promise);
  current = requestContext('signal-b', 'packet-b');
  const b = deferred<string>();
  const tokenB = coordinator.begin(current)!;
  const outcomeB = runInvestigationRequest(coordinator, tokenB, () => current, () => b.promise);
  b.resolve('assessment-b');
  assert.deepEqual(await outcomeB, { status: 'success', value: 'assessment-b' });
  a.resolve('assessment-a');
  assert.deepEqual(await outcomeA, { status: 'ignored' });
});

test('late failure from signal A cannot replace signal B success', async () => {
  const coordinator = new InvestigationRequestCoordinator();
  let current: InvestigationRequestContext | null = requestContext('signal-a', 'packet-a');
  const a = deferred<string>();
  const outcomeA = runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, () => a.promise);
  current = requestContext('signal-b', 'packet-b');
  const b = deferred<string>();
  const outcomeB = runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, () => b.promise);
  b.resolve('assessment-b');
  assert.equal((await outcomeB).status, 'success');
  a.reject(new Error('late failure'));
  assert.deepEqual(await outcomeA, { status: 'ignored' });
});

test('retry success remains after the invalidated first attempt completes', async () => {
  const coordinator = new InvestigationRequestCoordinator();
  const current = requestContext('signal-a', 'packet-a');
  const first = deferred<string>();
  const firstOutcome = runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, () => first.promise);
  coordinator.invalidate();
  const retry = deferred<string>();
  const retryOutcome = runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, () => retry.promise);
  retry.resolve('retry-success');
  assert.deepEqual(await retryOutcome, { status: 'success', value: 'retry-success' });
  first.resolve('stale-success');
  assert.deepEqual(await firstOutcome, { status: 'ignored' });
});

test('retry failure remains after the invalidated first attempt succeeds', async () => {
  const coordinator = new InvestigationRequestCoordinator();
  const current = requestContext('signal-a', 'packet-a');
  const first = deferred<string>();
  const firstOutcome = runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, () => first.promise);
  coordinator.invalidate();
  const retry = deferred<string>();
  const retryOutcome = runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, () => retry.promise);
  retry.reject(new Error('retry failure'));
  assert.equal((await retryOutcome).status, 'failure');
  first.resolve('stale-success');
  assert.deepEqual(await firstOutcome, { status: 'ignored' });
});

test('evidence changes invalidate and ignore an active completion', async () => {
  const coordinator = new InvestigationRequestCoordinator();
  let current: InvestigationRequestContext | null = requestContext('signal-a', 'packet-a');
  const pending = deferred<string>();
  const token = coordinator.begin(current)!;
  const outcome = runInvestigationRequest(coordinator, token, () => current, () => pending.promise);
  current = requestContext('signal-a', 'packet-b');
  coordinator.invalidate();
  pending.resolve('stale');
  assert.deepEqual(await outcome, { status: 'ignored' });
  assert.equal(token.controller.signal.aborted, true);
});

test('switching to a signal without evidence aborts and invalidates the request', async () => {
  const coordinator = new InvestigationRequestCoordinator();
  let current: InvestigationRequestContext | null = requestContext('signal-a', 'packet-a');
  const pending = deferred<string>();
  const token = coordinator.begin(current)!;
  const outcome = runInvestigationRequest(coordinator, token, () => current, () => pending.promise);
  current = null;
  coordinator.invalidate();
  pending.resolve('stale');
  assert.equal(token.controller.signal.aborted, true);
  assert.deepEqual(await outcome, { status: 'ignored' });
});

test('an aborted request does not become a visible failure', async () => {
  const coordinator = new InvestigationRequestCoordinator();
  const current = requestContext('signal-a', 'packet-a');
  const pending = deferred<string>();
  const outcome = runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, () => pending.promise);
  coordinator.invalidate();
  pending.reject(new DOMException('aborted', 'AbortError'));
  assert.deepEqual(await outcome, { status: 'ignored' });
});

test('duplicate starts for the same analysing packet produce one request', () => {
  const coordinator = new InvestigationRequestCoordinator();
  const current = requestContext('signal-a', 'packet-a');
  const first = coordinator.begin(current);
  const duplicate = coordinator.begin(current);
  assert.ok(first);
  assert.equal(duplicate, null);
  assert.equal(first.requestId, 1);
});

test('a completion with the correct signal but wrong packet identity is ignored', async () => {
  const coordinator = new InvestigationRequestCoordinator();
  let current: InvestigationRequestContext | null = requestContext('signal-a', 'packet-a');
  const pending = deferred<string>();
  const outcome = runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, () => pending.promise);
  current = requestContext('signal-a', 'packet-b');
  pending.resolve('wrong-packet');
  assert.deepEqual(await outcome, { status: 'ignored' });
});

test('a completion with an obsolete request identity is ignored', async () => {
  const coordinator = new InvestigationRequestCoordinator();
  const current = requestContext('signal-a', 'packet-a');
  const first = deferred<string>();
  const firstOutcome = runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, () => first.promise);
  coordinator.invalidate();
  const latestToken = coordinator.begin(current)!;
  first.resolve('obsolete');
  assert.deepEqual(await firstOutcome, { status: 'ignored' });
  assert.equal(latestToken.requestId, 2);
});

test('changing signals never displays the previous signal assessment', async () => {
  const coordinator = new InvestigationRequestCoordinator();
  let current: InvestigationRequestContext | null = requestContext('signal-a', 'packet-a');
  let displayed: string | null = null;
  const pending = deferred<string>();
  const outcomePromise = runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, () => pending.promise);
  current = requestContext('signal-b', 'packet-b');
  displayed = null;
  coordinator.invalidate();
  pending.resolve('assessment-a');
  const outcome = await outcomePromise;
  if (outcome.status === 'success') displayed = outcome.value;
  assert.equal(displayed, null);
  assert.deepEqual(outcome, { status: 'ignored' });
});

test('success, failure and retry settle normally when context remains current', async () => {
  const coordinator = new InvestigationRequestCoordinator();
  const current = requestContext('signal-a', 'packet-a');
  const success = await runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, async () => 'success');
  assert.deepEqual(success, { status: 'success', value: 'success' });
  const failure = await runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, async () => { throw new Error('failure'); });
  assert.equal(failure.status, 'failure');
  const retry = await runInvestigationRequest(coordinator, coordinator.begin(current)!, () => current, async () => 'retry-success');
  assert.deepEqual(retry, { status: 'success', value: 'retry-success' });
});
