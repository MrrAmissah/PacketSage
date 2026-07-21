import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { commandCenterLimitation, commandCenterNextActions, recordedHostnames } from '../src/lib/commandCenterPresentation';
import { eventsForFlow, flowsForEvent, hasSameObservedFlowIdentity, signalsForEvent, signalsForFlow } from '../src/lib/evidenceRelationships';
import { createJudgePathSession, deriveJudgePathProgress } from '../src/lib/judgePath';
import { EvidenceParseError, parseTextLog, type ParsedResult } from '../src/lib/parser';
import { buildProtocolFlags, buildProtocolInventory } from '../src/lib/protocolPresentation';
import type { DnsRecord, FlowSummary, HttpRecord, PacketEvent, ProtocolStat, SuspiciousSignal, TlsRecord } from '../src/types';

const root = new URL('../', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, root), 'utf8');

function event(id: string, overrides: Partial<PacketEvent> = {}): PacketEvent {
  return { id, timestamp: '2026-07-21T12:00:00.000Z', sourceIp: '10.0.0.15', sourcePort: 50_000, destinationIp: '203.0.113.80', destinationPort: 4444, protocol: 'TCP', length: 128, info: '[SYN]', ...overrides };
}

function flow(id: string, overrides: Partial<FlowSummary> = {}): FlowSummary {
  return { id, firstSeen: '2026-07-21T12:00:00.000Z', lastSeen: '2026-07-21T12:00:00.000Z', sourceIp: '10.0.0.15', sourcePort: 50_000, destinationIp: '203.0.113.80', destinationPort: 4444, protocol: 'TCP', packetCount: 1, byteCount: 128, duration: 0, direction: 'outbound', riskLevel: 'high', relatedEvents: [], ...overrides };
}

function signal(id: string, overrides: Partial<SuspiciousSignal> = {}): SuspiciousSignal {
  return { id, title: `Signal ${id}`, severity: 'medium', confidence: 'high', category: 'Test', observedEvidence: 'Observed record', interpretation: 'Requires review.', whatItDoesNotProve: 'Does not prove compromise.', recommendedDefensiveCheck: 'Validate independently.', ...overrides };
}

const dnsRecord: DnsRecord = { id: 'dns-1', relatedEventIds: ['evt-dns'], timestamp: '2026-07-21T12:00:00.000Z', clientIp: '10.0.0.15', query: 'example.test', queryType: 'A', response: '203.0.113.10', rcode: 'NOERROR', riskLevel: 'info' };
const httpRecord: HttpRecord = { id: 'http-1', relatedEventIds: ['evt-http'], timestamp: '2026-07-21T12:00:01.000Z', clientIp: '10.0.0.15', host: 'web.example', method: 'PATCH', uri: '/status', statusCode: 204, cleartext: true, riskLevel: 'info' };
const tlsRecord: TlsRecord = { id: 'tls-1', relatedEventIds: ['evt-tls'], timestamp: '2026-07-21T12:00:02.000Z', clientIp: '10.0.0.15', serverIp: '203.0.113.20', sni: 'secure.example', version: 'TLSv1.2', riskLevel: 'info' };
const tcpStat: ProtocolStat = { protocol: 'TCP', count: 1, percentage: 100, byteCount: 128, explanation: 'Observed TCP records.' };

function parsed(overrides: Partial<ParsedResult> = {}): ParsedResult {
  return {
    evidence: { id: 'evidence-1', name: 'custom.txt', type: 'txt', size: 128, uploadedAt: '2026-07-21T12:00:00.000Z', parseMode: 'txt', sourceFormat: 'Strict text', retentionMode: 'Ephemeral Memory', status: 'completed' },
    events: [], flows: [], dns: [], http: [], tls: [], signals: [], protocolStats: [], ...overrides,
  };
}

test('Protocol inventory for one TCP event contains only TCP facts', () => {
  assert.deepEqual(buildProtocolInventory([tcpStat], [], [], []).map(item => item.label), ['TCP']);
  assert.equal(buildProtocolInventory([tcpStat], [], [], [])[0].byteCount, 128);
});

test('Protocol inventory handles DNS-only input without HTTP or TLS records', () => {
  assert.deepEqual(buildProtocolInventory([], [dnsRecord], [], []).map(item => item.label), ['DNS']);
});

test('Protocol inventory handles HTTP-only input with the recorded method unchanged', () => {
  assert.deepEqual(buildProtocolInventory([], [], [httpRecord], []).map(item => item.label), ['HTTP']);
  assert.equal(httpRecord.method, 'PATCH');
});

test('Protocol inventory handles TLS-only input with no fixed TLS version', () => {
  assert.deepEqual(buildProtocolInventory([], [], [], [tlsRecord]).map(item => item.label), ['TLS']);
  assert.equal(tlsRecord.version, 'TLSv1.2');
});

test('No protocol records produces an honest empty inventory', () => {
  assert.deepEqual(buildProtocolInventory([], [], [], []), []);
});

test('Protocol flags appear only for source risk or DNS response flags', () => {
  assert.deepEqual(buildProtocolFlags([dnsRecord], [httpRecord], [tlsRecord]), []);
  assert.equal(buildProtocolFlags([{ ...dnsRecord, rcode: 'NXDOMAIN' }], [], []).length, 1);
});

test('Protocol Intelligence contains no legacy synthetic endpoint, port, or anomaly constants', () => {
  const code = source('src/components/ProtocolIntelligence.tsx');
  assert.doesNotMatch(code, /10\.0\.0\.15|203\.0\.113\.50|8080|Severe Repetitive Beacons|TLS_AES_/);
  assert.doesNotMatch(code, /\|\|\s*(?:[1-9]\d*|'[^']+')/);
});

test('Former text placeholder is rejected instead of inventing missing fields', () => {
  assert.throws(() => parseTextLog('legacy.txt', '10.0.0.15 to 203.0.113.80 port 4444 Protocol TCP'), (error: unknown) => error instanceof EvidenceParseError && /Line 1/.test(error.message));
});

test('Strict text accepts explicit source and destination ports', () => {
  const result = parseTextLog('strict.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 src_port=51234 dst_port=4444 protocol=TCP length=128');
  assert.equal(result.events[0].sourcePort, 51234);
  assert.equal(result.events[0].destinationPort, 4444);
});

test('Strict text preserves the supplied timestamp and omits unsupported service', () => {
  const result = parseTextLog('strict.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 dst_port=4444 protocol=TCP length=128');
  assert.equal(result.events[0].timestamp, '2026-07-21T12:00:00.000Z');
  assert.equal(result.events[0].sourcePort, 0);
  assert.equal(result.events[0].service, undefined);
  assert.equal(result.flows[0].service, undefined);
});

test('Strict text rejects missing required fields and arbitrary prose', () => {
  assert.throws(() => parseTextLog('missing.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 protocol=TCP length=128'), /dst_port is required/);
  assert.throws(() => parseTextLog('prose.txt', 'workstation contacted a remote host'), /Line 1/);
});

test('Strict text rejects malformed IP addresses', () => {
  assert.throws(() => parseTextLog('bad-ip.txt', '2026-07-21T12:00:00Z 10.0.0.999 -> 203.0.113.80 dst_port=4444 protocol=TCP length=128'), /valid IPv4/);
});

test('Strict text rejects malformed ports', () => {
  assert.throws(() => parseTextLog('bad-port.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 dst_port=70000 protocol=TCP length=128'), /dst_port/);
});

test('Strict text rejects protocol and port collisions', () => {
  assert.throws(() => parseTextLog('collision.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 dst_port=TCP protocol=4444 length=128'), /protocol must|dst_port must/);
});

test('Strict text output and deterministic IDs are stable', () => {
  const text = '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 src_port=51234 dst_port=4444 protocol=TCP length=128';
  assert.deepEqual(parseTextLog('stable.txt', text).events, parseTextLog('stable.txt', text).events);
});

test('Rejected text produces no partial ParsedResult', () => {
  let output: ParsedResult | undefined;
  assert.throws(() => { output = parseTextLog('mixed.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 dst_port=4444 protocol=TCP length=128\ninvalid prose'); });
  assert.equal(output, undefined);
});

test('Command Center actions do not prompt for a nonexistent signal', () => {
  const data = parsed({ events: [event('evt-1')], flows: [flow('flow-1')] });
  assert.deepEqual(commandCenterNextActions(data).map(action => action.destination), ['flows', 'timeline']);
});

test('Command Center records only evidence-backed hostnames', () => {
  assert.deepEqual(recordedHostnames(parsed({ dns: [dnsRecord], http: [httpRecord], tls: [tlsRecord] })), ['example.test', 'web.example', 'secure.example']);
  assert.deepEqual(recordedHostnames(parsed({ dns: [{ ...dnsRecord, query: 'unknown' }] })), []);
});

test('Command Center limitation wording is parse-mode specific', () => {
  assert.match(commandCenterLimitation('demo'), /Generated sample/);
  assert.doesNotMatch(commandCenterLimitation('txt'), /Generated sample/);
  assert.match(commandCenterLimitation('pcap'), /bounded browser decoder/);
});

test('Command Center source contains no fixed desktop identity or unsupported methods and state', () => {
  const code = source('src/components/CommandCenter.tsx');
  assert.doesNotMatch(code, /DESKTOP-25KH|HTTP POST|TLSv1\.3 handshake|connection established/);
});

test('Flow event resolution follows only flow.relatedEvents and preserves order', () => {
  const events = [event('evt-1'), event('evt-2'), event('evt-3')];
  assert.deepEqual(eventsForFlow(flow('flow-1', { relatedEvents: ['evt-2', 'evt-1'] }), events).map(item => item.id), ['evt-2', 'evt-1']);
});

test('Missing flow event IDs and shared IPs do not create relationships', () => {
  const sameIp = event('evt-1');
  assert.deepEqual(eventsForFlow(flow('flow-1', { relatedEvents: ['missing'] }), [sameIp]), []);
  assert.deepEqual(eventsForFlow(flow('flow-1'), [sameIp]), []);
});

test('Signals link to flows only through exact relatedFlowIds', () => {
  const signals = [signal('sig-exact', { relatedFlowIds: ['flow-1'] }), signal('sig-other', { relatedFlowIds: ['flow-2'] })];
  assert.deepEqual(signalsForFlow('flow-1', signals).map(item => item.id), ['sig-exact']);
});

test('High flow risk never creates a linked signal', () => {
  assert.deepEqual(signalsForFlow(flow('flow-high').id, []), []);
});

test('Flow Explorer contains no fabricated endpoint identity or connection state', () => {
  const code = source('src/components/FlowExplorer.tsx');
  assert.doesNotMatch(code, /finance-pc|db-prod|SYN_SENT|ESTABLISHED|closed_by_reset|Add this flow to report/);
});

test('Timeline resolves exact event-to-flow and event-to-signal relationships', () => {
  const flows = [flow('flow-1', { relatedEvents: ['evt-1'] }), flow('flow-2', { relatedEvents: ['evt-2'] })];
  const signals = [signal('sig-1', { relatedEventIds: ['evt-1'] }), signal('sig-2', { relatedEventIds: ['evt-2'] })];
  assert.deepEqual(flowsForEvent('evt-1', flows).map(item => item.id), ['flow-1']);
  assert.deepEqual(signalsForEvent('evt-1', signals).map(item => item.id), ['sig-1']);
});

test('Shared IP, prose, and protocol cannot create Timeline relationships', () => {
  assert.deepEqual(flowsForEvent('evt-unrelated', [flow('flow-1')]), []);
  assert.deepEqual(signalsForEvent('evt-unrelated', [signal('sig-1', { observedEvidence: 'evt-unrelated TCP 10.0.0.15' })]), []);
});

test('Full observed flow identity distinguishes ports and protocol', () => {
  const observed = event('evt-1');
  assert.equal(hasSameObservedFlowIdentity(observed, flow('same')), true);
  assert.equal(hasSameObservedFlowIdentity(observed, flow('port', { destinationPort: 443 })), false);
  assert.equal(hasSameObservedFlowIdentity(observed, flow('protocol', { protocol: 'UDP' })), false);
});

test('Timeline contains no synthetic flow or orphan report state', () => {
  const code = source('src/components/IncidentTimeline.tsx');
  assert.doesNotMatch(code, /temp-|localStorage|Add event to report|packet_sage_timeline_reports/);
});

test('Flow and Timeline report controls are completely removed', () => {
  const code = `${source('src/components/FlowExplorer.tsx')}\n${source('src/components/IncidentTimeline.tsx')}`;
  assert.doesNotMatch(code, /Add this flow to report|Add event to report|Added to report/);
});

test('Report print CSS hides shell and releases viewport clipping', () => {
  const css = source('src/index.css');
  assert.match(css, /@media print/);
  assert.match(css, /#packet-sage-workspace > aside/);
  assert.match(css, /\[data-testid="guided-sample-journey"\]/);
  assert.match(css, /overflow: visible !important/);
  assert.match(css, /height: auto !important/);
});

test('Report document includes early and late print markers and final sections', () => {
  const code = source('src/components/ReportBuilder.tsx');
  assert.match(code, /data-report-marker="early"/);
  assert.match(code, /data-report-marker="late"/);
  assert.match(code, /Provenance and limitations/);
  assert.match(code, /End of PacketSage evidence report draft/);
});

test('PDF verification script checks PDF validity, shell absence, late content, and multiple events', () => {
  const code = source('scripts/verify-report-pdf.mjs');
  assert.match(code, /%PDF/);
  assert.match(code, /Application navigation leaked/);
  assert.match(code, /Late report marker/);
  assert.match(code, /eventIds\.size > 8/);
});

test('Non-recommended signal selection does not complete guided review', () => {
  const progress = deriveJudgePathProgress({ evidenceLoaded: true, recommendedSignalId: 'sig-a', selectedSignalId: 'sig-b', includedInvestigationSignalIds: [], reportVisitedAfterInclusion: false });
  assert.equal(progress.stages.find(stage => stage.id === 'signal')?.complete, false);
});

test('Visiting Report Builder before inclusion does not complete report progress', () => {
  const progress = deriveJudgePathProgress({ evidenceLoaded: true, recommendedSignalId: 'sig-a', selectedSignalId: 'sig-a', includedInvestigationSignalIds: [], reportVisitedAfterInclusion: true });
  assert.equal(progress.stages.find(stage => stage.id === 'report')?.complete, false);
});

test('Completed but excluded investigation does not advance inclusion', () => {
  const progress = deriveJudgePathProgress({ evidenceLoaded: true, recommendedSignalId: 'sig-a', selectedSignalId: 'sig-a', includedInvestigationSignalIds: [], reportVisitedAfterInclusion: false });
  assert.equal(progress.stages.find(stage => stage.id === 'investigation')?.complete, false);
});

test('Only the recommended included investigation advances the guide', () => {
  const wrong = deriveJudgePathProgress({ evidenceLoaded: true, recommendedSignalId: 'sig-a', selectedSignalId: 'sig-a', includedInvestigationSignalIds: ['sig-b'], reportVisitedAfterInclusion: false });
  const correct = deriveJudgePathProgress({ evidenceLoaded: true, recommendedSignalId: 'sig-a', selectedSignalId: 'sig-a', includedInvestigationSignalIds: ['sig-a'], reportVisitedAfterInclusion: false });
  assert.equal(wrong.completedCount, 2);
  assert.equal(correct.completedCount, 3);
});

test('Report completes only after recommended inclusion and a later report visit', () => {
  const progress = deriveJudgePathProgress({ evidenceLoaded: true, recommendedSignalId: 'sig-a', selectedSignalId: 'sig-a', includedInvestigationSignalIds: ['sig-a'], reportVisitedAfterInclusion: true });
  assert.equal(progress.completedCount, 4);
});

test('Evidence replacement resets deterministic guided identities', () => {
  assert.deepEqual(createJudgePathSession('evidence-new'), { evidenceIdentity: 'evidence-new', dismissed: false, selectedSignalId: null, reportVisitedAfterInclusion: false });
});

test('Primary rows, cards, and Packet Academy modules expose keyboard operation', () => {
  assert.match(source('src/components/SuspiciousSignals.tsx'), /aria-label={`Review signal/);
  assert.match(source('src/components/FlowExplorer.tsx'), /onKeyDown={event => selectFromKeyboard/);
  assert.match(source('src/components/IncidentTimeline.tsx'), /<button type="button" onClick=\{\(\) => setSelectedEventId/);
  assert.match(source('src/components/LearningMode.tsx'), /activateWithKeyboard/);
});

test('Report Preview implements named dialog, focus trap, Escape, and focus return', () => {
  const code = source('src/components/ReportBuilder.tsx');
  assert.match(code, /aria-labelledby="report-preview-title"/);
  assert.match(code, /event\.key === 'Escape'/);
  assert.match(code, /event\.key !== 'Tab'/);
  assert.match(code, /previewTriggerRef\.current\?\.focus/);
});

test('Theme and mobile navigation controls have accessible names', () => {
  const code = source('src/App.tsx');
  assert.match(code, /aria-label={`Use \$\{t\.label\.toLowerCase\(\)\} theme`}/);
  assert.match(code, /aria-controls="primary-navigation"/);
  assert.match(code, /aria-current={isActive \? 'page'/);
});

test('Narrow navigation uses an explicit labelled menu instead of horizontal swipe discovery', () => {
  const code = source('src/App.tsx');
  assert.match(code, /Open primary navigation/);
  assert.match(code, /mobileNavOpen \? 'grid' : 'hidden'/);
  assert.doesNotMatch(code, /<nav[^>]+overflow-x-auto/);
});
