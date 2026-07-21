import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import FlowExplorer from '../src/components/FlowExplorer';
import IncidentTimeline from '../src/components/IncidentTimeline';
import { ReportDocument } from '../src/components/ReportBuilder';
import { parseCapture } from '../src/lib/capture';
import { buildInvestigationEvidencePacket, validateInvestigationRequest } from '../src/lib/investigation';
import {
  buildFlowsFromEvents,
  parseCsv,
  parseDemoData,
  parseSuricataEve,
  parseTextLog,
  parseTsharkJson,
  parseZeekLog,
} from '../src/lib/parser';
import { formatEndpoint, portIdentityPart } from '../src/lib/ports';
import { validateParsedResult } from '../src/lib/parseRequest';
import { buildReportModel, reportToMarkdown } from '../src/lib/report';
import { boundedCaptureSummary } from '../src/server/captureOverviewApi';
import { createOpenAiInvestigationRequest } from '../src/server/investigationApi';
import type { PacketEvent, SuspiciousSignal } from '../src/types';
import { nativeTcpPcap, nativeUdpPcap, rawIpv4Pcap } from './capture-fixtures';

const timestamp = '2026-07-21T12:00:00.000Z';

function tsharkPacket(layers: Record<string, unknown>) {
  return { _source: { layers: { frame: { 'frame.time_iso': timestamp, 'frame.len': '64' }, ip: { 'ip.src': '10.0.0.15', 'ip.dst': '203.0.113.80' }, ...layers } } };
}

function event(id: string, sourcePortState: PacketEvent['sourcePortState'], protocol = 'TCP'): PacketEvent {
  return {
    id,
    timestamp,
    sourceIp: '10.0.0.15',
    sourcePort: 0,
    sourcePortState,
    destinationIp: '203.0.113.80',
    destinationPort: sourcePortState === 'not-applicable' ? 0 : 443,
    destinationPortState: sourcePortState === 'not-applicable' ? 'not-applicable' : 'observed',
    protocol,
    length: 64,
    info: 'Recorded metadata',
  };
}

test('central endpoint formatting preserves observed zero', () => {
  assert.equal(formatEndpoint('10.0.0.15', 0, 'observed'), '10.0.0.15:0');
});

test('central endpoint formatting labels an unknown port', () => {
  assert.equal(formatEndpoint('10.0.0.15', 0, 'unknown'), '10.0.0.15:unknown');
});

test('central endpoint formatting omits an inapplicable port', () => {
  assert.equal(formatEndpoint('10.0.0.15', 0, 'not-applicable'), '10.0.0.15');
});

test('central endpoint formatting brackets IPv6 only when a suffix is present', () => {
  assert.equal(formatEndpoint('::1', 0, 'observed'), '[::1]:0');
  assert.equal(formatEndpoint('::1', 0, 'not-applicable'), '::1');
});

test('strict text marks an omitted source port unknown', () => {
  const parsed = parseTextLog('unknown.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 dst_port=443 protocol=TCP length=64');
  assert.deepEqual([parsed.events[0].sourcePort, parsed.events[0].sourcePortState], [0, 'unknown']);
});

test('strict text accepts explicit source port zero as observed', () => {
  const parsed = parseTextLog('zero.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 src_port=0 dst_port=443 protocol=TCP length=64');
  assert.deepEqual([parsed.events[0].sourcePort, parsed.events[0].sourcePortState], [0, 'observed']);
});

test('strict text keeps an explicit nonzero source port observed', () => {
  const parsed = parseTextLog('known.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 src_port=50000 dst_port=443 protocol=TCP length=64');
  assert.deepEqual([parsed.events[0].sourcePort, parsed.events[0].sourcePortState], [50000, 'observed']);
});

test('strict text accepts explicit destination port zero as observed', () => {
  const parsed = parseTextLog('zero.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 src_port=50000 dst_port=0 protocol=UDP length=64');
  assert.deepEqual([parsed.events[0].destinationPort, parsed.events[0].destinationPortState], [0, 'observed']);
});

test('CSV distinguishes explicit zero from an absent transport port', () => {
  const zero = parseCsv('zero.csv', 'source,source port,destination,destination port,protocol,length\n10.0.0.15,0,203.0.113.80,443,TCP,64');
  const absent = parseCsv('absent.csv', 'source,destination,destination port,protocol,length\n10.0.0.15,203.0.113.80,443,TCP,64');
  assert.equal(zero.events[0].sourcePortState, 'observed');
  assert.equal(absent.events[0].sourcePortState, 'unknown');
});

test('CSV marks ICMP ports not applicable', () => {
  const parsed = parseCsv('icmp.csv', 'source,destination,protocol,length\n10.0.0.15,203.0.113.80,ICMP,64');
  assert.deepEqual([parsed.events[0].sourcePortState, parsed.events[0].destinationPortState], ['not-applicable', 'not-applicable']);
});

test('Suricata distinguishes explicit zero from an absent transport port', () => {
  const zero = parseSuricataEve('zero.json', JSON.stringify({ timestamp, src_ip: '10.0.0.15', src_port: 0, dest_ip: '203.0.113.80', dest_port: 443, proto: 'TCP' }));
  const absent = parseSuricataEve('absent.json', JSON.stringify({ timestamp, src_ip: '10.0.0.15', dest_ip: '203.0.113.80', dest_port: 443, proto: 'TCP' }));
  assert.equal(zero.events[0].sourcePortState, 'observed');
  assert.equal(absent.events[0].sourcePortState, 'unknown');
});

test('Suricata marks ICMP ports not applicable', () => {
  const parsed = parseSuricataEve('icmp.json', JSON.stringify({ timestamp, src_ip: '10.0.0.15', dest_ip: '203.0.113.80', proto: 'ICMP' }));
  assert.equal(parsed.events[0].sourcePortState, 'not-applicable');
  assert.equal(parsed.events[0].destinationPortState, 'not-applicable');
});

test('Zeek distinguishes explicit zero from its missing-value marker', () => {
  const header = '#path conn\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto';
  const parsed = parseZeekLog('conn.log', `${header}\n1716285600\t10.0.0.15\t0\t203.0.113.80\t-\ttcp`);
  assert.equal(parsed.events[0].sourcePortState, 'observed');
  assert.equal(parsed.events[0].destinationPortState, 'unknown');
});

test('Zeek marks ICMP ports not applicable', () => {
  const parsed = parseZeekLog('conn.log', '#path conn\n#fields\tts\tid.orig_h\tid.resp_h\tproto\n1716285600\t10.0.0.15\t203.0.113.80\ticmp');
  assert.equal(parsed.events[0].sourcePortState, 'not-applicable');
});

test('TShark distinguishes explicit TCP zero from an absent TCP port', () => {
  const zero = parseTsharkJson('zero.json', JSON.stringify([tsharkPacket({ tcp: { 'tcp.srcport': '0', 'tcp.dstport': '443' } })]));
  const absent = parseTsharkJson('absent.json', JSON.stringify([tsharkPacket({ tcp: { 'tcp.dstport': '443' } })]));
  assert.equal(zero.events[0].sourcePortState, 'observed');
  assert.equal(absent.events[0].sourcePortState, 'unknown');
});

test('TShark marks ICMP ports not applicable', () => {
  const parsed = parseTsharkJson('icmp.json', JSON.stringify([tsharkPacket({ icmp: { 'icmp.type': '8' } })]));
  assert.deepEqual([parsed.events[0].sourcePortState, parsed.events[0].destinationPortState], ['not-applicable', 'not-applicable']);
});

test('TShark marks unsupported IP records not applicable', () => {
  const parsed = parseTsharkJson('ip.json', JSON.stringify([tsharkPacket({})]));
  assert.equal(parsed.events[0].protocol, 'IP');
  assert.equal(parsed.events[0].sourcePortState, 'not-applicable');
});

test('native TCP preserves literal port zero as observed', async () => {
  const parsed = await parseCapture('zero.pcap', nativeTcpPcap(0, 443));
  assert.deepEqual([parsed.events[0].sourcePort, parsed.events[0].sourcePortState], [0, 'observed']);
});

test('native UDP preserves literal port zero as observed', async () => {
  const parsed = await parseCapture('zero.pcap', nativeUdpPcap(50000, 0));
  assert.deepEqual([parsed.events[0].destinationPort, parsed.events[0].destinationPortState], [0, 'observed']);
});

test('native ICMP ports are not applicable', async () => {
  const parsed = await parseCapture('icmp.pcap', rawIpv4Pcap(1, new Uint8Array([8, 0, 0, 0])));
  assert.deepEqual([parsed.events[0].sourcePortState, parsed.events[0].destinationPortState], ['not-applicable', 'not-applicable']);
});

test('native non-initial fragments are not applicable', async () => {
  const parsed = await parseCapture('fragment.pcap', rawIpv4Pcap(6, new Uint8Array(), 1));
  assert.equal(parsed.events[0].protocol, 'IPv4 fragment');
  assert.equal(parsed.events[0].sourcePortState, 'not-applicable');
});

test('flow grouping does not collapse observed-zero and unknown transport ports', () => {
  assert.equal(buildFlowsFromEvents([event('evt-observed', 'observed'), event('evt-unknown', 'unknown')]).length, 2);
});

test('portless records do not collapse into observed-zero or unknown transport flows', () => {
  assert.equal(buildFlowsFromEvents([event('evt-observed', 'observed'), event('evt-unknown', 'unknown'), event('evt-na', 'not-applicable', 'ICMP')]).length, 3);
});

test('port identity encodes all ambiguous zero-valued states separately', () => {
  assert.equal(new Set(['observed', 'unknown', 'not-applicable'].map(state => portIdentityPart(0, state as PacketEvent['sourcePortState']))).size, 3);
});

test('ordinary observed nonzero identity input remains numeric', () => {
  assert.equal(portIdentityPart(443, 'observed'), 443);
});

test('guided sample deterministic identities remain unchanged', () => {
  const parsed = parseDemoData();
  assert.equal(parsed.evidence.id, 'evidence-1a8drws-1');
  assert.deepEqual(parsed.events.slice(0, 3).map(item => item.id), ['evt-0mgm3or-1', 'evt-0ke3dnq-1', 'evt-052a32b-1']);
  assert.deepEqual(parsed.flows.slice(0, 3).map(item => item.id), ['flow-0rtnruj-1', 'flow-0naypli-1', 'flow-08gxfuc-1']);
});

test('investigation packet serializes exact event and flow port states', () => {
  const events = [event('evt-zero', 'observed')];
  const flows = buildFlowsFromEvents(events);
  const signal: SuspiciousSignal = { id: 'sig-zero', title: 'Observed zero', severity: 'info', confidence: 'high', category: 'Review', observedEvidence: 'Literal port zero was recorded.', interpretation: 'Review context.', whatItDoesNotProve: 'No intent is established.', recommendedDefensiveCheck: 'Validate endpoint telemetry.', relatedFlowIds: [flows[0].id] };
  const packet = buildInvestigationEvidencePacket(signal, { flows, events, dns: [], http: [], tls: [] });
  assert.equal(packet?.events[0].sourcePortState, 'observed');
  assert.equal(packet?.flows[0].sourcePortState, 'observed');
  const request = createOpenAiInvestigationRequest(packet!);
  assert.match(JSON.stringify(request), /observed means the numeric port was supplied \(including zero\)/);
});

test('investigation request validation requires explicit port provenance', () => {
  const events = [event('evt-zero', 'observed')];
  const flows = buildFlowsFromEvents(events);
  const signal: SuspiciousSignal = { id: 'sig-zero', title: 'Observed zero', severity: 'info', confidence: 'high', category: 'Review', observedEvidence: 'Literal port zero was recorded.', interpretation: 'Review context.', whatItDoesNotProve: 'No intent is established.', recommendedDefensiveCheck: 'Validate endpoint telemetry.', relatedFlowIds: [flows[0].id] };
  const packet = buildInvestigationEvidencePacket(signal, { flows, events, dns: [], http: [], tls: [] })!;
  const invalid = structuredClone(packet) as unknown as { events: Array<Record<string, unknown>> };
  delete invalid.events[0].sourcePortState;
  assert.throws(() => validateInvestigationRequest({ evidence: invalid }), /port provenance/);
});

test('parsed-result validation rejects contradictory non-observed numeric ports', () => {
  const parsed = parseTextLog('known.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 src_port=50000 dst_port=443 protocol=TCP length=64');
  parsed.events[0].sourcePortState = 'unknown';
  assert.throws(() => validateParsedResult(parsed), /invalid port provenance/);
});

test('capture overview summary retains port provenance', () => {
  const parsed = parseTextLog('unknown.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 dst_port=443 protocol=TCP length=64');
  assert.equal(boundedCaptureSummary({ captureIdentity: parsed.evidence.id, flowSummary: parsed.flows }).flows[0].sourcePortState, 'unknown');
});

test('report model and Markdown preserve all three display states', () => {
  const parsed = parseTextLog('unknown.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 dst_port=443 protocol=TCP length=64');
  parsed.events.push(event('evt-zero', 'observed'), event('evt-na', 'not-applicable', 'ICMP'));
  const report = buildReportModel(parsed, []);
  const markdown = reportToMarkdown(report);
  assert.match(markdown, /10\.0\.0\.15:unknown/);
  assert.match(markdown, /10\.0\.0\.15:0/);
  assert.match(markdown, /10\.0\.0\.15 → 203\.0\.113\.80/);
});

test('screen Report Preview document preserves all three display states', () => {
  const parsed = parseTextLog('unknown.txt', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 dst_port=443 protocol=TCP length=64');
  parsed.events.push(event('evt-zero', 'observed'), event('evt-na', 'not-applicable', 'ICMP'));
  const markup = renderToStaticMarkup(React.createElement(ReportDocument, { report: buildReportModel(parsed, []) }));
  assert.match(markup, /10\.0\.0\.15:unknown/);
  assert.match(markup, /10\.0\.0\.15:0/);
  assert.match(markup, /10\.0\.0\.15.*203\.0\.113\.80/);
  assert.doesNotMatch(markup, /not-applicable/);
});

test('PDF verifier exercises standard and assessment-included three-state exports', () => {
  const verifier = readFileSync(new URL('../scripts/verify-report-pdf.mjs', import.meta.url), 'utf8');
  assert.match(verifier, /--port-provenance/);
  assert.match(verifier, /Observed literal port zero is missing from PDF output/);
  assert.match(verifier, /Portless source was rendered as an unknown transport port/);
  assert.match(verifier, /if \(includedAssessment\)/);
});

test('Flow Explorer renders truthful endpoint suffixes without sentinel language', () => {
  const events = [event('evt-zero', 'observed'), event('evt-unknown', 'unknown'), event('evt-na', 'not-applicable', 'ICMP')];
  const flows = buildFlowsFromEvents(events);
  const markup = renderToStaticMarkup(React.createElement(FlowExplorer, { flows, events, signals: [], onSelectFlow: () => undefined, selectedFlow: null, onCloseDrawer: () => undefined }));
  assert.match(markup, /10\.0\.0\.15:0/);
  assert.match(markup, /10\.0\.0\.15:unknown/);
  assert.doesNotMatch(markup, /not-applicable/);
});

test('Incident Timeline renders truthful endpoint suffixes without sentinel language', () => {
  const events = [event('evt-zero', 'observed'), event('evt-unknown', 'unknown'), event('evt-na', 'not-applicable', 'ICMP')];
  const markup = renderToStaticMarkup(React.createElement(IncidentTimeline, { events, flows: buildFlowsFromEvents(events), signals: [] }));
  assert.match(markup, /10\.0\.0\.15:0/);
  assert.match(markup, /10\.0\.0\.15:unknown/);
  assert.doesNotMatch(markup, /not-applicable/);
});
