import assert from 'node:assert/strict';
import test from 'node:test';
import { formatIpv6Hextets, parseCapture } from '../src/lib/capture';
import { MAX_CAPTURE_BYTES, MAX_TEXT_CHARACTERS } from '../src/lib/limits';
import {
  parseCsv,
  parseDemoData,
  parsePcapPlaceholder,
  parseSuricataEve,
  parseTextLog,
  parseTsharkJson,
  parseZeekLog,
} from '../src/lib/parser';
import { selectPresentedSignals } from '../src/lib/signalPresentation';
import { ParseRequestError, validateParseRequest } from '../src/lib/parseRequest';
import { resolveRelatedFlows } from '../src/lib/relatedFlows';
import type { FlowSummary } from '../src/types';
import { ipv6Pcap, validPcap, validPcapng } from './capture-fixtures';

test('deterministic IDs are reproducible and duplicate records remain unique', () => {
  const csv = 'Time,Source,Destination,Protocol,Length,Info\n1,10.0.0.1,8.8.8.8,TCP,64,hello\n1,10.0.0.1,8.8.8.8,TCP,64,hello';
  const first = parseCsv('same.csv', csv);
  const second = parseCsv('same.csv', csv);
  assert.deepEqual(first.events.map(record => record.id), second.events.map(record => record.id));
  assert.deepEqual(first.flows.map(record => record.id), second.flows.map(record => record.id));
  assert.equal(first.evidence.id, second.evidence.id);
  assert.notEqual(first.events[0].id, first.events[1].id);
  assert.doesNotMatch(JSON.stringify(first), /Math\.random/);
});

test('signal presentation never adds demo-only findings', () => {
  const upload = parseTextLog('user.log', '2026-07-21T12:00:00Z 10.0.0.2 -> 8.8.8.8 dst_port=443 protocol=TCP length=64');
  const presented = selectPresentedSignals(upload.signals);
  assert.deepEqual(presented.map(signal => signal.id), upload.signals.map(signal => signal.id));
  assert.equal(presented.length, upload.signals.length);
});

test('server-side PCAP handling rejects without synthetic evidence', () => {
  assert.throws(() => parsePcapPlaceholder('capture.pcap', 128), /decoded locally/i);
  assert.throws(
    () => validateParseRequest({ fileName: 'capture.pcap', fileContent: 'data', parseMode: 'pcap' }),
    (error: unknown) => error instanceof ParseRequestError && error.status === 415,
  );
});

test('plain UDP TShark packets are not classified as DNS', () => {
  const result = parseTsharkJson('udp.json', JSON.stringify([{ _source: { layers: {
    frame: { 'frame.time_iso': '2024-01-01T00:00:00.000Z', 'frame.len': '60' },
    ip: { 'ip.src': '10.0.0.1', 'ip.dst': '10.0.0.2' },
    udp: { 'udp.srcport': '5000', 'udp.dstport': '5001' },
  } } }]));
  assert.equal(result.dns.length, 0);
  assert.equal(result.events[0].service, 'Unknown');
});

test('malformed TShark input fails safely', () => {
  assert.throws(() => parseTsharkJson('bad.json', '{not json'), /Malformed TShark JSON/);
});

test('request and capture limits are enforced before parsing', async () => {
  assert.throws(
    () => validateParseRequest({ fileName: 'large.txt', fileContent: 'x'.repeat(MAX_TEXT_CHARACTERS + 1), parseMode: 'txt' }),
    (error: unknown) => error instanceof ParseRequestError && error.status === 413,
  );
  await assert.rejects(() => parseCapture('large.pcap', new ArrayBuffer(MAX_CAPTURE_BYTES + 1)), /browser-decoding limit/);
});

test('valid PCAP and PCAPNG fixtures decode real metadata with stable IDs', async () => {
  for (const [name, fixture] of [['fixture.pcap', validPcap()], ['fixture.pcapng', validPcapng()]] as const) {
    const first = await parseCapture(name, fixture);
    const second = await parseCapture(name, fixture);
    assert.equal(first.events.length, 1);
    assert.equal(first.events[0].timestamp, '2024-05-21T10:00:00.123Z');
    assert.equal(first.events[0].sourceIp, '10.0.0.15');
    assert.equal(first.events[0].destinationIp, '8.8.8.8');
    assert.equal(first.events[0].sourcePort, 53_000);
    assert.equal(first.events[0].destinationPort, 53);
    assert.equal(first.dns[0].query, 'example.com');
    assert.equal(first.dns[0].queryType, 'A');
    assert.deepEqual(first.dns[0].relatedEventIds, [first.events[0].id]);
    assert.equal(first.events[0].id, second.events[0].id);
    assert.equal(first.dns[0].id, second.dns[0].id);
    assert.equal(first.flows[0].id, second.flows[0].id);
  }
});

test('IPv6 formatting is canonical, deterministic, and uses the leftmost longest zero run', () => {
  const cases: Array<[readonly number[], string]> = [
    [[0x2001, 0x0db8, 0, 0, 0, 0, 0, 1], '2001:db8::1'],
    [[0, 0, 0, 0, 0, 0, 0, 1], '::1'],
    [[0, 0, 0, 0, 0, 0, 0, 0], '::'],
    [[0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0, 1, 2], '::1234:5678:9abc:def0:1:2'],
    [[0x2001, 0x0db8, 0, 0, 1, 2, 3, 4], '2001:db8::1:2:3:4'],
    [[0x2001, 0x0db8, 1, 2, 3, 0, 0, 0], '2001:db8:1:2:3::'],
    [[0x2001, 0x0db8, 1, 2, 3, 4, 5, 6], '2001:db8:1:2:3:4:5:6'],
    [[0x2001, 0x0db8, 0, 1, 2, 3, 4, 5], '2001:db8:0:1:2:3:4:5'],
    [[0x2001, 0, 0, 1, 0, 0, 2, 3], '2001::1:0:0:2:3'],
  ];

  cases.forEach(([hextets, expected]) => {
    assert.equal(formatIpv6Hextets(hextets), expected);
    assert.doesNotMatch(formatIpv6Hextets(hextets), /:::/);
  });
});

test('decoded IPv6 endpoints drive stable flow grouping, direction, and evidence IDs', async () => {
  const fixture = ipv6Pcap(
    [0, 0, 0, 0, 0, 0, 0, 1],
    [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1],
  );
  const first = await parseCapture('ipv6.pcap', fixture);
  const second = await parseCapture('ipv6.pcap', fixture);
  const differentEndpoint = await parseCapture('ipv6.pcap', ipv6Pcap(
    [0, 0, 0, 0, 0, 0, 0, 1],
    [0x2001, 0x0db8, 0, 0, 0, 0, 0, 2],
  ));

  assert.equal(first.events[0].sourceIp, '::1');
  assert.equal(first.events[0].destinationIp, '2001:db8::1');
  assert.equal(first.flows[0].sourceIp, '::1');
  assert.equal(first.flows[0].destinationIp, '2001:db8::1');
  assert.equal(first.flows[0].direction, 'outbound');
  assert.deepEqual(first.events.map(event => event.id), second.events.map(event => event.id));
  assert.deepEqual(first.flows.map(flow => flow.id), second.flows.map(flow => flow.id));
  assert.deepEqual(first.signals.map(signal => signal.id), second.signals.map(signal => signal.id));
  assert.equal(first.evidence.id, second.evidence.id);
  assert.notEqual(first.events[0].id, differentEndpoint.events[0].id);
  assert.notEqual(first.flows[0].id, differentEndpoint.flows[0].id);
});

test('related flow resolution uses only ordered exact ID intersections without fallback', () => {
  const flow = (id: string): FlowSummary => ({
    id,
    firstSeen: '2024-01-01T00:00:00.000Z',
    lastSeen: '2024-01-01T00:00:00.000Z',
    sourceIp: '10.0.0.1',
    sourcePort: 50_000,
    sourcePortState: 'observed',
    destinationIp: '198.51.100.1',
    destinationPort: 443,
    destinationPortState: 'observed',
    protocol: 'TCP',
    packetCount: 1,
    byteCount: 60,
    duration: 0,
    direction: 'outbound',
    riskLevel: 'info',
  });
  const firstFlow = flow('demo-flow-1');
  const realFlow = flow('flow-real-capture-9');
  const thirdFlow = flow('flow-real-capture-10');
  const flows = [firstFlow, realFlow, thirdFlow];

  assert.deepEqual(resolveRelatedFlows(['flow-real-capture-9'], flows).map(item => item.id), ['flow-real-capture-9']);
  assert.deepEqual(resolveRelatedFlows(['flow-real-capture-10', 'flow-real-capture-9'], flows).map(item => item.id), ['flow-real-capture-10', 'flow-real-capture-9']);
  assert.deepEqual(resolveRelatedFlows(['missing'], flows), []);
  assert.deepEqual(resolveRelatedFlows(['missing', 'flow-real-capture-9'], flows).map(item => item.id), ['flow-real-capture-9']);
  assert.deepEqual(resolveRelatedFlows([], flows), []);
  assert.deepEqual(resolveRelatedFlows(undefined, flows), []);
  assert.deepEqual(resolveRelatedFlows(['missing'], flows).map(item => item.id), []);
  assert.ok(!resolveRelatedFlows(['missing'], flows).includes(firstFlow));
  assert.deepEqual(resolveRelatedFlows(['flow-real-capture-9', 'flow-real-capture-9'], flows).map(item => item.id), ['flow-real-capture-9']);
});

test('malformed and truncated captures fail without evidence', async () => {
  await assert.rejects(() => parseCapture('bad.pcap', new Uint8Array([1, 2, 3, 4]).buffer), /malformed|truncated|unsupported/i);
});

test('all text adapters produce bounded normalized output', () => {
  const csv = parseCsv('dns.csv', 'Time,Source,Destination,Protocol,Length,Info\n1,10.0.0.1,8.8.8.8,DNS,64,Standard query A example.com');
  const suricata = parseSuricataEve('eve.json', '{"timestamp":"2024-01-01T00:00:00Z","src_ip":"10.0.0.1","dest_ip":"8.8.8.8","src_port":50000,"dest_port":53,"proto":"UDP","event_type":"dns","dns":{"rrname":"example.com","type":"A"}}');
  const zeek = parseZeekLog('dns.log', '#path dns\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tqtype_name\n1704067200\t10.0.0.1\t50000\t8.8.8.8\t53\tudp\texample.com\tA');
  const tshark = parseTsharkJson('dns.json', JSON.stringify([{ _source: { layers: {
    frame: { 'frame.time_iso': '2024-01-01T00:00:00.000Z', 'frame.len': '64' },
    ip: { 'ip.src': '10.0.0.1', 'ip.dst': '8.8.8.8' },
    udp: { 'udp.srcport': '50000', 'udp.dstport': '53' },
    dns: { 'dns.qry.name': 'example.com', 'dns.qry.type': 'A' },
  } } }]));
  assert.equal(csv.dns[0].query, 'example.com');
  assert.equal(suricata.dns[0].query, 'example.com');
  assert.equal(zeek.dns[0].query, 'example.com');
  assert.equal(tshark.dns[0].query, 'example.com');
  for (const result of [csv, suricata, zeek, tshark]) {
    assert.ok(result.events[0].id);
    assert.deepEqual(result.dns[0].relatedEventIds, [result.events[0].id]);
  }
});

test('bundled demo remains internally consistent', () => {
  const first = parseDemoData();
  const second = parseDemoData();
  assert.equal(first.events.length, 40);
  assert.equal(first.flows.length, 34);
  assert.equal(first.dns.length, 19);
  assert.equal(first.http.length, 1);
  assert.equal(first.tls.length, 2);
  assert.deepEqual(first.events.map(event => event.id), second.events.map(event => event.id));
  const eventIds = new Set(first.events.map(event => event.id));
  first.flows.flatMap(flow => flow.relatedEvents || []).forEach(id => assert.ok(eventIds.has(id)));
  [...first.dns, ...first.http, ...first.tls]
    .flatMap(record => record.relatedEventIds || [])
    .forEach(id => assert.ok(eventIds.has(id)));
});
