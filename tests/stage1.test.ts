import assert from 'node:assert/strict';
import test from 'node:test';
import { parseCapture } from '../src/lib/capture';
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
import { validPcap, validPcapng } from './capture-fixtures';

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
  const upload = parseTextLog('user.log', '10.0.0.2 to 8.8.8.8 port 443 Protocol TCP');
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
    assert.equal(first.events[0].id, second.events[0].id);
    assert.equal(first.dns[0].id, second.dns[0].id);
    assert.equal(first.flows[0].id, second.flows[0].id);
  }
});

test('malformed and truncated captures fail without evidence', async () => {
  await assert.rejects(() => parseCapture('bad.pcap', new Uint8Array([1, 2, 3, 4]).buffer), /malformed|truncated|unsupported/i);
});

test('all text adapters produce bounded normalized output', () => {
  const suricata = parseSuricataEve('eve.json', '{"timestamp":"2024-01-01T00:00:00Z","src_ip":"10.0.0.1","dest_ip":"8.8.8.8","src_port":50000,"dest_port":53,"proto":"UDP","event_type":"dns","dns":{"rrname":"example.com","type":"A"}}');
  const zeek = parseZeekLog('dns.log', '#path dns\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tqtype_name\n1704067200\t10.0.0.1\t50000\t8.8.8.8\t53\tudp\texample.com\tA');
  assert.equal(suricata.dns[0].query, 'example.com');
  assert.equal(zeek.dns[0].query, 'example.com');
  assert.ok(suricata.events[0].id);
  assert.ok(zeek.events[0].id);
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
});
