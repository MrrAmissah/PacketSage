import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, root), 'utf8');

test('strategic roadmap distinguishes current production architecture from future work', () => {
  const roadmap = source('docs/ROADMAP.md');
  assert.match(roadmap, /## 1\. Shipped production baseline/);
  assert.match(roadmap, /## 2\. Near term/);
  assert.match(roadmap, /## 3\. Mid term/);
  assert.match(roadmap, /## 4\. Long term/);
  assert.match(roadmap, /## 5\. Intentionally deferred during Build Week/);
  assert.match(roadmap, /bounded browser-side PCAP and PCAPNG metadata decoding/);
  assert.match(roadmap, /bounded server parsing for Wireshark CSV, Suricata EVE JSON, Zeek TSV\/log exports, TShark JSON and strict structured text/);
  assert.match(roadmap, /Evidence-grounded Investigation using a bounded `gpt-5\.6-sol` packet/);
  assert.match(roadmap, /separately bounded and citation-free Capture Overview/);
  assert.match(roadmap, /Observed evidence, deterministic derivation, external context and AI inference remain visibly separate/);
});

test('strategic roadmap no longer presents shipped adapters or capture decoding as future work', () => {
  const roadmap = source('docs/ROADMAP.md');
  assert.doesNotMatch(roadmap, /Decodes CSV\/JSON in-memory|Evaluates Heuristics locally|Strip Secrets via Regex/);
  assert.doesNotMatch(roadmap, /Ingesting Outputs from Zeek & Suricata \(Stage 2 Target\)/);
  assert.doesNotMatch(roadmap, /Allow users to upload raw binary `\.pcap` or `\.pcapng` files/);
  assert.doesNotMatch(roadmap, /When native binary `\.pcap` decoding is introduced/);
});
