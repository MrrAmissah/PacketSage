import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, root), 'utf8');

test('strategic roadmap distinguishes current production architecture from future work', () => {
  const roadmap = source('docs/PACKETSAGE_STRATEGIC_ROADMAP_RESEARCH.md');
  assert.match(roadmap, /### Current production architecture/);
  assert.match(roadmap, /### Intentional Build Week deferrals/);
  assert.match(roadmap, /### Near-term roadmap/);
  assert.match(roadmap, /### Long-term direction/);
  assert.match(roadmap, /Supported `\.pcap` and `\.pcapng` captures are decoded in bounded browser memory/);
  assert.match(roadmap, /Supported CSV, Suricata EVE JSON, Zeek TSV, TShark JSON, and strict text evidence is submitted to the server parsing endpoint/);
  assert.match(roadmap, /GPT-5\.6 endpoint receives only a bounded packet for one operator-selected signal/);
  assert.match(roadmap, /separate Google Gemini endpoint receives a bounded, redacted whole-capture summary/);
  assert.match(roadmap, /Observed evidence, deterministic derivation, external context and AI inference remain visibly separate/);
});

test('strategic roadmap no longer presents shipped adapters or capture decoding as future work', () => {
  const roadmap = source('docs/PACKETSAGE_STRATEGIC_ROADMAP_RESEARCH.md');
  assert.doesNotMatch(roadmap, /Decodes CSV\/JSON in-memory|Evaluates Heuristics locally|Strip Secrets via Regex/);
  assert.doesNotMatch(roadmap, /Ingesting Outputs from Zeek & Suricata \(Stage 2 Target\)/);
  assert.doesNotMatch(roadmap, /Allow users to upload raw binary `\.pcap` or `\.pcapng` files/);
  assert.doesNotMatch(roadmap, /When native binary `\.pcap` decoding is introduced/);
});
