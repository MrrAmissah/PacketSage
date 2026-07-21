import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ArchitectureRoadmap } from '../src/components/ArchitectureRoadmap';
import {
  INVESTIGATION_TIMEOUT_MS,
  MAX_CAPTURE_BYTES,
  MAX_CAPTURE_PACKETS,
  MAX_INVESTIGATION_EVENTS,
  MAX_INVESTIGATION_FLOWS,
  MAX_INVESTIGATION_PROTOCOL_RECORDS,
  MAX_INVESTIGATION_REQUEST_BYTES,
  MAX_PARSED_RECORDS,
  MAX_REQUEST_BYTES,
  MAX_TEXT_CHARACTERS,
} from '../src/lib/limits';
import { MAX_REPORT_TIMELINE_EVENTS, PACKETSAGE_REPORT_VERSION } from '../src/lib/report';

const root = new URL('../', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, root), 'utf8');
const markup = renderToStaticMarkup(React.createElement(ArchitectureRoadmap));

test('Architecture spec is restored as an evidence-independent primary route', () => {
  const app = source('src/App.tsx');
  assert.match(app, /import ArchitectureRoadmap from '.\/components\/ArchitectureRoadmap'/);
  assert.match(app, /case 'architecture':\s*return <ArchitectureRoadmap \/>/);
  assert.match(app, /id: 'architecture', label: 'Architecture spec', icon: Terminal, enabled: true/);
  assert.match(app, /activeTab === 'architecture' \? 'Architecture spec'/);
});

test('Architecture spec identifies the real browser and server processing split', () => {
  assert.match(markup, /Current runtime boundaries/);
  assert.match(markup, /PCAP and PCAPNG bytes are decoded locally/);
  assert.match(markup, /\/api\/parse boundary validates and normalizes supported CSV, Suricata, Zeek, TShark JSON and strict text evidence/);
  assert.match(markup, /Binary captures stay local; supported text is validated by the parser endpoint/);
});

test('Architecture spec renders limits from shared runtime constants', () => {
  assert.match(markup, new RegExp(`${MAX_CAPTURE_BYTES / 1024 / 1024} MiB`));
  assert.match(markup, new RegExp(MAX_CAPTURE_PACKETS.toLocaleString()));
  assert.match(markup, new RegExp(MAX_TEXT_CHARACTERS.toLocaleString()));
  assert.match(markup, new RegExp(MAX_PARSED_RECORDS.toLocaleString()));
  assert.match(markup, new RegExp(`${MAX_REQUEST_BYTES / 1024 / 1024} MiB request-body`));
  assert.match(markup, new RegExp(`${MAX_INVESTIGATION_REQUEST_BYTES / 1024} KiB packet`));
  assert.match(markup, new RegExp(`${MAX_INVESTIGATION_FLOWS} flows, ${MAX_INVESTIGATION_EVENTS} events and ${MAX_INVESTIGATION_PROTOCOL_RECORDS} protocol records`));
  assert.match(markup, new RegExp(`${INVESTIGATION_TIMEOUT_MS / 1_000}-second timeout`));
  assert.match(markup, new RegExp(`Up to ${MAX_REPORT_TIMELINE_EVENTS} timeline rows`));
  assert.match(markup, new RegExp(PACKETSAGE_REPORT_VERSION.replace('.', '\\.')));
});

test('Architecture spec keeps the two AI roles and report handoffs separate', () => {
  assert.match(markup, /one validated, bounded signal packet to GPT-5\.6 with strict structured output and store: false/);
  assert.match(markup, /separate \/api\/analyze proxy sends a redacted, bounded whole-capture summary to Gemini/);
  assert.match(markup, /No AI output enters a report automatically/);
  assert.match(markup, /Raw-capture boundary/);
  assert.match(markup, /Unsupported model citations are removed without substitution/);
});

test('Architecture spec reflects every implemented Build Week delivery stage', () => {
  for (const stage of ['Stage 1', 'Stage 2', 'Stage 3', 'Stage 4A']) {
    assert.match(markup, new RegExp(`${stage} · Implemented`));
  }
  assert.match(markup, /Professional report identity and PDF/);
  assert.match(markup, /Full assessment workspace/);
});

test('Architecture spec labels future architecture without presenting it as active', () => {
  for (const capability of ['Persistent case management', 'Large-capture worker tier', 'Enterprise policy gateway', 'External intelligence integrations']) {
    assert.match(markup, new RegExp(capability));
  }
  assert.equal((markup.match(/Not implemented/g) || []).length, 4);
  assert.doesNotMatch(markup, /Demo Decoder|Planned Binary PCAP Decoders|full native binary PCAP decoding is a planned/i);
});

test('Architecture documentation and product navigation agree', () => {
  assert.match(source('README.md'), /\*\*Architecture Spec\*\*: Shows the implemented browser, serverless and model-provider boundaries/);
  assert.match(source('docs/PRODUCT_SPEC.md'), /### 4\.11 Architecture Spec/);
  assert.match(source('docs/TECHNICAL_SPEC.md'), /Packet Academy, and Architecture spec/);
  assert.match(source('docs/TECHNICAL_SPEC.md'), /Architecture spec is evidence-independent/);
  assert.match(source('docs/USER_GUIDE.md'), /Open \*\*Architecture spec\*\* at any time, including before loading evidence/);
});
