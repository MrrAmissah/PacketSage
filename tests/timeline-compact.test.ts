import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import IncidentTimeline from '../src/components/IncidentTimeline';
import type { FlowSummary, PacketEvent, SuspiciousSignal } from '../src/types';

const root = new URL('../', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, root), 'utf8');

function packetEvent(id: string, overrides: Partial<PacketEvent> = {}): PacketEvent {
  return {
    id,
    timestamp: '2026-07-21T12:34:56.000Z',
    sourceIp: '10.0.0.5',
    sourcePort: 51_000,
    destinationIp: '203.0.113.20',
    destinationPort: 443,
    protocol: 'TCP',
    service: 'HTTPS',
    length: 256,
    info: 'A recorded encrypted web connection crossed the capture point.',
    ...overrides,
  };
}

function flow(id: string, relatedEvents: string[]): FlowSummary {
  return {
    id,
    firstSeen: '2026-07-21T12:34:56.000Z',
    lastSeen: '2026-07-21T12:34:57.000Z',
    sourceIp: '10.0.0.5',
    sourcePort: 51_000,
    destinationIp: '203.0.113.20',
    destinationPort: 443,
    protocol: 'TCP',
    service: 'HTTPS',
    packetCount: 2,
    byteCount: 512,
    duration: 1,
    direction: 'outbound',
    riskLevel: 'info',
    relatedEvents,
  };
}

function signal(id: string, relatedEventIds: string[]): SuspiciousSignal {
  return {
    id,
    title: 'Observed signal',
    severity: 'info',
    confidence: 'medium',
    category: 'Network observation',
    observedEvidence: 'Recorded metadata only.',
    interpretation: 'Requires review.',
    whatItDoesNotProve: 'No outcome is established.',
    recommendedDefensiveCheck: 'Review the exact evidence.',
    relatedEventIds,
  };
}

function renderTimeline(events: PacketEvent[], flows: FlowSummary[] = [], signals: SuspiciousSignal[] = []): string {
  return renderToStaticMarkup(React.createElement(IncidentTimeline, { events, flows, signals }));
}

test('timeline event cards do not repeat the full recorded timestamp', () => {
  const event = packetEvent('evt-one');
  const markup = renderTimeline([event]);
  const cards = [...markup.matchAll(/<button data-testid="timeline-event-card"[\s\S]*?<\/button>/g)];
  assert.equal(cards.length, 1);
  assert.doesNotMatch(cards[0][0], /2026-07-21T12:34:56\.000Z/);
  assert.match(markup, /dateTime="2026-07-21T12:34:56\.000Z"/);
});

test('one displayed date is retained once beside the session reconstruction heading', () => {
  const markup = renderTimeline([
    packetEvent('evt-one'),
    packetEvent('evt-two', { timestamp: '2026-07-21T13:00:00.000Z' }),
  ]);
  assert.match(markup, /data-testid="timeline-session-date"[^>]*>Recorded on Jul 21, 2026 UTC<\/time>/);
  assert.doesNotMatch(markup, /data-testid="timeline-date-separator"/);
});

test('evidence spanning multiple dates renders a separator whenever the date changes', () => {
  const markup = renderTimeline([
    packetEvent('evt-one'),
    packetEvent('evt-two', { timestamp: '2026-07-22T00:01:00.000Z' }),
    packetEvent('evt-three', { timestamp: '2026-07-23T02:00:00.000Z' }),
  ]);
  assert.equal((markup.match(/data-testid="timeline-date-separator"/g) || []).length, 3);
  assert.match(markup, />Jul 21, 2026 UTC<\/time>/);
  assert.match(markup, />Jul 22, 2026 UTC<\/time>/);
  assert.match(markup, />Jul 23, 2026 UTC<\/time>/);
  assert.doesNotMatch(markup, /data-testid="timeline-session-date"/);
});

test('compact card endpoint routes derive from the actual event', () => {
  const markup = renderTimeline([packetEvent('evt-route', {
    sourceIp: '2001:db8::1',
    sourcePort: 5353,
    destinationIp: '2001:db8::2',
    destinationPort: 53,
  })]);
  assert.match(markup, /data-testid="timeline-event-route"[^>]*>\[2001:db8::1\]:5353 → \[2001:db8::2\]:53<\/p>/);
});

test('relationship summaries count only exact parser-established IDs', () => {
  const event = packetEvent('evt-exact');
  const markup = renderTimeline(
    [event],
    [flow('flow-exact', ['evt-exact']), flow('flow-unrelated', ['evt-other'])],
    [signal('sig-exact', ['evt-exact']), signal('sig-unrelated', ['evt-other'])],
  );
  assert.match(markup, /data-testid="timeline-event-relationships"[^>]*>1 related flow · 1 signal<\/p>/);
  assert.doesNotMatch(markup, /2 related flows|2 signals/);
});

test('sparse one-event evidence retains identity, route, counts, and chronology', () => {
  const markup = renderTimeline([packetEvent('evt-sparse', { service: undefined, info: '' })]);
  assert.equal((markup.match(/data-testid="timeline-event-card"/g) || []).length, 1);
  assert.match(markup, /evt-sparse/);
  assert.match(markup, /10\.0\.0\.5:51000 → 203\.0\.113\.20:443/);
  assert.match(markup, /0 related flows · 0 signals/);
  assert.match(markup, /\+00:00:00/);
});

test('timeline cards preserve keyboard semantics and a height-neutral selected state', () => {
  const code = source('src/components/IncidentTimeline.tsx');
  assert.match(code, /<button data-testid="timeline-event-card"/);
  assert.match(code, /onClick=\{\(\) => setSelectedEventId\(event\.id\)\}/);
  assert.match(code, /aria-pressed=\{isSelected\}/);
  assert.match(code, /isSelected \? 'border-accent-primary bg-accent-soft'/);
  assert.doesNotMatch(code, /isSelected \? '[^']*p-[0-9]/);
});

test('compact timeline layout can stack at 390px without imposing global overflow', () => {
  const code = source('src/components/IncidentTimeline.tsx');
  assert.match(code, /grid min-w-0 gap-x-4 gap-y-1 sm:grid-cols-/);
  assert.match(code, /data-testid="timeline-event-route"[^\n]+\[overflow-wrap:anywhere\]/);
  assert.match(code, /grid-cols-\[3\.4rem_2\.5rem_minmax\(0,1fr\)\]/);
  assert.doesNotMatch(code, /timeline-event-card[^\n]+min-w-\[[^\]]+\]/);
});
