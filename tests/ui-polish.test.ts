import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import FlowExplorer from '../src/components/FlowExplorer';
import type { FlowSummary } from '../src/types';

const root = new URL('../', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, root), 'utf8');

const baseFlow: Omit<FlowSummary, 'id' | 'riskLevel'> = {
  firstSeen: '2026-07-21T12:00:00.000Z',
  lastSeen: '2026-07-21T12:00:01.000Z',
  sourceIp: '10.0.0.5',
  sourcePort: 51_000,
  destinationIp: '203.0.113.20',
  destinationPort: 443,
  protocol: 'TCP',
  packetCount: 2,
  byteCount: 256,
  duration: 1,
  direction: 'outbound',
  relatedEvents: [],
};

const flows: FlowSummary[] = (['info', 'low', 'medium', 'high'] as const).map((riskLevel, index) => ({
  ...baseFlow,
  id: `flow-${riskLevel}`,
  destinationPort: 440 + index,
  riskLevel,
}));

test('Flow Explorer renders every risk level as a semantic colored pill', () => {
  const markup = renderToStaticMarkup(React.createElement(FlowExplorer, {
    flows,
    events: [],
    signals: [],
    onSelectFlow: () => undefined,
    selectedFlow: flows.at(-1) || null,
    onCloseDrawer: () => undefined,
  }));

  for (const level of ['info', 'low', 'medium', 'high']) {
    assert.match(markup, new RegExp(`data-risk-pill="${level}"`));
  }
  assert.match(markup, /data-risk-pill="info"[^>]+border-border-subtle[^>]+bg-surface-muted[^>]+text-text-muted/);
  assert.doesNotMatch(markup, /data-risk-pill="info"[^>]+bg-blue-/);
  assert.doesNotMatch(markup, /data-risk-pill="info"[^>]+text-white/);
  assert.doesNotMatch(markup, /data-risk-pill="info"[^>]+dark:/);
  assert.match(markup, /data-risk-pill="low"[^>]+bg-emerald-600[^>]+text-white/);
  assert.match(markup, /data-risk-pill="medium"[^>]+bg-amber-500[^>]+text-white/);
  assert.match(markup, /data-risk-pill="high"[^>]+bg-status-danger[^>]+text-white/);
  assert.doesNotMatch(markup, /data-risk-dot/);
});

test('Flow Explorer uses the same risk pill in the table and selected-flow drawer', () => {
  const code = source('src/components/FlowExplorer.tsx');
  assert.equal((code.match(/<RiskPill level=/g) || []).length, 2);
  assert.doesNotMatch(code, /riskDotClasses|h-1\.5 w-1\.5 rounded-full/);
  assert.doesNotMatch(code, /<td className="p-3 uppercase">\{flow\.riskLevel\}<\/td>/);
});

test('information popovers escape clipped headers through a viewport-clamped portal', () => {
  const popover = source('src/components/InfoPopover.tsx');
  const app = source('src/App.tsx');
  assert.match(popover, /createPortal\(/);
  assert.match(popover, /document\.body/);
  assert.match(popover, /window\.innerWidth - popoverWidth - margin/);
  assert.match(popover, /window\.innerHeight - popoverHeight - margin/);
  assert.match(popover, /maxHeight: 'calc\(100vh - 24px\)'/);
  assert.match(popover, /aria-expanded=\{isOpen\}/);
  assert.match(popover, /const popoverId = useId\(\)/);
  assert.match(app, /min-h-12 overflow-hidden/);
});

test('only the first Packet Academy lesson receives the Recommended badge', () => {
  const academy = source('src/components/LearningMode.tsx');
  assert.equal((academy.match(/getStatusIndicator\(isCompleted, true\)/g) || []).length, 1);
  assert.equal((academy.match(/getStatusIndicator\(isCompleted, false\)/g) || []).length, 3);
  assert.doesNotMatch(academy, /const isRecommended = hasEvidence/);
});
