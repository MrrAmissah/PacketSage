import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import CompactInvestigationResult from '../src/components/CompactInvestigationResult';
import EvidenceGroundedAssessment from '../src/components/EvidenceGroundedAssessment';
import { assessmentCitationIds, retainedAssessmentForContext } from '../src/lib/assessmentWorkspace';
import { buildInvestigationEvidencePacket, investigationPacketIdentity, resolveCitedEvent, resolveCitedFlow } from '../src/lib/investigation';
import { findGuidedInvestigationSignal } from '../src/lib/judgePath';
import { parseDemoData } from '../src/lib/parser';
import type { InvestigationRecord } from '../src/types';

const root = new URL('../', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, root), 'utf8');

function fixture() {
  const data = parseDemoData();
  const signal = findGuidedInvestigationSignal(data.evidence.parseMode, data.signals, data.flows, data.events);
  assert.ok(signal);
  const packet = buildInvestigationEvidencePacket(signal, data);
  assert.ok(packet);
  const flowId = packet.flows[0].id;
  const eventId = packet.events[0].id;
  const record: InvestigationRecord = {
    schemaVersion: '1',
    provider: 'Test provider',
    model: 'test-model',
    generationState: 'completed',
    createdAt: '2026-07-21T12:00:00.000Z',
    selectedEvidenceId: data.evidence.id,
    signalId: signal.id,
    packetIdentity: investigationPacketIdentity(packet),
    packet,
    assessment: {
      summary: 'The retained records show a repeated pattern. Intent is not confirmed.',
      observedEvidence: [{ statement: 'An exact flow and event were retained.', evidenceIds: [flowId, eventId] }],
      inferences: [{ statement: 'The cadence may be automated.', confidence: 'medium', evidenceIds: [flowId] }],
      uncertainties: ['The initiating process is not present in the packet metadata.'],
      nextSteps: [{ action: 'Review endpoint telemetry.', reason: 'Identify the initiating process.' }],
    },
    includedInReport: false,
  };
  const context = { selectedEvidenceId: record.selectedEvidenceId, signalId: record.signalId, packetIdentity: record.packetIdentity };
  return { data, record, context, flowId, eventId };
}

function renderWorkspace(record: InvestigationRecord) {
  const { data } = fixture();
  return renderToStaticMarkup(React.createElement(EvidenceGroundedAssessment, {
    record,
    flows: data.flows,
    events: data.events,
    onBack: () => undefined,
    onInclusionChange: () => undefined,
    onInspectFlow: () => undefined,
    onInspectEvent: () => undefined,
    onOpenReport: () => undefined,
    onRerun: () => undefined,
  }));
}

test('full assessment cannot resolve without a valid retained assessment', () => {
  const { context } = fixture();
  assert.equal(retainedAssessmentForContext([], context), null);
});

test('full assessment resolves only for the correct evidence, signal, and packet identity', () => {
  const { record, context } = fixture();
  assert.equal(retainedAssessmentForContext([record], context), record);
  assert.equal(retainedAssessmentForContext([record], { ...context, selectedEvidenceId: 'evidence-other' }), null);
  assert.equal(retainedAssessmentForContext([record], { ...context, signalId: 'signal-other' }), null);
  assert.equal(retainedAssessmentForContext([record], { ...context, packetIdentity: 'packet-other' }), null);
});

test('opening the retained workspace performs no API request', () => {
  const signals = source('src/components/SuspiciousSignals.tsx');
  const handler = signals.match(/const handleOpenFullAssessment[\s\S]*?\n  };/)?.[0] || '';
  assert.match(handler, /setFullAssessmentOpen\(true\)/);
  assert.doesNotMatch(handler, /fetch|handleInvestigate|\/api\//);
});

test('full workspace renders summary and all four structured assessment areas', () => {
  const { record } = fixture();
  const markup = renderWorkspace(record);
  assert.match(markup, /Assessment summary/);
  assert.match(markup, /Observed evidence/);
  assert.match(markup, /Analyst inference/);
  assert.match(markup, /Uncertainty \/ missing evidence/);
  assert.match(markup, /Recommended next investigative steps/);
});

test('exact flow and event citations retain exact resolver navigation', () => {
  const { data, record, flowId, eventId } = fixture();
  assert.equal(resolveCitedFlow(flowId, record.packet, data.flows)?.id, flowId);
  assert.equal(resolveCitedEvent(eventId, record.packet, data.events)?.id, eventId);
  assert.deepEqual(assessmentCitationIds(record.assessment), [flowId, eventId]);
  const markup = renderWorkspace(record);
  assert.match(markup, new RegExp(`Open exact flow ${flowId}`));
  assert.match(markup, new RegExp(`Open exact event ${eventId}`));
});

test('assessment inclusion remains an explicit unpressed control', () => {
  const { record } = fixture();
  const markup = renderWorkspace(record);
  assert.match(markup, /Include AI-assisted assessment in report/);
  assert.match(markup, /aria-pressed="false"/);
  const workspace = source('src/components/EvidenceGroundedAssessment.tsx');
  assert.doesNotMatch(workspace, /useEffect\([\s\S]{0,300}onInclusionChange/);
});

test('inclusion removal state is reflected by both full and compact views', () => {
  const { record } = fixture();
  const included = { ...record, includedInReport: true };
  assert.match(renderWorkspace(included), /Remove AI-assisted assessment from report/);
  const compactIncluded = renderToStaticMarkup(React.createElement(CompactInvestigationResult, { record: included, citationCount: 2, openButtonRef: React.createRef<HTMLButtonElement>(), onOpen: () => undefined, onRerun: () => undefined }));
  const compactRemoved = renderToStaticMarkup(React.createElement(CompactInvestigationResult, { record, citationCount: 2, openButtonRef: React.createRef<HTMLButtonElement>(), onOpen: () => undefined, onRerun: () => undefined }));
  assert.match(compactIncluded, /Included in report/);
  assert.match(compactRemoved, /Not included/);
});

test('rerun remains a deliberate button action', () => {
  const workspace = source('src/components/EvidenceGroundedAssessment.tsx');
  const compact = source('src/components/CompactInvestigationResult.tsx');
  assert.match(workspace, /onClick=\{onRerun\}[\s\S]*Run again with current referenced evidence/);
  assert.match(compact, /onClick=\{onRerun\}[\s\S]*Run again with current referenced evidence/);
  assert.doesNotMatch(workspace, /useEffect\([\s\S]{0,300}onRerun/);
});

test('evidence replacement invalidates the retained workspace and closes local view state', () => {
  const { record, context } = fixture();
  assert.equal(retainedAssessmentForContext([record], { ...context, selectedEvidenceId: 'replacement-evidence' }), null);
  const signals = source('src/components/SuspiciousSignals.tsx');
  assert.match(signals, /setFullAssessmentOpen\(false\)[\s\S]*selectedEvidenceId/);
});

test('stale packet identity and malformed retained output cannot open', () => {
  const { record, context } = fixture();
  assert.equal(retainedAssessmentForContext([{ ...record, packetIdentity: 'stale-packet' }], { ...context, packetIdentity: 'stale-packet' }), null);
  const malformed = { ...record, assessment: { ...record.assessment, summary: '' } };
  assert.equal(retainedAssessmentForContext([malformed], context), null);
});

test('back closes the internal view and returns focus to the originating signal control', () => {
  const signals = source('src/components/SuspiciousSignals.tsx');
  const workspace = source('src/components/EvidenceGroundedAssessment.tsx');
  assert.match(signals, /handleCloseFullAssessment[\s\S]*setFullAssessmentOpen\(false\)[\s\S]*fullAssessmentTriggerRef\.current\?\.focus/);
  assert.match(signals, /mapped\.find\(signal => signal\.id === selectedSignalId\)/);
  assert.match(workspace, /workspaceRef\.current\?\.scrollIntoView\(\{ behavior: 'auto', block: 'start' \}\)/);
});

test('citation-restricted flow navigation still restores unrestricted flow navigation', () => {
  const app = source('src/App.tsx');
  const workspace = source('src/components/EvidenceGroundedAssessment.tsx');
  assert.match(workspace, /onInspectFlow\(\[flow\]\)/);
  assert.match(app, /if \(item\.id === 'flows'\) setRelatedFlowScopeIds\(null\)/);
});

test('provider and model remain inside optional technical details', () => {
  const workspace = source('src/components/EvidenceGroundedAssessment.tsx');
  const details = workspace.slice(workspace.indexOf('<details'), workspace.indexOf('</details>') + 10);
  assert.match(details, /Provider/);
  assert.match(details, /Model/);
  assert.doesNotMatch(workspace.slice(0, workspace.indexOf('<details')), /record\.provider|record\.model/);
  assert.doesNotMatch(renderWorkspace(fixture().record).match(/<h1[\s\S]*?<\/h1>/)?.[0] || '', /Test provider|test-model/);
});

test('workspace provides desktop columns and a naturally stacked narrow layout without horizontal minima', () => {
  const workspace = source('src/components/EvidenceGroundedAssessment.tsx');
  assert.match(workspace, /xl:grid-cols-\[minmax\(0,1fr\)_360px\]/);
  assert.match(workspace, /grid min-w-0 gap-6/);
  assert.doesNotMatch(workspace, /min-w-\[(?:[4-9]\d\d|\d{4,})px\]|overflow-x-auto/);
});

test('later spotlight targets are stable without implementing a tour', () => {
  const code = `${source('src/components/SuspiciousSignals.tsx')}\n${source('src/components/CompactInvestigationResult.tsx')}\n${source('src/components/EvidenceGroundedAssessment.tsx')}`;
  assert.match(code, /data-tour-target="investigation-trigger"/);
  assert.match(code, /data-tour-target="open-full-assessment"/);
  assert.match(code, /data-tour-target="assessment-report-inclusion"/);
  assert.doesNotMatch(code, /spotlight|driver\.js|intro\.js/i);
});
