import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ReportBuilder from '../src/components/ReportBuilder';
import { boundedCaptureSummary, clientSafeCaptureOverviewError } from '../src/server/captureOverviewApi';
import {
  completedCaptureOverview,
  includedCaptureOverview,
  setCaptureOverviewInclusion,
  validateCaptureOverviewResponse,
} from '../src/lib/captureOverview';
import { sha256Hex } from '../src/lib/checksum';
import {
  clearInvestigationRecords,
  completedInvestigationRecord,
  setInvestigationReportInclusion,
  upsertInvestigationRecord,
} from '../src/lib/investigationRecords';
import { buildReportModel, evidenceChecksumLabel, reportToMarkdown } from '../src/lib/report';
import { parseDemoData, type ParsedResult } from '../src/lib/parser';
import type {
  FlowSummary,
  InvestigationEvidencePacket,
  InvestigationRecord,
  AiAnalysisResult,
  PacketEvent,
  SuspiciousSignal,
} from '../src/types';

const timestamp = '2026-07-20T10:00:00.000Z';

function packetEvent(id = 'evt-1'): PacketEvent {
  return {
    id,
    timestamp,
    sourceIp: '10.0.0.5',
    sourcePort: 50_000,
    destinationIp: '198.51.100.20',
    destinationPort: 443,
    protocol: 'TCP',
    service: 'HTTPS',
    length: 96,
    info: 'Observed packet metadata',
  };
}

function flow(id = 'flow-1', relatedEvents = ['evt-1']): FlowSummary {
  return {
    id,
    firstSeen: timestamp,
    lastSeen: timestamp,
    sourceIp: '10.0.0.5',
    sourcePort: 50_000,
    destinationIp: '198.51.100.20',
    destinationPort: 443,
    protocol: 'TCP',
    service: 'HTTPS',
    packetCount: 1,
    byteCount: 96,
    duration: 0,
    direction: 'outbound',
    riskLevel: 'medium',
    relatedEvents,
  };
}

function signal(id = 'sig-1', overrides: Partial<SuspiciousSignal> = {}): SuspiciousSignal {
  return {
    id,
    title: `Signal ${id}`,
    severity: 'medium',
    confidence: 'medium',
    category: 'Review',
    observedEvidence: 'One exact related flow was observed.',
    interpretation: 'Review the supplied relationship.',
    whatItDoesNotProve: 'This does not confirm malicious activity.',
    recommendedDefensiveCheck: `Review endpoint telemetry for ${id}.`,
    relatedFlowIds: ['flow-1'],
    relatedEventIds: ['evt-1'],
    ...overrides,
  };
}

function dataFixture(overrides: Partial<ParsedResult> = {}): ParsedResult {
  return {
    evidence: {
      id: 'evidence-1',
      name: 'fixture.csv',
      type: 'csv',
      size: 3,
      uploadedAt: timestamp,
      parseMode: 'csv',
      sourceFormat: 'CSV',
      retentionMode: 'Browser memory only',
      status: 'completed',
      sha256: 'a'.repeat(64),
      checksumStatus: 'calculated',
    },
    events: [packetEvent()],
    flows: [flow()],
    dns: [],
    http: [],
    tls: [],
    signals: [signal()],
    protocolStats: [],
    ...overrides,
  };
}

function packet(signalId = 'sig-1', eventId = 'evt-1'): InvestigationEvidencePacket {
  return {
    version: '1',
    signal: {
      ...signal(signalId),
      relatedFlowIds: ['flow-1'],
      relatedEventIds: [eventId],
    },
    flows: [{
      ...flow(),
      relatedEventIds: [eventId],
    }],
    events: [{
      ...packetEvent(eventId),
      sourceType: 'csv',
    }],
    dns: [],
    http: [],
    tls: [],
    limitsApplied: { flowsTruncated: false, eventsTruncated: false, protocolRecordsTruncated: false },
  };
}

function record(signalId = 'sig-1', packetIdentity = 'packet-1'): InvestigationRecord {
  return completedInvestigationRecord({
    selectedEvidenceId: 'evidence-1',
    signalId,
    packetIdentity,
    packet: packet(signalId),
    apiResult: {
      schemaVersion: '1', provider: 'OpenAI', model: 'server-returned-model',
      assessment: {
        summary: `Assessment summary for ${signalId}.`,
        observedEvidence: [{ statement: `Observed statement for ${signalId}.`, evidenceIds: ['flow-1'] }],
        inferences: [{ statement: `Inference for ${signalId}.`, confidence: 'low', evidenceIds: ['flow-1'] }],
        uncertainties: [`Uncertainty for ${signalId}.`],
        nextSteps: [{ action: `Next step for ${signalId}.`, reason: 'Independent validation is required.' }],
      },
    },
  });
}

function include(input: InvestigationRecord): InvestigationRecord {
  return setInvestigationReportInclusion([input], input, true)[0];
}

const overviewResult: AiAnalysisResult = {
  executiveSummary: 'Orientation only.', whatHappened: 'A broad traffic pattern.', normalActivity: 'Routine traffic may be present.', suspiciousActivity: 'Review-worthy patterns need validation.', analystQuestions: 'Which hosts are expected?', recommendedChecks: 'Validate with endpoint records.', beginnerExplanation: 'Flows describe conversations.', technicalExplanation: 'Metadata was summarized within fixed record limits.', confidence: 'low', limitations: 'This is not evidence-linked.',
};

function overview() {
  return completedCaptureOverview('evidence-1', { provider: 'Google', model: 'gemini-test', result: overviewResult });
}

test('retained capture overview records complete model provenance and default exclusion', () => {
  const retained = overview();
  assert.equal(retained.schemaVersion, '1');
  assert.equal(retained.provider, 'Google');
  assert.equal(retained.model, 'gemini-test');
  assert.equal(retained.captureIdentity, 'evidence-1');
  assert.equal(retained.generationState, 'completed');
  assert.match(retained.createdAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(retained.includedInReport, false);
});

test('capture overview inclusion is explicit and limited to the current capture', () => {
  const retained = overview();
  assert.equal(setCaptureOverviewInclusion(retained, 'stale-evidence', true)?.includedInReport, false);
  const included = setCaptureOverviewInclusion(retained, 'evidence-1', true);
  assert.equal(includedCaptureOverview(included, 'evidence-1'), included);
  assert.equal(includedCaptureOverview(included, 'different-evidence'), null);
});

test('capture overview appears only under a provider-neutral contextual report heading', () => {
  const included = setCaptureOverviewInclusion(overview(), 'evidence-1', true);
  const report = buildReportModel(dataFixture(), [], {}, included);
  const markdown = reportToMarkdown(report);
  assert.equal(report.contextualOverview, included);
  assert.match(markdown, /Capture overview — contextual note/);
  assert.doesNotMatch(markdown, /### Gemini capture overview/);
  assert.match(markdown, /not evidence-linked/);
  assert.doesNotMatch(markdown.split('## AI-assisted investigation assessments')[0], /Evidence IDs:/);
});

test('excluded capture overview never enters report output', () => {
  const markdown = reportToMarkdown(buildReportModel(dataFixture(), [], {}, overview()));
  assert.doesNotMatch(markdown, /Orientation only\./);
});

test('capture overview response schema and provenance are enforced', () => {
  assert.deepEqual(validateCaptureOverviewResponse({ provider: 'Google', model: 'gemini-test', result: overviewResult }).result, overviewResult);
  assert.throws(() => validateCaptureOverviewResponse({ provider: 'Google', model: '', result: overviewResult }), /provenance/);
  assert.throws(() => validateCaptureOverviewResponse({ provider: 'Google', model: 'gemini-test', result: {} }), /invalid response/);
});

test('capture overview request is bounded and errors remain client-safe', () => {
  const bounded = boundedCaptureSummary({ captureIdentity: 'evidence-1', flowSummary: Array.from({ length: 100 }, (_, index) => ({ sourceIp: `10.0.0.${index}` })), httpRecords: [{ uri: '/login?token=private-value' }] });
  assert.equal(bounded.flows.length, 15);
  assert.doesNotMatch(JSON.stringify(bounded), /private-value/);
  assert.throws(() => boundedCaptureSummary({ captureIdentity: 'evidence-1', data: 'x'.repeat(180_001) }), /too large/);
  assert.deepEqual(clientSafeCaptureOverviewError(new Error('secret upstream detail')), { status: 500, message: 'Unable to generate the capture overview.' });
});

test('a successful current assessment can be explicitly included', () => {
  const current = record();
  assert.deepEqual({ schema: current.schemaVersion, provider: current.provider, model: current.model, state: current.generationState, evidence: current.selectedEvidenceId }, { schema: '1', provider: 'OpenAI', model: 'server-returned-model', state: 'completed', evidence: 'evidence-1' });
  const updated = setInvestigationReportInclusion([current], current, true);
  assert.equal(updated[0].includedInReport, true);
});

test('changing server-returned investigation provenance changes the retained record without client constants', () => {
  const first = record();
  const changed = completedInvestigationRecord({
    selectedEvidenceId: first.selectedEvidenceId,
    signalId: first.signalId,
    packetIdentity: first.packetIdentity,
    packet: first.packet,
    apiResult: { schemaVersion: '1', provider: 'Configured provider', model: 'new-server-model', assessment: first.assessment },
  });
  assert.deepEqual({ schema: changed.schemaVersion, provider: changed.provider, model: changed.model }, { schema: '1', provider: 'Configured provider', model: 'new-server-model' });
});

test('invalid investigation provenance cannot produce a retained completed record', () => {
  const valid = record();
  assert.throws(() => completedInvestigationRecord({
    selectedEvidenceId: valid.selectedEvidenceId,
    signalId: valid.signalId,
    packetIdentity: valid.packetIdentity,
    packet: valid.packet,
    apiResult: { schemaVersion: '1', provider: '', model: 'server-model', assessment: valid.assessment },
  }), /provider provenance/);
});

test('primary capability labels are provider-neutral while provenance remains optional', () => {
  const overviewSource = readFileSync('src/components/CaptureOverview.tsx', 'utf8');
  const investigationSource = readFileSync('src/components/SuspiciousSignals.tsx', 'utf8');
  assert.match(overviewSource, /> Capture Overview</);
  assert.doesNotMatch(overviewSource, /Capture Overview[^\n]*Google|Capture Overview[^\n]*Gemini/);
  assert.match(investigationSource, />Evidence-grounded investigation</);
  assert.doesNotMatch(investigationSource, /Evidence-grounded investigation[^\n]*(OpenAI|GPT)/);
  assert.match(overviewSource, /current\?\.provider/);
  assert.match(investigationSource, /completedRecord\?\.provider/);
});

test('screen, print, and Markdown report output retain neutral heading and optional provenance', () => {
  const included = setCaptureOverviewInclusion(overview(), 'evidence-1', true);
  const markup = renderToStaticMarkup(React.createElement(ReportBuilder, {
    data: dataFixture(), investigations: [include(record())], captureOverview: included,
  }));
  const markdown = reportToMarkdown(buildReportModel(dataFixture(), [include(record())], {}, included));
  for (const output of [markup, markdown]) {
    assert.match(output, /Capture overview — contextual note/);
    assert.match(output, /Google/);
    assert.match(output, /gemini-test/);
    assert.doesNotMatch(output, /Gemini capture overview/);
  }
});

test('failure state cannot be included because no validated record exists', () => {
  assert.deepEqual(setInvestigationReportInclusion([], {
    selectedEvidenceId: 'evidence-1', signalId: 'sig-1', packetIdentity: 'packet-1',
  }, true), []);
});

test('a stale packet identity cannot be included', () => {
  const current = record();
  const updated = setInvestigationReportInclusion([current], {
    selectedEvidenceId: current.selectedEvidenceId,
    signalId: current.signalId,
    packetIdentity: 'obsolete-packet',
  }, true);
  assert.equal(updated[0].includedInReport, false);
});

test('new evidence clears completed and included assessments', () => {
  assert.deepEqual(clearInvestigationRecords(), []);
});

test('reinvestigation with changed evidence does not preserve inclusion', () => {
  const oldRecord = include(record('sig-1', 'packet-old'));
  const replacement = record('sig-1', 'packet-new');
  const updated = upsertInvestigationRecord([oldRecord], replacement);
  assert.equal(updated.length, 1);
  assert.equal(updated[0].packetIdentity, 'packet-new');
  assert.equal(updated[0].includedInReport, false);
});

test('multiple included assessments remain distinct in report output', () => {
  const first = include(record('sig-1', 'packet-1'));
  const second = include(record('sig-2', 'packet-2'));
  const data = dataFixture({ signals: [signal('sig-1'), signal('sig-2')] });
  const report = buildReportModel(data, [first, second]);
  assert.deepEqual(report.assessments.map(item => item.signalId), ['sig-1', 'sig-2']);
});

test('excluded assessments do not appear in any report output', () => {
  const report = buildReportModel(dataFixture(), [record()]);
  assert.equal(report.assessments.length, 0);
  assert.doesNotMatch(reportToMarkdown(report), /Assessment summary for sig-1/);
});

test('observed evidence and inference remain separately labelled in report output', () => {
  const markdown = reportToMarkdown(buildReportModel(dataFixture(), [include(record())]));
  assert.match(markdown, /#### Observed evidence/);
  assert.match(markdown, /#### Analyst inference — Not confirmed/);
  assert.ok(markdown.indexOf('Observed statement') < markdown.indexOf('Inference for'));
});

test('exact evidence IDs survive report preview model and Markdown export', () => {
  const report = buildReportModel(dataFixture(), [include(record())]);
  assert.deepEqual(report.assessments[0].assessment.observedEvidence[0].evidenceIds, ['flow-1']);
  assert.match(reportToMarkdown(report), /`flow-1`/);
});

test('known content produces its real SHA-256 digest', async () => {
  assert.equal(await sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('demo evidence never displays a fabricated checksum', () => {
  const demo = parseDemoData();
  assert.equal(evidenceChecksumLabel(demo), 'Not applicable — generated demonstration dataset');
  assert.doesNotMatch(evidenceChecksumLabel(demo), /^[a-f0-9]{64}$/);
});

test('no-event evidence produces no synthetic timeline', () => {
  const report = buildReportModel(dataFixture({ events: [], flows: [], signals: [] }), []);
  assert.deepEqual(report.timeline, []);
  assert.match(reportToMarkdown(report), /No timeline events were available in the selected evidence\./);
});

test('timeline rows come only from actual event IDs', () => {
  const data = dataFixture({ events: [packetEvent('evt-real')] });
  const report = buildReportModel(data, []);
  assert.deepEqual(report.timeline.map(item => item.id), ['evt-real']);
});

test('timeline signal association uses exact relationships rather than IP prose', () => {
  const unrelated = signal('sig-prose', {
    observedEvidence: 'Text mentions 10.0.0.5 but has no exact relationship.',
    relatedFlowIds: [],
    relatedEventIds: [],
  });
  const report = buildReportModel(dataFixture({ signals: [unrelated] }), []);
  assert.deepEqual(report.timeline[0].signalIds, []);
});

test('findings expose exact signal, flow, and event references without substitution', () => {
  const reviewed = signal('sig-exact', { status: 'Added to report', relatedFlowIds: ['flow-1'], relatedEventIds: ['evt-1'] });
  const report = buildReportModel(dataFixture({ signals: [reviewed] }), []);
  assert.deepEqual(report.findings[0], {
    title: 'Signal sig-exact', severity: 'medium', signalId: 'sig-exact', relatedFlowIds: ['flow-1'], relatedEventIds: ['evt-1'],
  });
});

test('recommendations come only from included assessments and reviewed signals', () => {
  const reviewed = signal('sig-1', { status: 'Added to report' });
  const report = buildReportModel(dataFixture({ signals: [reviewed] }), [include(record())]);
  assert.deepEqual(report.recommendations.map(item => item.source), [
    'AI-assisted assessment for signal sig-1',
    'Reviewed signal sig-1',
  ]);
});

test('no recommendations produces the honest empty state', () => {
  const unreviewed = signal('sig-1', { status: 'Needs review' });
  const report = buildReportModel(dataFixture({ signals: [unreviewed] }), []);
  assert.deepEqual(report.recommendations, []);
  assert.match(reportToMarkdown(report), /No case-specific recommendations have been added to this report draft\./);
});
