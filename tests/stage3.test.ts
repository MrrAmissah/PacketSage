import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
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
    assessment: {
      summary: `Assessment summary for ${signalId}.`,
      observedEvidence: [{ statement: `Observed statement for ${signalId}.`, evidenceIds: ['flow-1'] }],
      inferences: [{ statement: `Inference for ${signalId}.`, confidence: 'low', evidenceIds: ['flow-1'] }],
      uncertainties: [`Uncertainty for ${signalId}.`],
      nextSteps: [{ action: `Next step for ${signalId}.`, reason: 'Independent validation is required.' }],
    },
  });
}

function include(input: InvestigationRecord): InvestigationRecord {
  return setInvestigationReportInclusion([input], input, true)[0];
}

function sourceFiles(root: string): string[] {
  return readdirSync(root).flatMap(name => {
    const file = path.join(root, name);
    if (name === 'node_modules' || name === 'dist' || name === '.git') return [];
    return statSync(file).isDirectory() ? sourceFiles(file) : [file];
  });
}

test('legacy analyze route and Gemini implementation references are removed', () => {
  assert.equal(existsSync(path.resolve('api/analyze.ts')), false);
  const files = [
    path.resolve('server.ts'), path.resolve('package.json'), path.resolve('.env.example'),
    path.resolve('README.md'), path.resolve('metadata.json'), path.resolve('CONTRIBUTING.md'),
    ...sourceFiles(path.resolve('src')), ...sourceFiles(path.resolve('api')), ...sourceFiles(path.resolve('docs')),
  ];
  const combined = files.map(file => readFileSync(file, 'utf8')).join('\n');
  assert.doesNotMatch(combined, /gemini|@google\/genai|\/api\/analyze|AiAnalysisResult/i);
});

test('a successful current assessment can be explicitly included', () => {
  const current = record();
  const updated = setInvestigationReportInclusion([current], current, true);
  assert.equal(updated[0].includedInReport, true);
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
