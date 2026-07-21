import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ReportDocument } from '../src/components/ReportBuilder';
import type { ParsedResult } from '../src/lib/parser';
import { buildReportModel, reportToMarkdown } from '../src/lib/report';
import {
  createReportDetailsSession,
  reportDetailsForEvidence,
  reportIdentityIncomplete,
} from '../src/lib/reportDetails';
import type { InvestigationRecord } from '../src/types';

function source(path: string): string {
  return readFileSync(path, 'utf8');
}

function fixture(): ParsedResult {
  return {
    evidence: {
      id: 'evidence-current', name: 'capture.pcapng', type: 'application/x-pcapng', size: 512,
      uploadedAt: '2026-07-21T10:00:00.000Z', parseMode: 'pcap', sourceFormat: 'PCAPNG',
      retentionMode: 'Browser memory only', status: 'completed', sha256: 'b'.repeat(64), checksumStatus: 'calculated',
    },
    events: [
      { id: 'evt-late', timestamp: '2026-07-21T10:02:00.000Z', sourceIp: '10.0.0.2', sourcePort: 51000, destinationIp: '203.0.113.10', destinationPort: 443, protocol: 'TCP', service: 'HTTPS', length: 128, info: 'Later event' },
      { id: 'evt-early', timestamp: '2026-07-21T09:58:00.000Z', sourceIp: '10.0.0.2', sourcePort: 53000, destinationIp: '10.0.0.1', destinationPort: 53, protocol: 'UDP', service: 'DNS', length: 74, info: 'Earlier event' },
    ],
    flows: [], dns: [], http: [], tls: [], signals: [], protocolStats: [],
  };
}

const details = createReportDetailsSession('evidence-current', {
  investigator: 'Avery Mensah',
  roleOrUnit: 'Network Defense Unit',
  organization: 'Example Response Team',
  caseReferenceId: 'CASE-2026-071',
  scopeNotes: 'Bounded review of the supplied capture.',
});

function report(records: InvestigationRecord[] = []) {
  return buildReportModel(fixture(), records, {}, null, {
    reportDetails: details,
    generatedAt: '2026-07-21T11:15:00.000Z',
    timeZone: 'Africa/Accra',
  });
}

function includedRecord(): InvestigationRecord {
  return {
    schemaVersion: '1', provider: 'OpenAI', model: 'server-model', generationState: 'completed',
    createdAt: '2026-07-21T11:10:00.000Z', selectedEvidenceId: 'evidence-current', signalId: 'sig-1',
    packetIdentity: 'packet-1', includedInReport: true,
    packet: {
      version: '1',
      signal: { id: 'sig-1', title: 'Selected deterministic signal', severity: 'medium', confidence: 'high', category: 'Review', observedEvidence: 'Exact observation.', interpretation: 'Review required.', whatItDoesNotProve: 'Not confirmed.', recommendedDefensiveCheck: 'Validate independently.', relatedFlowIds: [], relatedEventIds: ['evt-early'] },
      flows: [],
      events: [{ id: 'evt-early', timestamp: '2026-07-21T09:58:00.000Z', sourceIp: '10.0.0.2', sourcePort: 53000, destinationIp: '10.0.0.1', destinationPort: 53, protocol: 'UDP', service: 'DNS', length: 74 }],
      dns: [], http: [], tls: [], limitsApplied: { flowsTruncated: false, eventsTruncated: false, protocolRecordsTruncated: false },
    },
    assessment: {
      summary: 'Retained assessment summary.',
      observedEvidence: [{ statement: 'Retained observed statement.', evidenceIds: ['evt-early'] }],
      inferences: [{ statement: 'Retained inference.', confidence: 'low', evidenceIds: ['evt-early'] }],
      uncertainties: ['Retained uncertainty.'],
      nextSteps: [{ action: 'Retained next step.', reason: 'Validate independently.' }],
    },
  };
}

test('investigator and case details begin empty and are never fabricated', () => {
  assert.deepEqual(createReportDetailsSession('evidence-current').details, { investigator: '', roleOrUnit: '', organization: '', caseReferenceId: '', scopeNotes: '' });
});

test('saved report details appear in the in-app report document', () => {
  const markup = renderToStaticMarkup(React.createElement(ReportDocument, { report: report() }));
  for (const value of ['Avery Mensah', 'Network Defense Unit', 'Example Response Team', 'CASE-2026-071', 'Bounded review of the supplied capture.']) assert.match(markup, new RegExp(value));
});

test('Report Preview uses the same saved-detail report document', () => {
  const code = source('src/components/ReportBuilder.tsx');
  assert.equal((code.match(/<ReportDocument report=\{report\} \/>/g) || []).length, 2);
  assert.match(code, /aria-labelledby="report-preview-title"/);
});

test('saved report details appear in copied Markdown', () => {
  const markdown = reportToMarkdown(report());
  assert.match(markdown, /Investigator \/ Prepared by: Avery Mensah/);
  assert.match(markdown, /Case or reference ID: CASE-2026-071/);
  assert.match(markdown, /Report scope \/ notes: Bounded review of the supplied capture\./);
});

test('saved details are asserted in the Print and PDF verification path', () => {
  const verifier = source('scripts/verify-report-pdf.mjs');
  assert.match(verifier, /Saved case identity is missing/);
  assert.match(verifier, /Saved investigator identity is missing/);
});

test('Cancel and Escape close the editor without saving draft details', () => {
  const code = source('src/components/ReportBuilder.tsx');
  assert.match(code, /onClick=\{closeDetails\}[^>]*>Cancel</);
  assert.match(code, /event\.key === 'Escape'/);
  assert.doesNotMatch(code, /closeDetails[^\n]+onReportDetailsChange/);
});

test('evidence replacement safely reinitializes report details', () => {
  const replacement = reportDetailsForEvidence(details, 'evidence-replacement');
  assert.equal(replacement.evidenceIdentity, 'evidence-replacement');
  assert.equal(replacement.details.investigator, '');
  assert.equal(replacement.details.caseReferenceId, '');
});

test('report generation time carries an explicit timezone and offset', () => {
  const model = report();
  assert.equal(model.generation.generatedAt, '2026-07-21T11:15:00.000Z');
  assert.equal(model.generation.timeZone, 'Africa/Accra (UTC+00:00)');
});

test('evidence time range derives only from recorded event timestamps', () => {
  const model = report();
  assert.equal(model.evidence.earliestRecordedEvent, '2026-07-21T09:58:00.000Z');
  assert.equal(model.evidence.latestRecordedEvent, '2026-07-21T10:02:00.000Z');
});

test('missing identity details warn without blocking export actions', () => {
  assert.equal(reportIdentityIncomplete(createReportDetailsSession('evidence-current').details), true);
  const code = source('src/components/ReportBuilder.tsx');
  assert.match(code, /report-identity-warning/);
  assert.match(code, /Preview, Markdown and Print\/PDF remain available/);
  assert.doesNotMatch(code, /disabled=\{identityIncomplete\}/);
});

test('PacketSage version and Draft status are retained in every report model', () => {
  const model = report();
  assert.equal(model.generation.packetSageVersion, 'v1.1.0');
  assert.equal(model.generation.status, 'Draft');
  assert.match(reportToMarkdown(model), /NETWORK EVIDENCE REPORT — DRAFT/);
});

test('Timeline headings repeat through the print table-header group', () => {
  const css = source('src/index.css');
  assert.match(css, /\.report-document thead \{[\s\S]*display: table-header-group/);
  assert.match(source('scripts/verify-report-pdf.mjs'), /repeatedTimelineHeaders >= 2/);
});

test('Timeline rows remain intact while the overall table can paginate', () => {
  const css = source('src/index.css');
  assert.match(css, /\.report-document tr \{[\s\S]*break-inside: avoid/);
  assert.match(css, /\.report-document table \{[\s\S]*break-inside: auto/);
  assert.doesNotMatch(css, /\.report-document section,[\s\S]*break-inside: avoid/);
});

test('PDF verification rejects an orphan Timeline heading', () => {
  assert.match(source('scripts/verify-report-pdf.mjs'), /Timeline heading was orphaned from its first event row/);
});

test('PDF verification rejects near-empty intermediate content pages', () => {
  assert.match(source('scripts/verify-report-pdf.mjs'), /nearEmptyPage === -1/);
});

test('standard sample PDF requires every bounded Timeline event', () => {
  assert.match(source('scripts/verify-report-pdf.mjs'), /eventIds\.size === 40/);
});

test('assessment-included PDF requires every retained assessment section', () => {
  const verifier = source('scripts/verify-report-pdf.mjs');
  assert.match(verifier, /includedAssessment/);
  for (const heading of ['Assessment summary', 'Observed evidence', 'Analyst inference', 'Uncertainty / missing evidence', 'Recommended next investigative steps']) assert.match(verifier, new RegExp(heading.replace('/', '\\/')));
});

test('application chrome and guided controls remain absent from PDF', () => {
  const verifier = source('scripts/verify-report-pdf.mjs');
  assert.match(verifier, /Application navigation leaked into print output/);
  assert.match(verifier, /Application shell leaked into print output/);
  assert.match(verifier, /Guided journey leaked into print output/);
});

test('full assessment and report retain the exact same validated record object', () => {
  const retained = includedRecord();
  const model = report([retained]);
  assert.equal(model.assessments[0], retained);
  assert.equal(model.assessments[0].assessment, retained.assessment);
  assert.match(reportToMarkdown(model), /Retained observed statement/);
});

test('opening Report Builder neither invokes AI nor populates report identity', () => {
  const reportSource = source('src/components/ReportBuilder.tsx');
  assert.doesNotMatch(reportSource, /fetch\(|\/api\/investigate|\/api\/analyze/);
  assert.match(source('src/App.tsx'), /setReportDetails\(createReportDetailsSession\(data\.evidence\.id\)\)/);
  assert.doesNotMatch(source('src/lib/reportDetails.ts'), /investigator:\s*'[^']+'/);
});
