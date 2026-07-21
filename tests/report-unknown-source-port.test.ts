import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ReportDocument } from '../src/components/ReportBuilder';
import { parseDemoData, parseTextLog } from '../src/lib/parser';
import { buildReportModel, formatReportEndpoint, reportToMarkdown } from '../src/lib/report';
import type { InvestigationRecord } from '../src/types';

const strictLine = '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 dst_port=4444 protocol=TCP length=128';
const parsed = parseTextLog('unknown-source-port.txt', strictLine);

function source(path: string): string {
  return readFileSync(path, 'utf8');
}

function model(records: InvestigationRecord[] = []) {
  return buildReportModel(parsed, records, {}, null, {
    generatedAt: '2026-07-21T12:05:00.000Z',
    timeZone: 'UTC',
  });
}

function includedRecord(): InvestigationRecord {
  const event = parsed.events[0];
  return {
    schemaVersion: '1',
    provider: 'OpenAI',
    model: 'gpt-5.6-sol',
    generationState: 'completed',
    createdAt: '2026-07-21T12:04:00.000Z',
    selectedEvidenceId: parsed.evidence.id,
    signalId: 'sig-hotfix',
    packetIdentity: 'packet-hotfix',
    includedInReport: true,
    packet: {
      version: '1',
      signal: {
        id: 'sig-hotfix', title: 'Selected signal', severity: 'medium', confidence: 'high', category: 'Review',
        observedEvidence: 'Observed event.', interpretation: 'Review required.', whatItDoesNotProve: 'Not confirmed.',
        recommendedDefensiveCheck: 'Validate independently.', relatedFlowIds: [], relatedEventIds: [event.id],
      },
      flows: [],
      events: [event],
      dns: [], http: [], tls: [],
      limitsApplied: { flowsTruncated: false, eventsTruncated: false, protocolRecordsTruncated: false },
    },
    assessment: {
      summary: 'Retained assessment summary.',
      observedEvidence: [{ statement: 'Retained observation.', evidenceIds: [event.id] }],
      inferences: [{ statement: 'Retained inference.', confidence: 'low', evidenceIds: [event.id] }],
      uncertainties: ['Retained uncertainty.'],
      nextSteps: [{ action: 'Retained next step.', reason: 'Validate independently.' }],
    },
  };
}

test('documented strict text accepts an omitted source port', () => {
  assert.equal(parsed.events.length, 1);
});

test('omitted strict-text source port retains the normalized unknown sentinel', () => {
  assert.equal(parsed.events[0].sourcePort, 0);
});

test('report endpoint formatter labels the unknown sentinel honestly', () => {
  assert.equal(formatReportEndpoint('10.0.0.15', 0, 'unknown'), '10.0.0.15:unknown');
});

test('report endpoint formatter preserves known observed ports', () => {
  assert.equal(formatReportEndpoint('10.0.0.15', 53000, 'observed'), '10.0.0.15:53000');
});

test('report model never exposes the unknown source-port sentinel as port zero', () => {
  const timeline = model().timeline[0];
  assert.equal(timeline.source, '10.0.0.15:unknown');
  assert.equal(timeline.destination, '203.0.113.80:4444');
  assert.doesNotMatch(JSON.stringify(timeline), /10\.0\.0\.15:0(?:\D|$)/);
});

test('screen report renders the unknown source port without fabricated port zero', () => {
  const markup = renderToStaticMarkup(React.createElement(ReportDocument, { report: model() }));
  assert.match(markup, /10\.0\.0\.15:unknown/);
  assert.doesNotMatch(markup, /10\.0\.0\.15:0(?:\D|$)/);
});

test('Report Preview consumes the same sanitized report document', () => {
  const builder = source('src/components/ReportBuilder.tsx');
  assert.equal((builder.match(/<ReportDocument report=\{report\} \/>/g) || []).length, 2);
  assert.match(builder, /aria-labelledby="report-preview-title"/);
});

test('Markdown labels the unknown port and never exports the sentinel', () => {
  const markdown = reportToMarkdown(model());
  assert.match(markdown, /10\.0\.0\.15:unknown/);
  assert.doesNotMatch(markdown, /10\.0\.0\.15:0(?:\D|$)/);
});

test('focused PDF mode loads the real omitted-source-port fixture', () => {
  const verifier = source('scripts/verify-report-pdf.mjs');
  assert.match(verifier, /--unknown-source-port/);
  assert.match(verifier, /10\.0\.0\.15 -> 203\.0\.113\.80 dst_port=4444 protocol=TCP length=128/);
});

test('focused PDF mode rejects port zero and requires the unknown label', () => {
  const verifier = source('scripts/verify-report-pdf.mjs');
  assert.match(verifier, /Unknown source-port sentinel leaked into PDF output/);
  assert.match(verifier, /Unknown source port is not labelled honestly in PDF output/);
});

test('generated-sample report endpoints remain unchanged', () => {
  const demo = buildReportModel(parseDemoData(), []);
  assert.equal(demo.timeline.length, 40);
  assert.equal(demo.timeline[0].source, '10.0.0.15:51234');
  assert.equal(demo.timeline[0].destination, '10.0.0.1:53');
  assert.doesNotMatch(JSON.stringify(demo.timeline), /:unknown/);
});

test('assessment inclusion and provenance remain unchanged by report formatting', () => {
  const record = includedRecord();
  const report = model([record]);
  assert.equal(report.assessments[0], record);
  const markdown = reportToMarkdown(report);
  assert.match(markdown, /Provider: OpenAI/);
  assert.match(markdown, /Model: gpt-5\.6-sol/);
  assert.match(markdown, /Retained assessment summary\./);
});

test('report generation no longer directly interpolates raw event endpoints', () => {
  const report = source('src/lib/report.ts');
  assert.doesNotMatch(report, /\$\{event\.sourceIp\}:\$\{event\.sourcePort\}/);
  assert.doesNotMatch(report, /\$\{event\.destinationIp\}:\$\{event\.destinationPort\}/);
  assert.equal((report.match(/formatReportEndpoint\(event\./g) || []).length, 2);
});
