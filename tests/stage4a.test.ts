import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { completedCaptureOverview, validateCaptureOverviewResponse } from '../src/lib/captureOverview';
import { deterministicId } from '../src/lib/deterministic';
import { InvestigationRequestCoordinator } from '../src/lib/investigationRequests';
import { createJudgePathSession, deriveJudgePathProgress, shouldShowGuidedJourney } from '../src/lib/judgePath';
import { parseDemoData } from '../src/lib/parser';
import { buildReportModel } from '../src/lib/report';

const root = new URL('../', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, root), 'utf8');

test('bundled guided sample satisfies the stable evidence contract', () => {
  const first = parseDemoData();
  const second = parseDemoData();
  const expectedEvidenceId = deterministicId('evidence', [
    first.evidence.name, first.evidence.type, first.evidence.size,
    first.evidence.parseMode, first.evidence.sourceFormat,
  ]);

  assert.equal(first.evidence.name, 'guided_defensive_analysis_sample.json');
  assert.equal(first.evidence.id, expectedEvidenceId);
  assert.equal(first.evidence.id, second.evidence.id);
  assert.equal(first.evidence.checksumStatus, 'demo-not-applicable');
  assert.deepEqual(
    [first.events.length, first.flows.length, first.dns.length, first.http.length, first.tls.length, first.signals.length],
    [40, 34, 19, 1, 2, 13],
  );
  assert.ok(first.events.every((event, index) => index === 0 || first.events[index - 1].timestamp <= event.timestamp));
  assert.deepEqual(first.events.map(event => event.id), second.events.map(event => event.id));
  assert.deepEqual(first.flows.map(flow => flow.id), second.flows.map(flow => flow.id));
  assert.deepEqual(first.signals.map(signal => signal.id), second.signals.map(signal => signal.id));

  const flowIds = new Set(first.flows.map(flow => flow.id));
  const eventIds = new Set(first.events.map(event => event.id));
  assert.ok(first.signals.some(signal => signal.relatedFlowIds?.some(id => flowIds.has(id))));
  assert.ok(first.signals.some(signal => signal.relatedEventIds?.some(id => eventIds.has(id))));
  assert.ok(first.signals.some(signal => signal.relatedFlowIds?.length && signal.relatedEventIds?.length));
});

test('guided progress derives only from real workflow state and uses correct destinations', () => {
  const loaded = deriveJudgePathProgress({ evidenceLoaded: true, signalSelected: false, investigationIncluded: false, reportVisited: false });
  assert.equal(loaded.completedCount, 1);
  assert.deepEqual(loaded.nextAction, { label: 'Review signals', destination: 'signals' });

  const selected = deriveJudgePathProgress({ evidenceLoaded: true, signalSelected: true, investigationIncluded: false, reportVisited: false });
  assert.equal(selected.completedCount, 2);
  assert.equal(selected.nextAction.destination, 'signals');

  const included = deriveJudgePathProgress({ evidenceLoaded: true, signalSelected: true, investigationIncluded: true, reportVisited: false });
  assert.equal(included.completedCount, 3);
  assert.deepEqual(included.nextAction, { label: 'Build report', destination: 'report' });
});

test('guide dismissal is session-scoped and replacement evidence resets it', () => {
  const first = { ...createJudgePathSession('evidence-a'), dismissed: true, signalSelected: true, reportVisited: true };
  assert.equal(shouldShowGuidedJourney('demo', first), false);
  const replacement = createJudgePathSession('evidence-b');
  assert.deepEqual(replacement, { evidenceIdentity: 'evidence-b', dismissed: false, signalSelected: false, reportVisited: false });
  assert.equal(shouldShowGuidedJourney('demo', replacement), true);
  assert.equal(shouldShowGuidedJourney('pcap', replacement), false);
});

test('Capture Overview remains optional and never advances the primary stages', () => {
  const before = deriveJudgePathProgress({ evidenceLoaded: true, signalSelected: true, investigationIncluded: false, reportVisited: false });
  assert.deepEqual(before.stages.map(stage => stage.id), ['evidence', 'signal', 'investigation', 'report']);
  assert.equal(before.completedCount, 2);
});

test('model output remains excluded from reports until explicit inclusion', () => {
  const demo = parseDemoData();
  const validated = validateCaptureOverviewResponse({
    provider: 'Google', model: 'test-model', result: {
      executiveSummary: 'Summary', whatHappened: 'Pattern', normalActivity: 'Routine', suspiciousActivity: 'Review',
      analystQuestions: 'Question', recommendedChecks: 'Check', beginnerExplanation: 'Beginner', technicalExplanation: 'Technical',
      confidence: 'medium', limitations: 'Limited',
    },
  });
  const overview = completedCaptureOverview(demo.evidence.id, validated);
  assert.equal(overview.includedInReport, false);
  const report = buildReportModel(demo, [], {}, overview);
  assert.equal(report.contextualOverview, null);
  assert.equal(report.assessments.length, 0);
});

test('duplicate investigation requests are blocked while a request is active and Retry remains possible', () => {
  const coordinator = new InvestigationRequestCoordinator();
  const context = { signalId: 'signal-1', packetIdentity: 'packet-1' };
  const first = coordinator.begin(context);
  assert.ok(first);
  assert.equal(coordinator.begin(context), null);
  assert.equal(coordinator.settle(first, context), true);
  assert.ok(coordinator.begin(context));
});

test('Capture Overview blocks duplicate clicks while active and keeps Retry available after settlement', () => {
  const overviewSource = source('src/components/CaptureOverview.tsx');
  assert.match(overviewSource, /if \(activeController\.current\) return/);
  assert.match(overviewSource, /finally[\s\S]*activeController\.current === controller[\s\S]*activeController\.current = null/);
  assert.match(overviewSource, />Retry</);
});

test('malformed model output cannot create retained output or advance guided progress', () => {
  assert.throws(() => validateCaptureOverviewResponse({ provider: 'Google', model: '', result: {} }), /provenance/i);
  const progress = deriveJudgePathProgress({ evidenceLoaded: true, signalSelected: true, investigationIncluded: false, reportVisited: false });
  assert.equal(progress.stages.find(stage => stage.id === 'investigation')?.complete, false);
});

test('primary judge-path labels remain provider-neutral with truthful sample wording', () => {
  const activeUi = [
    source('src/components/GuidedSampleJourney.tsx'),
    source('src/components/EvidenceImport.tsx'),
    source('src/components/CaptureOverview.tsx'),
    source('src/components/InvestigationAssessment.tsx'),
    source('src/components/ReportBuilder.tsx'),
  ].join('\n');
  assert.match(activeUi, /Load guided investigation sample/);
  assert.match(activeUi, /Evidence-grounded investigation/i);
  assert.doesNotMatch(activeUi, />\s*(?:Google|Gemini|OpenAI|GPT)[^<]*</i);
  assert.doesNotMatch(JSON.stringify(parseDemoData()), /confirmed (?:compromise|malware|command and control|credential theft|data exfiltration)/i);
});

test('browser source contains no AI credential identifiers', () => {
  const browserSource = [
    source('src/App.tsx'),
    source('src/components/CaptureOverview.tsx'),
    source('src/components/SuspiciousSignals.tsx'),
  ].join('\n');
  assert.doesNotMatch(browserSource, /(?:OPENAI|GEMINI)_API_KEY|VITE_(?:OPENAI|GEMINI)_API_KEY/);
});
