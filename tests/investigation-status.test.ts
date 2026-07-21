import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { deriveGeneralInvestigationStatus, deriveJudgePathProgress } from '../src/lib/judgePath';

const root = new URL('../', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, root), 'utf8');

const guided = (overrides: Partial<Parameters<typeof deriveJudgePathProgress>[0]> = {}) => deriveJudgePathProgress({
  evidenceLoaded: true,
  recommendedSignalId: 'sig-recommended',
  selectedSignalId: null,
  completedInvestigationSignalIds: [],
  includedInvestigationSignalIds: [],
  reportVisitedAfterInclusion: false,
  ...overrides,
});

test('guided journey and persistent status share one progression action', () => {
  const progress = guided();
  assert.deepEqual(progress.status.nextAction, progress.nextAction);
  const app = source('src/App.tsx');
  assert.match(app, /\? guidedProgress\.status/);
  assert.match(app, /progress=\{guidedProgress\}/);
});

test('selecting a different signal does not advance the recommended-signal stage', () => {
  const progress = guided({ selectedSignalId: 'sig-other' });
  assert.equal(progress.completedCount, 1);
  assert.equal(progress.nextAction.id, 'review-recommended-signal');
});

test('selecting the recommended signal advances to a manual investigation action', () => {
  const progress = guided({ selectedSignalId: 'sig-recommended' });
  assert.equal(progress.completedCount, 2);
  assert.deepEqual(progress.nextAction, { id: 'run-investigation', label: 'Run evidence-grounded investigation', destination: 'signals' });
  assert.deepEqual(progress.status.items.find(item => item.id === 'assessment'), { id: 'assessment', label: 'Assessment included', value: 'Current', tone: 'indigo' });
});

test('a completed assessment remains excluded until the user includes it', () => {
  const progress = guided({ selectedSignalId: 'sig-recommended', completedInvestigationSignalIds: ['sig-recommended'] });
  assert.equal(progress.completedCount, 2);
  assert.equal(progress.nextAction.id, 'review-and-include-assessment');
  assert.equal(progress.status.items.find(item => item.id === 'assessment')?.value, 'Review required');
});

test('explicit assessment inclusion advances the report action without marking it reviewed', () => {
  const progress = guided({ selectedSignalId: 'sig-recommended', completedInvestigationSignalIds: ['sig-recommended'], includedInvestigationSignalIds: ['sig-recommended'] });
  assert.equal(progress.completedCount, 3);
  assert.deepEqual(progress.nextAction, { id: 'open-report', label: 'Build report', destination: 'report' });
  assert.equal(progress.status.items.find(item => item.id === 'assessment')?.value, 'Complete');
  assert.equal(progress.status.items.find(item => item.id === 'report')?.value, 'Ready');
});

test('visiting the report before inclusion cannot complete the report stage', () => {
  const progress = guided({ selectedSignalId: 'sig-recommended', completedInvestigationSignalIds: ['sig-recommended'], reportVisitedAfterInclusion: true });
  assert.equal(progress.completedCount, 2);
  assert.equal(progress.status.items.find(item => item.id === 'report')?.value, 'Not ready');
});

test('visiting the report after inclusion completes the guided path', () => {
  const progress = guided({ selectedSignalId: 'sig-recommended', includedInvestigationSignalIds: ['sig-recommended'], reportVisitedAfterInclusion: true });
  assert.equal(progress.completedCount, 4);
  assert.deepEqual(progress.nextAction, { id: 'open-report', label: 'Review report', destination: 'report' });
});

test('status actions navigate and focus but never start an AI request', () => {
  const app = source('src/App.tsx');
  const handler = app.match(/const handleInvestigationStatusAction[\s\S]*?\n  };/)?.[0] || '';
  assert.match(handler, /setActiveTab/);
  assert.match(handler, /setGuidedSignalAction/);
  assert.doesNotMatch(handler, /fetch|\/api\/(?:investigate|analyze)|handleInvestigationCompleted/);
});

test('status actions never include an assessment or mark a finding reviewed', () => {
  const app = source('src/App.tsx');
  const handler = app.match(/const handleInvestigationStatusAction[\s\S]*?\n  };/)?.[0] || '';
  assert.doesNotMatch(handler, /setInvestigationReportInclusion|handleInvestigationInclusion|handleUpdateSignalStatus|includedInReport/);
});

test('custom evidence receives a general action with no sample-specific recommendation', () => {
  const status = deriveGeneralInvestigationStatus({ evidenceLoaded: true, signalCount: 2, hasFlows: true, hasEvents: true, selectedSignalId: null, completedInvestigationSignalIds: [], includedInvestigationSignalIds: [], reportVisitedAfterInclusion: false });
  assert.equal(status.mode, 'general');
  assert.deepEqual(status.nextAction, { id: 'review-observed-signals', label: 'Review observed signals', destination: 'signals' });
  assert.doesNotMatch(JSON.stringify(status), /recommended signal/i);
});

test('status rows use one fixed icon shape, solid semantic tones, and one primary action', () => {
  const commandCenter = source('src/components/CommandCenter.tsx');
  const statusPanel = commandCenter.slice(commandCenter.indexOf('{/* Right Column: Persistent case workflow summary */}'));
  assert.match(commandCenter, /h-8 w-8 shrink-0 items-center justify-center rounded-lg text-white/);
  assert.match(commandCenter, /blue: 'bg-blue-600'/);
  assert.match(commandCenter, /indigo: 'bg-indigo-600'/);
  assert.match(commandCenter, /amber: 'bg-amber-500'/);
  assert.match(commandCenter, /green: 'bg-emerald-600'/);
  assert.match(commandCenter, /slate: 'bg-slate-500'/);
  assert.equal((commandCenter.match(/data-testid="investigation-status-primary-action"/g) || []).length, 1);
  assert.doesNotMatch(statusPanel, /Next analyst actions|bg-status-success-bg|animate-pulse/);
});
