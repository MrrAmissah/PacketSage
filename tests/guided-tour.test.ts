import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  GUIDED_TOUR_COMPLETION_VALUE,
  GUIDED_TOUR_STEPS,
  createGuidedTourSession,
  deriveGuidedTourWorkflowIndex,
  guidedTourProgressControl,
  replayGuidedTourSession,
  shouldShowGuidedTour,
  type GuidedTourWorkflowState,
} from '../src/lib/guidedTour';
import { deriveJudgePathProgress } from '../src/lib/judgePath';

const root = new URL('../', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, root), 'utf8');
const workflow = (overrides: Partial<GuidedTourWorkflowState> = {}): GuidedTourWorkflowState => ({
  parseMode: 'demo',
  evidenceIdentity: 'evidence-a',
  recommendedSignalId: 'signal-a',
  selectedSignalId: null,
  completedInvestigationSignalIds: [],
  includedInvestigationSignalIds: [],
  assessmentWorkspaceSignalId: null,
  ...overrides,
});

test('new guided progression wording is rendered from unchanged inclusion rules', () => {
  const progress = deriveJudgePathProgress({ evidenceLoaded: true, recommendedSignalId: 'signal-a', selectedSignalId: null, includedInvestigationSignalIds: [], reportVisitedAfterInclusion: false });
  assert.equal(progress.stages.find(stage => stage.id === 'investigation')?.label, 'Investigate and include assessment');
  assert.equal(progress.status.items.find(item => item.id === 'signal')?.label, 'Recommended signal review');
  assert.equal(progress.stages.find(stage => stage.id === 'investigation')?.complete, false);
  assert.match(source('src/components/GuidedSampleJourney.tsx'), /\{stage\.label\}/);
});

test('tour appears for a fresh generated sample', () => {
  const session = createGuidedTourSession('demo', 'evidence-a', null);
  assert.ok(session);
  assert.equal(shouldShowGuidedTour(session, 'demo', 'evidence-a'), true);
});

test('tour never appears for custom evidence', () => {
  assert.equal(createGuidedTourSession('pcap', 'evidence-a', null), null);
  assert.equal(createGuidedTourSession('txt', 'evidence-a', null), null);
});

test('Step 1 targets the existing recommended-signal action', () => {
  assert.deepEqual(GUIDED_TOUR_STEPS[0], {
    id: 'signal',
    target: 'recommended-signal-action',
    title: 'Start with a deterministic signal',
    copy: 'PacketSage has linked this signal to exact flows and events. Review the evidence before asking AI to assist.',
  });
  assert.match(source('src/components/GuidedSampleJourney.tsx'), /data-tour-target=\{progress\.nextAction\.id === 'review-recommended-signal' \? 'recommended-signal-action'/);
});

test('selecting another signal cannot advance Step 1', () => {
  assert.equal(deriveGuidedTourWorkflowIndex(workflow({ selectedSignalId: 'signal-b' })), 0);
});

test('Step 2 targets the manual investigation trigger only after exact recommendation selection', () => {
  assert.equal(deriveGuidedTourWorkflowIndex(workflow({ selectedSignalId: 'signal-a' })), 1);
  assert.equal(GUIDED_TOUR_STEPS[1].target, 'investigation-trigger');
  assert.match(source('src/components/SuspiciousSignals.tsx'), /data-tour-target="investigation-trigger"[\s\S]*onClick=\{handleInvestigate\}/);
});

test('no tour control starts an AI request', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.doesNotMatch(tour, /fetch\(|\/api\/investigate|handleInvestigate|\.click\(/);
  assert.match(tour, /The highlighted control remains live and keyboard reachable/);
});

test('failed or malformed investigations cannot advance without a retained completion', () => {
  const index = deriveGuidedTourWorkflowIndex(workflow({ selectedSignalId: 'signal-a' }));
  assert.equal(index, 1);
  assert.equal(guidedTourProgressControl(1, index!).enabled, false);
  assert.match(guidedTourProgressControl(1, index!).requirement || '', /valid response/);
});

test('Step 3 is reachable only for the exact valid retained assessment', () => {
  assert.equal(deriveGuidedTourWorkflowIndex(workflow({ selectedSignalId: 'signal-a', completedInvestigationSignalIds: ['signal-b'] })), 1);
  assert.equal(deriveGuidedTourWorkflowIndex(workflow({ selectedSignalId: 'signal-a', completedInvestigationSignalIds: ['signal-a'] })), 2);
  assert.equal(GUIDED_TOUR_STEPS[2].target, 'open-full-assessment');
});

test('opening the full assessment remains a manual live-control action', () => {
  assert.equal(deriveGuidedTourWorkflowIndex(workflow({ selectedSignalId: 'signal-a', completedInvestigationSignalIds: ['signal-a'], assessmentWorkspaceSignalId: null })), 2);
  const compact = source('src/components/CompactInvestigationResult.tsx');
  assert.match(compact, /data-tour-target="open-full-assessment"[\s\S]*onClick=\{onOpen\}/);
});

test('Step 4 targets explicit report inclusion only after the exact workspace opens', () => {
  assert.equal(deriveGuidedTourWorkflowIndex(workflow({ selectedSignalId: 'signal-a', completedInvestigationSignalIds: ['signal-a'], assessmentWorkspaceSignalId: 'signal-a' })), 3);
  assert.equal(deriveGuidedTourWorkflowIndex(workflow({ selectedSignalId: 'signal-a', completedInvestigationSignalIds: ['signal-a'], assessmentWorkspaceSignalId: 'signal-b' })), 2);
  assert.equal(GUIDED_TOUR_STEPS[3].target, 'assessment-report-inclusion');
});

test('assessment inclusion remains manual and is the only completion transition', () => {
  const before = workflow({ selectedSignalId: 'signal-a', completedInvestigationSignalIds: ['signal-a'], assessmentWorkspaceSignalId: 'signal-a' });
  assert.equal(deriveGuidedTourWorkflowIndex(before), 3);
  assert.equal(deriveGuidedTourWorkflowIndex({ ...before, includedInvestigationSignalIds: ['signal-a'] }), 4);
  assert.match(source('src/components/EvidenceGroundedAssessment.tsx'), /data-tour-target="assessment-report-inclusion"[\s\S]*onClick=\{\(\) => onInclusionChange/);
});

test('Capture Overview cannot advance the state-driven tour', () => {
  assert.equal(deriveGuidedTourWorkflowIndex(workflow()), 0);
  assert.doesNotMatch(source('src/lib/guidedTour.ts'), /captureOverview|Gemini|overviewRecord/);
});

test('Skip or finish without AI closes the tour and stores only the versioned completion preference', () => {
  const app = source('src/App.tsx');
  assert.match(app, /localStorage\.setItem\(GUIDED_TOUR_STORAGE_KEY, GUIDED_TOUR_COMPLETION_VALUE\)/);
  assert.match(app, /setGuidedTourSession\(previous => previous \? \{ \.\.\.previous, active: false \}/);
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.match(tour, /Finish without AI/);
  assert.match(tour, /'Skip tour'/);
  assert.equal(createGuidedTourSession('demo', 'evidence-a', GUIDED_TOUR_COMPLETION_VALUE)?.active, false);
});

test('Escape closes the tour through the same dismissal boundary', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.match(tour, /event\.key !== 'Escape'/);
  assert.match(tour, /event\.preventDefault\(\);\s*onDismiss\(\)/);
});

test('Replay restarts a dismissed tour without mutating retained content', () => {
  assert.deepEqual(replayGuidedTourSession('evidence-a', 7), { evidenceIdentity: 'evidence-a', active: true, replay: true, requestId: 7 });
  const app = source('src/App.tsx');
  const commandCenter = source('src/components/CommandCenter.tsx');
  assert.match(commandCenter, /data-testid="guided-tour-replay"/);
  assert.match(commandCenter, />\s*Replay tour\s*</);
  assert.match(app, /onReplayTour=\{commandCenterReplay\}/);
  const preferenceWrite = app.slice(app.indexOf('const finishGuidedTour'), app.indexOf('const handleDataParsed'));
  assert.doesNotMatch(preferenceWrite, /assessment|citation|reportContent|signalContent|JSON\.stringify/);
});

test('dismissed journey replay is integrated into Command Center without a detached spacer row', () => {
  const app = source('src/App.tsx');
  const commandCenter = source('src/components/CommandCenter.tsx');
  assert.doesNotMatch(app, /className="mb-3 flex justify-end print:hidden"/);
  assert.match(commandCenter, /Evidence decoded[\s\S]*data-testid="guided-tour-replay"/);
  assert.match(commandCenter, /isDemo && onReplayTour/);
  assert.match(commandCenter, /id="command-center-workspace"[^>]+pb-6/);
  assert.doesNotMatch(commandCenter, /id="command-center-workspace"[^>]+py-6/);
});

test('evidence replacement closes an active tour immediately', () => {
  const session = createGuidedTourSession('demo', 'evidence-a', null);
  assert.equal(shouldShowGuidedTour(session, 'demo', 'evidence-b'), false);
  assert.match(source('src/App.tsx'), /setGuidedTourSession\(createGuidedTourSession\(data\.evidence\.parseMode, data\.evidence\.id/);
});

test('stale evidence identity cannot expose a spotlight target', () => {
  const session = replayGuidedTourSession('old-evidence', 3);
  assert.equal(shouldShowGuidedTour(session, 'demo', 'current-evidence'), false);
  assert.equal(shouldShowGuidedTour(session, 'pcap', 'old-evidence'), false);
});

test('reduced-motion users receive no tour transition or forced smooth scrolling', () => {
  const combined = `${source('src/components/ContextualSpotlightTour.tsx')}\n${source('src/components/SuspiciousSignals.tsx')}`;
  assert.match(combined, /motion-reduce:transition-none/);
  assert.match(combined, /prefers-reduced-motion: reduce/);
  assert.match(combined, /\? 'auto' : 'smooth'/);
});

test('tour and replay content are absent from Print and PDF output', () => {
  const css = source('src/index.css');
  assert.match(css, /\[data-testid="contextual-spotlight-tour"\]/);
  assert.match(css, /\[data-testid="guided-tour-replay"\]/);
  assert.match(source('src/components/ContextualSpotlightTour.tsx'), /print:hidden/);
});

test('desktop callout positioning clamps every edge of the viewport', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.match(tour, /Math\.min\([\s\S]*Math\.max\([\s\S]*EDGE_GAP/);
  assert.match(tour, /window\.innerHeight - height - EDGE_GAP/);
  assert.match(tour, /max-h-\[calc\(100vh-24px\)\]/);
});

test('approximately 390 px layout uses a viewport-bounded width without global overflow', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.match(tour, /Math\.min\(CALLOUT_MAX_WIDTH, window\.innerWidth - EDGE_GAP \* 2\)/);
  assert.match(tour, /overflow-y-auto/);
  assert.doesNotMatch(tour, /min-w-\[|w-\[(?:4|5|6|7|8|9)\d\dpx\]/);
});

test('Light and Dark modes preserve semantic spotlight contrast', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  const css = source('src/index.css');
  assert.match(tour, /bg-surface[\s\S]*text-text-primary[\s\S]*border-border-subtle/);
  assert.match(css, /:root[\s\S]*--bg-surface:[\s\S]*\.dark[\s\S]*--bg-surface:/);
});

test('soft ash and slate informational Flow Explorer risk treatment remains unchanged', () => {
  const flowExplorer = source('src/components/FlowExplorer.tsx');
  assert.match(flowExplorer, /info: 'border-border-subtle bg-surface-muted text-text-muted'/);
  assert.doesNotMatch(flowExplorer, /info: '[^']*(?:status-info|blue|sky|cyan)/);
});
