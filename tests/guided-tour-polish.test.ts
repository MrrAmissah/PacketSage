import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { deriveGuidedTourWorkflowIndex, guidedTourProgressControl, type GuidedTourWorkflowState } from '../src/lib/guidedTour';

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

test('spotlight target ring has no white background plate or canvas-colored offset', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  const ring = tour.match(/data-testid="spotlight-target-ring"[^>]+className="([^"]+)"/)?.[1] || '';
  assert.match(ring, /ring-2 ring-accent-primary/);
  assert.doesNotMatch(ring, /ring-offset|bg-(?:white|surface|canvas)|rgba\(255/);
  assert.doesNotMatch(tour, /rect\.(?:top|bottom|left|right) [+-] 6/);
});

test('spotlight renders no white connector, triangle, or seam', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.doesNotMatch(tour, /connector|triangle|border-white|rgba\(255|rotate-45|clip-path/i);
  assert.doesNotMatch(tour, /ring-black\/5/);
});

test('technical Focus highlighted control wording is removed from the primary CTA', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.doesNotMatch(tour, /Focus highlighted control/);
  assert.match(tour, /handlePrimaryProgression/);
});

test('restrained Focus target remains outside the primary footer hierarchy', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.match(tour, />Focus target<\/button>/);
  assert.ok(tour.indexOf('>Focus target</button>') < tour.indexOf('data-testid="guided-tour-footer"'));
  assert.match(tour, /text-text-muted/);
});

test('Step 1 provides Review signal and continue', () => {
  assert.deepEqual(guidedTourProgressControl(0, 0), {
    label: 'Review signal and continue', enabled: true, requirement: null,
  });
});

test('Step 1 invokes only safe recommended-signal selection and then advances', () => {
  const app = source('src/App.tsx');
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.match(app, /handleTourReviewSignal[\s\S]*signalId: recommendedGuidedSignal\.id,[\s\S]*focusTarget: 'investigation'/);
  assert.match(tour, /onReviewSignal\(\);[\s\S]*moveToStep\(1\)/);
  assert.doesNotMatch(tour.slice(tour.indexOf('if (displayStepIndex === 0)'), tour.indexOf('if (displayStepIndex === 1)')), /workflowIndex >= 1/);
  assert.equal(deriveGuidedTourWorkflowIndex(workflow({ selectedSignalId: 'signal-a' })), 1);
});

test('Step 2 Next contains no route that can start AI', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.equal(guidedTourProgressControl(1, 1).label, 'Next');
  assert.doesNotMatch(tour, /fetch\(|\/api\/investigate|handleInvestigate|\.click\(/);
});

test('Step 2 Next stays disabled before a valid retained assessment', () => {
  const control = guidedTourProgressControl(1, 1);
  assert.equal(control.enabled, false);
  assert.match(control.requirement || '', /Complete the highlighted investigation/);
  assert.match(source('src/components/ContextualSpotlightTour.tsx'), /disabled=\{!progressControl\.enabled\}/);
});

test('failed or malformed output cannot enable Step 2 Next', () => {
  const state = workflow({ selectedSignalId: 'signal-a', completedInvestigationSignalIds: [] });
  const index = deriveGuidedTourWorkflowIndex(state);
  assert.equal(index, 1);
  assert.equal(guidedTourProgressControl(1, index!).enabled, false);
  assert.match(guidedTourProgressControl(1, index!).requirement || '', /Failed or invalid responses/);
});

test('Step 3 provides Open assessment and continue', () => {
  assert.deepEqual(guidedTourProgressControl(2, 2), {
    label: 'Open assessment and continue', enabled: true, requirement: null,
  });
});

test('Step 3 opens the matching workspace without including the assessment', () => {
  const app = source('src/App.tsx');
  const signals = source('src/components/SuspiciousSignals.tsx');
  const handler = app.slice(app.indexOf('const handleTourOpenAssessment'), app.indexOf('const renderActiveContent'));
  assert.match(handler, /focusTarget: 'open-assessment'/);
  assert.doesNotMatch(handler, /handleInvestigationInclusion|onInvestigationInclusionChange|includedInReport/);
  assert.match(signals, /shouldOpenAssessment[\s\S]*setFullAssessmentOpen\(shouldOpenAssessment\)/);
});

test('Step 4 Finish remains unavailable before explicit inclusion', () => {
  const control = guidedTourProgressControl(3, 3);
  assert.equal(control.label, 'Finish tour');
  assert.equal(control.enabled, false);
  assert.match(control.requirement || '', /Include the assessment/);
});

test('Finish closes and persists only after explicit inclusion', () => {
  assert.equal(guidedTourProgressControl(3, 4).enabled, true);
  const app = source('src/App.tsx');
  assert.match(app, /localStorage\.setItem\(GUIDED_TOUR_STORAGE_KEY, GUIDED_TOUR_COMPLETION_VALUE\)/);
  assert.doesNotMatch(app, /guidedTourWorkflowIndex !== 4[\s\S]*finishGuidedTour/);
  assert.match(source('src/components/ContextualSpotlightTour.tsx'), /displayStepIndex === 2[\s\S]*onOpenAssessment\(\)[\s\S]*onComplete\(\)/);
});

test('Back and Skip retain independent secondary actions', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.match(tour, /moveToStep\(displayStepIndex - 1\)/);
  assert.match(tour, />Back<\/button>/);
  assert.match(tour, />Skip tour<\/button>/);
  assert.doesNotMatch(tour, /onDismiss=\{handlePrimaryProgression\}/);
});

test('Light and Dark spotlight visuals use semantic surfaces without a white halo', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  const css = source('src/index.css');
  assert.match(tour, /border-border-subtle bg-surface[\s\S]*text-text-primary/);
  assert.match(tour, /rgba\(0,98,241,0\.24\)/);
  assert.doesNotMatch(tour, /bg-white|border-white|rgba\(255/);
  assert.match(css, /\.dark[\s\S]*--bg-surface:/);
});

test('desktop and 390 px footers use a fixed three-column hierarchy without wrapping', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  const footerStart = tour.lastIndexOf('<div', tour.indexOf('data-testid="guided-tour-footer"'));
  const footer = tour.slice(footerStart, tour.indexOf('</div>', footerStart) + 6);
  assert.match(tour, /grid-cols-\[auto_1fr_auto\][^\n]+data-testid="guided-tour-footer"/);
  assert.match(footer, /whitespace-nowrap/);
  assert.doesNotMatch(footer, /flex-wrap|min-w-\[(?:4|5|6|7|8|9)\d\dpx\]/);
  assert.match(tour, /Math\.min\(CALLOUT_MAX_WIDTH, window\.innerWidth - EDGE_GAP \* 2\)/);
});

test('Replay returns Step 1 to an unselected signal list without erasing workflow progress', () => {
  const app = source('src/App.tsx');
  const handler = app.slice(app.indexOf('const handleReplayGuidedTour'), app.indexOf('const handleTourDisplayStepChange'));
  assert.match(handler, /signalId: recommendedGuidedSignal\.id,[\s\S]*focusTarget: 'signal-list'/);
  assert.doesNotMatch(handler, /selectedSignalId:\s*null|setInvestigations|setGuideSession/);
});

test('Back to Step 1 also restores the uncluttered signal-list presentation', () => {
  const app = source('src/App.tsx');
  const handler = app.slice(app.indexOf('const handleTourDisplayStepChange'), app.indexOf('const handleTimelineFocusHandled'));
  assert.match(handler, /stepIndex === 0[\s\S]*focusTarget: 'signal-list'/);
});

test('signal-list presentation action closes drawers without reporting a new signal selection', () => {
  const signals = source('src/components/SuspiciousSignals.tsx');
  const action = signals.slice(signals.indexOf("guidedSignalAction.focusTarget === 'signal-list'"), signals.indexOf('const shouldOpenAssessment'));
  assert.match(action, /setFullAssessmentOpen\(false\)/);
  assert.match(action, /onAssessmentWorkspaceChange\?\.\(null\)/);
  assert.match(action, /setSelectedSignal\(null\)/);
  assert.doesNotMatch(action, /onSignalSelected/);
});

test('desktop Step 1 spotlights the full keyboard-operable signal row', () => {
  const signals = source('src/components/SuspiciousSignals.tsx');
  const desktopRow = signals.slice(signals.indexOf('<tr\n                        id={`signal-row-'), signals.indexOf('{/* Severity badge column */}'));
  assert.match(desktopRow.slice(0, desktopRow.indexOf('<td')), /data-tour-target=\{recommendedSignalId === sig\.id/);
  assert.match(desktopRow, /role="button"[\s\S]*tabIndex=\{0\}/);
});

test('oversized signal rows are clipped to their visible scroll container', () => {
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.match(tour, /function visibleTargetRect\(target: HTMLElement\): DOMRect/);
  assert.match(tour, /\(auto\|scroll\|hidden\|clip\).*style\.overflowX/);
  assert.match(tour, /right = Math\.min\(right, ancestorRect\.right\)/);
  assert.match(tour, /rect\.left >= EDGE_GAP[\s\S]*rect\.right <= window\.innerWidth - EDGE_GAP/);
});
