import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { guidedTourProgressControl } from '../src/lib/guidedTour';

const root = new URL('../', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, root), 'utf8');

test('workspace scroll reset follows navigation identity and ignores inclusion state', () => {
  const app = source('src/App.tsx');
  const scrollEffect = app.slice(app.indexOf('workspaceScrollRef.current?.scrollTo'), app.indexOf('const finishGuidedTour'));
  const scrollBoundary = scrollEffect.slice(0, scrollEffect.indexOf('React.useEffect', 1));
  assert.match(scrollBoundary, /activeTab, parsedData\?\.evidence\.id, guideSession\?\.selectedSignalId, assessmentWorkspaceSignalId/);
  assert.doesNotMatch(scrollBoundary, /hasIncludedInvestigation|includedInvestigationSignalIds|reportVisitedAfterInclusion/);
});

test('different evidence and assessment identities remain navigation reset boundaries', () => {
  const app = source('src/App.tsx');
  assert.match(app, /workspaceScrollRef\.current\?\.scrollTo[\s\S]*parsedData\?\.evidence\.id[\s\S]*assessmentWorkspaceSignalId/);
  assert.match(app, /setAssessmentWorkspaceSignalId\(null\)[\s\S]*setActiveTab\('overview'\)/);
});

test('Step 4 stays attached to live inclusion state and enables Finish without report navigation', () => {
  const app = source('src/App.tsx');
  const tour = source('src/components/ContextualSpotlightTour.tsx');
  assert.equal(guidedTourProgressControl(3, 4).enabled, true);
  assert.match(tour, /MutationObserver\(syncTarget\)/);
  assert.match(tour, /displayStepIndex === 2[\s\S]*moveToStep\(3\)[\s\S]*onComplete\(\)/);
  assert.doesNotMatch(tour, /setActiveTab|onOpenReport|Report builder/);
  assert.match(app, /activeTab !== 'report'[\s\S]*<ContextualSpotlightTour/);
});

test('removing inclusion keeps Step 4 disabled without stale completion', () => {
  assert.equal(guidedTourProgressControl(3, 3).enabled, false);
  assert.match(guidedTourProgressControl(3, 3).requirement || '', /Include the assessment/);
});
