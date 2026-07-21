import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');

test('loaded evidence filename uses a compact responsive width and visual ellipsis', () => {
  assert.match(app, /data-testid="evidence-filename"[\s\S]*?max-w-\[clamp\(7rem,10vw,12rem\)\]/);
  assert.match(app, /aria-hidden="true" className="min-w-0 truncate">\{parsedData\.evidence\.name\}/);
});

test('loaded evidence filename exposes the unmodified full value on hover and focus', () => {
  assert.match(app, /aria-label={`Loaded evidence: \$\{parsedData\.evidence\.name\}`}/);
  assert.match(app, /tabIndex=\{0\}/);
  assert.match(app, /aria-describedby="workspace-evidence-filename-tooltip"/);
  assert.match(app, /role="tooltip"[^>]+group-hover:visible[^>]+group-focus-visible:visible/);
  assert.match(app, /Full filename: \{parsedData\.evidence\.name\}/);
});

test('global utility cluster is the non-shrinking grid column', () => {
  assert.match(app, /grid-cols-1 sm:grid-cols-\[minmax\(0,1fr\)_auto\]/);
  assert.match(app, /data-testid="header-actions"[^>]+shrink-0 flex-nowrap/);
});

test('retention is separated from the theme selector by the protected gutter', () => {
  assert.match(app, /data-testid="workspace-status-header"[^>]+gap-x-4 xl:gap-x-6/);
  assert.match(app, /data-testid="header-actions"[^>]+sm:border-l[^>]+sm:pl-4 xl:pl-6/);
  assert.ok(app.indexOf('data-testid="header-retention"') < app.indexOf('data-testid="theme-selector"'));
});

test('empty state retains evidence, parser, assessment, and retention values', () => {
  for (const value of ['None loaded', 'Idle', 'N/A', 'Volatile']) assert.match(app, new RegExp(value));
});

test('loaded state retains filename, parser, assessment count, and retention', () => {
  assert.match(app, /parsedData\.evidence\.name/);
  assert.match(app, /parsedData\.evidence\.parseMode/);
  assert.match(app, /investigations\.filter\(record => record\.includedInReport\)\.length/);
  assert.equal((app.match(/data-testid="header-retention"/g) ?? []).length, 2);
});

test('laptop state metadata wraps without entering the utility column', () => {
  assert.match(app, /data-testid="evidence-status-strip"[^>]+flex flex-wrap[^>]+min-w-0 w-full/);
  assert.doesNotMatch(app, /data-testid="evidence-status-strip"[^>]+overflow-x-auto/);
});

test('mobile header deliberately stacks state above controls', () => {
  assert.match(app, /grid grid-cols-1 sm:grid-cols-\[minmax\(0,1fr\)_auto\]/);
  assert.match(app, /data-testid="header-actions"[^>]+w-full[^>]+sm:w-auto/);
});

test('theme selector preserves light dark and system controls in one readable group', () => {
  assert.match(app, /data-testid="theme-selector"[^>]+shrink-0/);
  for (const label of ['Light', 'Dark', 'System']) assert.match(app, new RegExp(`label: '${label}'`));
  assert.match(app, /<span className="hidden 2xl:inline">\{t\.label\}<\/span>/);
});

test('header actions remain native keyboard controls with accessible theme names', () => {
  assert.match(app, /aria-label={`Use \$\{t\.label\.toLowerCase\(\)\} theme`}/);
  assert.match(app, /data-testid="build-report-action"[\s\S]*?<\/button>/);
  assert.doesNotMatch(app, /data-testid="header-actions"[^>]+overflow-hidden/);
});

test('local capture status remains visible in narrow and loaded layouts', () => {
  assert.match(app, /data-testid="local-capture-status"[^>]+role="status"[^>]+aria-label="Local capture decoding is active"/);
  assert.doesNotMatch(app, /data-testid="local-capture-status"[^>]+hidden/);
});

test('workspace header correction leaves the contextual spotlight tour mounted', () => {
  assert.match(app, /<GuidedSampleJourney/);
  assert.match(app, /onReplayTour=\{handleReplayGuidedTour\}/);
  assert.match(app, /onReplayTour=\{commandCenterReplay\}/);
});
