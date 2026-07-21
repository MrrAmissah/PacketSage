import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { writeReportMarkdown } from '../src/lib/reportClipboard';

const root = new URL('../', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, root), 'utf8');

test('successful clipboard writes report success', async () => {
  let written = '';
  const result = await writeReportMarkdown({ writeText: async value => { written = value; } }, '# Report');
  assert.deepEqual(result, { ok: true, message: 'Markdown copied.' });
  assert.equal(written, '# Report');
});

test('rejected clipboard writes return an honest bounded failure', async () => {
  const result = await writeReportMarkdown({ writeText: async () => { throw new DOMException('blocked', 'NotAllowedError'); } }, '# Report');
  assert.deepEqual(result, { ok: false, message: 'Could not copy Markdown. Clipboard access was denied.' });
  assert.doesNotMatch(result.message, /NotAllowedError|stack|DOMException/);
});

test('successful clipboard retry replaces a prior failure', async () => {
  let attempts = 0;
  const clipboard = {
    writeText: async () => {
      attempts += 1;
      if (attempts === 1) throw new Error('denied');
    },
  };
  assert.equal((await writeReportMarkdown(clipboard, '# Report')).ok, false);
  assert.deepEqual(await writeReportMarkdown(clipboard, '# Report'), { ok: true, message: 'Markdown copied.' });
});

test('Report Builder announces clipboard failure and remains retryable', () => {
  const reportBuilder = source('src/components/ReportBuilder.tsx');
  assert.match(reportBuilder, /data-testid="copy-markdown-status"/);
  assert.match(reportBuilder, /role=\{copyFeedback\.ok \? 'status' : 'alert'\}/);
  assert.match(reportBuilder, /onClick=\{copyMarkdown\}/);
  assert.match(reportBuilder, /setCopyFeedback\(null\)[\s\S]*writeReportMarkdown/);
});

test('print layout removes screen padding and tightens section rhythm without indivisible sections', () => {
  const css = source('src/index.css');
  const print = css.slice(css.indexOf('@media print'));
  assert.match(print, /\.report-document \{[\s\S]*padding: 0 !important/);
  assert.match(print, /\.report-document > \* \+ \* \{[\s\S]*margin-top: 1\.25rem !important/);
  assert.match(print, /\[data-testid="included-investigation"\] > \* \+ \*[\s\S]*margin-top: 0\.625rem !important/);
  assert.match(print, /\[aria-labelledby="report-recommendations"\] li[\s\S]*padding: 0\.625rem !important/);
  assert.match(print, /\[data-report-marker="late"\] > \* \+ \*[\s\S]*margin-top: 0\.5rem !important/);
  assert.match(print, /\[data-report-boundary="relationships"\],[\s\S]*\[data-report-boundary="timeline"\][\s\S]*break-after: avoid/);
  assert.doesNotMatch(print, /\.report-document section,[\s\S]*break-inside: avoid/);
});

test('print report exposes retained model provenance while screen details remain optional', () => {
  const reportBuilder = source('src/components/ReportBuilder.tsx');
  assert.match(reportBuilder, /<details className="mt-2 text-\[9px\] text-text-muted print:hidden">/);
  assert.match(reportBuilder, /hidden text-\[9px\] text-text-muted print:block">AI provenance — Provider:/);
});

test('PDF verification deliberately dismisses the tour and enforces populated assessment pages', () => {
  const verifier = source('scripts/verify-report-pdf.mjs');
  assert.match(verifier, /Close guided tour/);
  assert.match(verifier, /timeout: 30_000/);
  assert.match(verifier, /nearEmptyPage[\s\S]*< 140/);
  assert.match(verifier, /orphaned from meaningful following content/);
  assert.match(verifier, /Included assessment provider provenance is missing/);
  assert.match(verifier, /Included assessment evidence citations are missing/);
});
