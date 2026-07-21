import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const includedAssessment = process.argv.includes('--included-assessment');
const unknownSourcePort = process.argv.includes('--unknown-source-port');
const positional = process.argv.slice(2).filter(argument => !argument.startsWith('--'));
const baseUrl = positional[0] || 'http://127.0.0.1:3000';
const pdfPath = resolve(positional[1] || (includedAssessment
  ? 'artifacts/packetsage-report-with-assessment-verification.pdf'
  : 'artifacts/packetsage-report-verification.pdf'));
const session = `packetsage-print-${process.pid}`;
mkdirSync(dirname(pdfPath), { recursive: true });

function browser(...args) {
  try {
    return execFileSync('agent-browser', ['--session', session, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 30_000,
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message.split('\n')[0] : 'unknown browser failure';
    throw new Error(`PDF browser step failed (${args.join(' ')}): ${detail}`);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function waitForText(text, timeoutMs = 75_000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (browser('get', 'text', 'body').includes(text)) return;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1_000);
  }
  throw new Error(`Timed out waiting for ${text}.`);
}

try {
  browser('open', baseUrl);
  browser('wait', '--load', 'networkidle');
  if (unknownSourcePort) {
    browser('check', 'input[type="checkbox"]:not([disabled])');
    browser('wait', '250');
    browser('fill', 'textarea', '2026-07-21T12:00:00Z 10.0.0.15 -> 203.0.113.80 dst_port=4444 protocol=TCP length=128');
    browser('eval', 'Array.from(document.querySelectorAll("button")).find(button => button.textContent?.trim() === "Submit pasted logs" && !button.disabled)?.click(); "clicked"');
    browser('wait', '--text', 'Evidence decoded');
  } else {
    browser('find', 'role', 'button', 'click', '--name', 'Load guided investigation sample');
    browser('wait', '--text', 'Command center');
    browser('wait', '[data-testid="contextual-spotlight-tour"]');
    browser('find', 'role', 'button', 'click', '--name', 'Close guided tour', '--exact');
  }
  browser('find', 'role', 'button', 'click', '--name', 'Report builder', '--exact');
  browser('wait', '--text', 'NETWORK EVIDENCE REPORT');
  browser('find', 'role', 'button', 'click', '--name', 'Edit report details');
  browser('find', 'label', 'Investigator / Prepared by', 'fill', 'Avery Mensah');
  browser('find', 'label', 'Role or unit', 'fill', 'Network Defense Unit');
  browser('find', 'label', 'Organization', 'fill', 'Example Response Team');
  browser('find', 'label', 'Case or reference ID', 'fill', 'CASE-2026-071');
  browser('find', 'label', 'Optional report scope / notes', 'fill', 'Bounded review of the loaded network evidence.');
  browser('find', 'role', 'button', 'click', '--name', 'Save report details');

  if (includedAssessment) {
    browser('find', 'role', 'button', 'click', '--name', 'Signals & observations', '--exact');
    browser('find', 'role', 'button', 'click', '--name', 'Review signal Repeated outbound connections');
    browser('find', 'role', 'button', 'click', '--name', 'Investigate with AI');
    waitForText('Open full assessment');
    browser('find', 'role', 'button', 'click', '--name', 'Open full assessment', '--exact');
    browser('wait', '[data-testid="assessment-report-inclusion"]');
    browser('eval', 'document.querySelector("[data-testid=assessment-report-inclusion]")?.click(); "clicked"');
    waitForText('Remove AI-assisted assessment from report', 10_000);
    browser('find', 'role', 'button', 'click', '--name', 'Report builder', '--exact');
    waitForText('NETWORK EVIDENCE REPORT', 10_000);
  }

  browser('pdf', pdfPath);

  const pdf = readFileSync(pdfPath);
  assert(pdf.subarray(0, 4).toString() === '%PDF', 'Generated file is not a valid PDF.');
  const text = execFileSync('pdftotext', [pdfPath, '-'], { encoding: 'utf8' });
  const compactText = text.replace(/\s/g, '');
  assert(compactText.includes('NETWORKEVIDENCEREPORT'), 'Early report marker is missing.');
  assert(text.includes('CASE-2026-071'), 'Saved case identity is missing.');
  assert(text.includes('Avery Mensah'), 'Saved investigator identity is missing.');
  assert(text.includes('Timezone:'), 'Explicit report timezone is missing.');
  assert(text.includes('PacketSage version:'), 'PacketSage version is missing.');
  assert(text.includes('Provenance and limitations'), 'Final report section is missing.');
  assert(text.includes('End of PacketSage evidence report draft.'), 'Late report marker is missing.');
  assert(!text.includes('Import evidence'), 'Application navigation leaked into print output.');
  assert(!text.includes('Packet Academy'), 'Application shell leaked into print output.');
  assert(!text.includes('stages complete'), 'Guided journey leaked into print output.');
  const pages = text.split('\f').map(page => page.trim());
  if (!pages.at(-1)) pages.pop();
  const blankPage = pages.findIndex(page => page.length === 0);
  assert(blankPage === -1, `Printed page ${blankPage + 1} is blank.`);
  const nearEmptyPage = pages.findIndex(page => page.replace(/\s/g, '').length < 140);
  assert(nearEmptyPage === -1, `Printed page ${nearEmptyPage + 1} contains only a heading or near-empty content.`);
  const timelinePage = pages.find(page => page.includes('Timeline'));
  assert(timelinePage && /evt-[a-z0-9-]+/.test(timelinePage), 'Timeline heading was orphaned from its first event row.');
  for (const heading of ['Executive summary', 'Findings', 'Contextual overview', 'AI-assisted investigation assessments', 'Case-specific recommendations', 'Provenance and limitations']) {
    const page = pages.find(candidate => candidate.includes(heading));
    const followingContent = page?.slice((page.indexOf(heading) || 0) + heading.length).replace(/\s/g, '').length || 0;
    assert(followingContent >= 30, `${heading} was orphaned from meaningful following content.`);
  }
  const eventIds = new Set(text.match(/evt-[a-z0-9-]+/g) || []);
  const repeatedTimelineHeaders = (text.match(/Recorded time \/ Evidence ID/g) || []).length;
  if (unknownSourcePort) {
    assert(eventIds.size === 1, `Expected the one strict-text timeline event, found ${eventIds.size}.`);
    assert(!text.includes('10.0.0.15:0'), 'Unknown source-port sentinel leaked into PDF output.');
    assert(compactText.includes('10.0.0.15:unknown'), 'Unknown source port is not labelled honestly in PDF output.');
  } else {
    assert(eventIds.size > 8, `Expected more than 8 printed timeline events, found ${eventIds.size}.`);
    assert(eventIds.size === 40, `Expected all 40 bounded timeline events, found ${eventIds.size}.`);
    assert(repeatedTimelineHeaders >= 2, `Expected repeated Timeline headers, found ${repeatedTimelineHeaders}.`);
    assert(compactText.includes('10.0.0.15:51234'), 'Known source port changed in PDF output.');
  }
  assert(!text.includes('Replay guided tour'), 'Guided-tour content leaked into print output.');
  assert(!/Step [1-4] of 4/.test(text), 'Contextual-tour content leaked into print output.');
  if (includedAssessment) {
    assert(text.includes('Assessment summary'), 'Included assessment summary is missing.');
    assert(text.includes('Observed evidence'), 'Included assessment observed evidence is missing.');
    assert(text.includes('Analyst inference'), 'Included assessment inference is missing.');
    assert(text.includes('Uncertainty / missing evidence'), 'Included assessment uncertainty is missing.');
    assert(text.includes('Recommended next investigative steps'), 'Included assessment next steps are missing.');
    assert(text.includes('Provider:'), 'Included assessment provider provenance is missing.');
    assert(text.includes('Model:'), 'Included assessment model provenance is missing.');
    assert(/(?:flow|evt|dns|http|tls)-[a-z0-9-]+/.test(text), 'Included assessment evidence citations are missing.');
  }
  process.stdout.write(`Verified report-only PDF: ${pdfPath} (${pages.length} pages, ${eventIds.size} timeline events, ${repeatedTimelineHeaders} repeated Timeline headers, assessment ${includedAssessment ? 'included' : 'excluded'}, unknown source port ${unknownSourcePort ? 'included' : 'excluded'})\n`);
} finally {
  try { browser('close'); } catch { /* best-effort browser cleanup */ }
  if (process.env.KEEP_VERIFICATION_PDF !== '1') rmSync(pdfPath, { force: true });
}
