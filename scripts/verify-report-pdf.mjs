import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const baseUrl = process.argv[2] || 'http://127.0.0.1:3000';
const pdfPath = resolve(process.argv[3] || 'artifacts/packetsage-report-verification.pdf');
const session = `packetsage-print-${process.pid}`;
mkdirSync(dirname(pdfPath), { recursive: true });

function browser(...args) {
  return execFileSync('agent-browser', ['--session', session, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

try {
  browser('open', baseUrl);
  browser('wait', '--load', 'networkidle');
  browser('find', 'role', 'button', 'click', '--name', 'Load guided investigation sample');
  browser('wait', '--text', 'Command center');
  browser('find', 'role', 'button', 'click', '--name', 'Report builder');
  browser('wait', '--text', 'PacketSage evidence report draft');
  browser('pdf', pdfPath);

  const pdf = readFileSync(pdfPath);
  assert(pdf.subarray(0, 4).toString() === '%PDF', 'Generated file is not a valid PDF.');
  const text = execFileSync('pdftotext', [pdfPath, '-'], { encoding: 'utf8' });
  assert(text.includes('PacketSage evidence report draft'), 'Early report marker is missing.');
  assert(text.includes('Provenance and limitations'), 'Final report section is missing.');
  assert(text.includes('End of PacketSage evidence report draft.'), 'Late report marker is missing.');
  assert(!text.includes('Import evidence'), 'Application navigation leaked into print output.');
  assert(!text.includes('Packet Academy'), 'Application shell leaked into print output.');
  assert(!text.includes('stages complete'), 'Guided journey leaked into print output.');
  const eventIds = new Set(text.match(/evt-[a-z0-9-]+/g) || []);
  assert(eventIds.size > 8, `Expected more than 8 printed timeline events, found ${eventIds.size}.`);
  process.stdout.write(`Verified report-only PDF: ${pdfPath} (${eventIds.size} timeline events)\n`);
} finally {
  try { browser('close'); } catch { /* best-effort browser cleanup */ }
  if (process.env.KEEP_VERIFICATION_PDF !== '1') rmSync(pdfPath, { force: true });
}
