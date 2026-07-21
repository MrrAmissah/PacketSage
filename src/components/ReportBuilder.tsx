import React, { useMemo, useState } from 'react';
import { Check, Clipboard, Eye, FileText, Printer, X } from 'lucide-react';
import type { ParsedResult } from '../lib/parser';
import type { CaptureOverviewRecord, InvestigationRecord, SignalReviewStatus } from '../types';
import { buildReportModel, reportToMarkdown, type ReportModel } from '../lib/report';

interface ReportBuilderProps {
  data: ParsedResult | null;
  investigations: InvestigationRecord[];
  captureOverview: CaptureOverviewRecord | null;
  signalStatusOverrides?: Record<string, SignalReviewStatus>;
}

interface ReportDocumentProps {
  report: ReportModel;
}

function IdList({ values }: { values: readonly string[] }) {
  if (!values.length) return <span className="text-text-muted">None referenced</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {values.map(value => <code key={value} className="rounded bg-surface-muted px-1 py-0.5 text-[10px]">{value}</code>)}
    </span>
  );
}

function ReportDocument({ report }: ReportDocumentProps) {
  return (
    <article data-testid="report-document" className="space-y-7 rounded-xl border border-border-subtle bg-surface p-5 text-xs text-text-secondary shadow-sm print:border-0 print:shadow-none">
      <header className="space-y-2 border-b border-border-subtle pb-5">
        <p className="text-[10px] font-bold uppercase tracking-widest text-accent-primary">PacketSage evidence report draft</p>
        <h2 className="text-xl font-bold text-text-primary">{report.evidence.name}</h2>
        <dl className="grid gap-2 sm:grid-cols-3">
          <div><dt className="text-text-muted">Evidence type</dt><dd className="font-semibold text-text-primary">{report.evidence.type}</dd></div>
          <div><dt className="text-text-muted">Parse mode</dt><dd className="font-semibold text-text-primary">{report.evidence.parseMode}</dd></div>
          <div className="sm:col-span-3"><dt className="text-text-muted">SHA-256</dt><dd className="break-all font-mono text-[10px] text-text-primary" data-testid="report-checksum">{report.evidence.checksum}</dd></div>
        </dl>
      </header>

      <section aria-labelledby="report-summary">
        <h3 id="report-summary" className="mb-2 text-sm font-bold text-text-primary">Executive summary</h3>
        <p className="leading-relaxed">{report.executiveSummary}</p>
      </section>

      <section aria-labelledby="report-findings" className="space-y-3">
        <h3 id="report-findings" className="text-sm font-bold text-text-primary">Findings</h3>
        {!report.findings.length ? (
          <p className="rounded-lg bg-surface-muted p-3 text-text-muted">No reviewed findings have been added to this report draft.</p>
        ) : report.findings.map(finding => (
          <div key={finding.signalId} className="rounded-lg border border-border-subtle p-3">
            <div className="mb-2 flex items-center justify-between gap-3">
              <h4 className="font-semibold text-text-primary">{finding.title}</h4>
              <span className="uppercase text-text-muted">{finding.severity}</span>
            </div>
            <dl className="grid gap-2">
              <div><dt className="font-semibold">Signal ID</dt><dd><IdList values={[finding.signalId]} /></dd></div>
              <div><dt className="font-semibold">Related flow IDs</dt><dd><IdList values={finding.relatedFlowIds} /></dd></div>
              <div><dt className="font-semibold">Related event IDs</dt><dd><IdList values={finding.relatedEventIds} /></dd></div>
            </dl>
          </div>
        ))}
      </section>

      <section aria-labelledby="report-timeline" className="space-y-3">
        <h3 id="report-timeline" className="text-sm font-bold text-text-primary">Timeline</h3>
        {!report.timeline.length ? (
          <p className="rounded-lg bg-surface-muted p-3 text-text-muted">No timeline events were available in the selected evidence.</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border-subtle">
            <table className="w-full min-w-[720px] text-left text-[10px]">
              <thead className="bg-surface-muted text-text-muted"><tr><th className="p-2">Timestamp / event ID</th><th className="p-2">Source → destination</th><th className="p-2">Protocol</th><th className="p-2">Signals</th></tr></thead>
              <tbody className="divide-y divide-border-subtle">
                {report.timeline.map(event => (
                  <tr key={event.id}>
                    <td className="p-2"><div>{event.timestamp}</div><code>{event.id}</code></td>
                    <td className="p-2 font-mono">{event.source} → {event.destination}</td>
                    <td className="p-2">{event.protocol} · {event.length} bytes</td>
                    <td className="p-2"><IdList values={event.signalIds} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {report.timelineTruncated && <p className="text-[10px] text-text-muted">Timeline truncated to {report.timeline.length} of {report.counts.events} events.</p>}
      </section>

      <section aria-labelledby="report-contextual-overview" className="space-y-4" data-testid="report-contextual-overview">
        <div>
          <h3 id="report-contextual-overview" className="text-sm font-bold text-text-primary">Contextual overview</h3>
          <p className="mt-1 text-[10px] text-text-muted">Optional orientation only. This content is not evidence-linked and contains no evidence citations.</p>
        </div>
        {!report.contextualOverview ? <p className="rounded-lg bg-surface-muted p-3 text-text-muted">No capture overview has been explicitly included.</p> : (
          <article className="space-y-3 rounded-xl border border-purple-500/20 bg-purple-500/5 p-4" data-testid="included-capture-overview">
            <h4 className="font-bold text-text-primary">Capture overview — contextual note</h4>
            <p className="font-semibold text-status-warning">Contextual orientation — not evidence-linked.</p>
            <p>{report.contextualOverview.result.executiveSummary}</p>
            <div><h5 className="font-bold text-text-primary">Traffic-pattern explanation</h5><p>{report.contextualOverview.result.whatHappened}</p></div>
            <div><h5 className="font-bold text-text-primary">Beginner perspective</h5><p>{report.contextualOverview.result.beginnerExplanation}</p></div>
            <div><h5 className="font-bold text-text-primary">Technical perspective</h5><p>{report.contextualOverview.result.technicalExplanation}</p></div>
            <div><h5 className="font-bold text-text-primary">Analyst triage questions</h5><p>{report.contextualOverview.result.analystQuestions}</p></div>
            <details className="text-[10px] text-text-muted"><summary className="cursor-pointer font-semibold">AI provenance</summary><p className="mt-1">Provider: {report.contextualOverview.provider} · Model: {report.contextualOverview.model} · Schema: {report.contextualOverview.schemaVersion} · Generated: {report.contextualOverview.createdAt} · Capture: {report.contextualOverview.captureIdentity}</p></details>
          </article>
        )}
      </section>

      <section aria-labelledby="report-assessments" className="space-y-4" data-testid="report-assessments">
        <div>
          <h3 id="report-assessments" className="text-sm font-bold text-text-primary">AI-assisted investigation assessments</h3>
          <p className="mt-1 text-[10px] text-text-muted">Only explicitly included, validated assessments appear here. Inclusion does not confirm an inference.</p>
        </div>
        {!report.assessments.length ? (
          <p className="rounded-lg bg-surface-muted p-3 text-text-muted">No AI-assisted assessments have been explicitly included in this report draft.</p>
        ) : report.assessments.map(record => (
          <article key={`${record.signalId}:${record.packetIdentity}`} className="space-y-4 rounded-xl border border-accent-primary/20 bg-accent-soft/10 p-4" data-testid="included-investigation">
            <header>
              <h4 className="font-bold text-text-primary">{record.packet.signal.title}</h4>
              <div className="mt-1 flex flex-wrap gap-3 font-mono text-[9px] text-text-muted">
                <span>Signal: {record.signalId}</span><span>Packet: {record.packetIdentity}</span>
              </div>
              <details className="mt-2 text-[9px] text-text-muted"><summary className="cursor-pointer font-semibold">AI provenance</summary><p>Provider: {record.provider} · Model: {record.model} · Schema: {record.schemaVersion} · Generated: {record.createdAt} · Evidence: {record.selectedEvidenceId}</p></details>
              <p className="mt-2 leading-relaxed">{record.assessment.summary}</p>
            </header>
            <section><h5 className="mb-2 font-bold text-text-primary">Observed evidence</h5>{record.assessment.observedEvidence.map((item, index) => <div key={`${item.statement}-${index}`} className="mb-2"><p>{item.statement}</p><IdList values={item.evidenceIds} /></div>)}</section>
            <section className="rounded-lg border border-status-warning/20 bg-status-warning-bg/5 p-3"><h5 className="mb-1 font-bold text-status-warning">Analyst inference — Not confirmed</h5>{record.assessment.inferences.map((item, index) => <div key={`${item.statement}-${index}`} className="mb-2"><p><span className="font-semibold uppercase">{item.confidence} confidence:</span> {item.statement}</p><IdList values={item.evidenceIds} /></div>)}</section>
            <section><h5 className="mb-1 font-bold text-text-primary">Uncertainty / missing evidence — Not confirmed</h5><ul className="list-disc space-y-1 pl-5">{record.assessment.uncertainties.map(item => <li key={item}>{item}</li>)}</ul></section>
            <section><h5 className="mb-1 font-bold text-text-primary">Recommended next investigative steps</h5><ul className="list-disc space-y-1 pl-5">{record.assessment.nextSteps.map(item => <li key={`${item.action}:${item.reason}`}><span className="font-semibold">{item.action}</span> — {item.reason}</li>)}</ul></section>
          </article>
        ))}
      </section>

      <section aria-labelledby="report-recommendations" className="space-y-3">
        <h3 id="report-recommendations" className="text-sm font-bold text-text-primary">Case-specific recommendations</h3>
        {!report.recommendations.length ? (
          <p className="rounded-lg bg-surface-muted p-3 text-text-muted">No case-specific recommendations have been added to this report draft.</p>
        ) : (
          <ul className="space-y-2">
            {report.recommendations.map((recommendation, index) => (
              <li key={`${recommendation.source}:${index}`} className="rounded-lg border border-border-subtle p-3">
                <p>{recommendation.action}{recommendation.reason ? ` — ${recommendation.reason}` : ''}</p>
                <p className="mt-1 text-[9px] text-text-muted">Source: {recommendation.source}</p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </article>
  );
}

export default function ReportBuilder({ data, investigations, captureOverview, signalStatusOverrides = {} }: ReportBuilderProps) {
  const [previewOpen, setPreviewOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const report = useMemo(
    () => data ? buildReportModel(data, investigations, signalStatusOverrides, captureOverview) : null,
    [data, investigations, signalStatusOverrides, captureOverview],
  );

  if (!report) return <div className="rounded-xl border border-border-subtle bg-surface p-6 text-sm text-text-muted">Import evidence before building a report.</div>;

  const copyMarkdown = async () => {
    await navigator.clipboard.writeText(reportToMarkdown(report));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };
  const reportReady = report.counts.reviewedFindings > 0 || report.counts.includedAssessments > 0;

  return (
    <div id="report-builder-workspace" className="space-y-5">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end print:hidden">
        <div><p className="text-[10px] font-bold uppercase tracking-widest text-accent-primary">Evidence-grounded export</p><h1 className="text-xl font-bold text-text-primary">Report builder</h1><p className="mt-1 text-xs text-text-muted">Preview and export only reviewed findings and explicitly included assessments.</p></div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => setPreviewOpen(true)} className="inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs font-semibold text-text-primary"><Eye size={13} /> Preview</button>
          <button type="button" onClick={copyMarkdown} className="inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs font-semibold text-text-primary">{copied ? <Check size={13} /> : <Clipboard size={13} />} {copied ? 'Copied' : 'Copy Markdown'}</button>
          <button type="button" onClick={() => window.print()} className="inline-flex items-center gap-1.5 rounded-lg bg-accent-primary px-3 py-2 text-xs font-bold text-white"><Printer size={13} /> Print / PDF</button>
        </div>
      </div>

      <div className="rounded-lg border border-border-subtle bg-surface p-3 text-xs print:hidden" role="status">
        <span className="font-semibold text-text-primary">Report readiness: </span>
        <span className={reportReady ? 'text-status-success' : 'text-status-warning'}>
          {reportReady ? 'Ready to preview or export with explicitly included content.' : 'Review a deterministic finding or explicitly include an assessment before export.'}
        </span>
        <p className="mt-1 text-[10px] text-text-muted">Capture Overview is optional context and never makes a report evidence-ready by itself.</p>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6 print:hidden">
        {[
          ['Events', report.counts.events], ['Flows', report.counts.flows], ['Signals', report.counts.signals],
          ['Reviewed findings', report.counts.reviewedFindings], ['Included assessments', report.counts.includedAssessments],
          ['Contextual overview', report.contextualOverview ? 'Included' : 'Not included'],
        ].map(([label, value]) => <div key={label} className="rounded-lg border border-border-subtle bg-surface p-3"><div className="text-[9px] uppercase text-text-muted">{label}</div><div className="mt-1 font-mono text-lg font-bold text-text-primary">{value}</div></div>)}
      </div>

      <ReportDocument report={report} />

      {previewOpen && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-950/70 p-4 print:hidden" role="dialog" aria-modal="true" aria-label="Report preview">
          <div className="mx-auto max-w-5xl space-y-3">
            <div className="flex justify-end"><button type="button" onClick={() => setPreviewOpen(false)} className="inline-flex items-center gap-1 rounded-lg bg-white px-3 py-2 text-xs font-bold text-slate-900"><X size={13} /> Close preview</button></div>
            <ReportDocument report={report} />
          </div>
        </div>
      )}
    </div>
  );
}
