import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, Check, Clipboard, Eye, FileText, Pencil, Printer, X } from 'lucide-react';
import type { ParsedResult } from '../lib/parser';
import type { CaptureOverviewRecord, InvestigationRecord, SignalReviewStatus } from '../types';
import { buildReportModel, reportToMarkdown, type ReportModel } from '../lib/report';
import {
  createReportDetailsSession,
  reportDetailsForEvidence,
  reportIdentityIncomplete,
  type ReportDetails,
  type ReportDetailsRecord,
} from '../lib/reportDetails';
import { PacketSageIcon } from './Logo';

interface ReportBuilderProps {
  data: ParsedResult | null;
  investigations: InvestigationRecord[];
  captureOverview: CaptureOverviewRecord | null;
  reportDetails?: ReportDetailsRecord | null;
  onReportDetailsChange?: (record: ReportDetailsRecord) => void;
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

function DetailValue({ value }: { value: string }) {
  return <span className={value ? 'text-text-primary' : 'italic text-text-muted'}>{value || 'Not provided'}</span>;
}

function useModalFocus(
  open: boolean,
  dialogRef: React.RefObject<HTMLDivElement | null>,
  triggerRef: React.RefObject<HTMLButtonElement | null>,
  onClose: () => void,
  initialFocusSelector?: string,
) {
  useEffect(() => {
    if (!open) return;
    const dialog = dialogRef.current;
    const focusableSelector = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
    const focusable = (): HTMLElement[] => dialog
      ? Array.from(dialog.querySelectorAll<HTMLElement>(focusableSelector))
      : [];
    const initialFocus = initialFocusSelector
      ? dialog?.querySelector<HTMLElement>(initialFocusSelector)
      : null;
    (initialFocus || focusable()[0])?.focus();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== 'Tab') return;
      const elements = focusable();
      if (!elements.length) return;
      const first = elements[0];
      const last = elements[elements.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      triggerRef.current?.focus();
    };
  }, [dialogRef, initialFocusSelector, onClose, open, triggerRef]);
}

export function ReportDocument({ report }: ReportDocumentProps) {
  return (
    <article data-testid="report-document" className="report-document space-y-7 rounded-xl border border-border-subtle bg-surface p-5 text-xs text-text-secondary shadow-sm print:border-0 print:shadow-none">
      <header className="report-document-header space-y-5 border-b-2 border-slate-300 pb-6">
        <div className="flex items-start justify-between gap-4 border-t-4 border-[#0062f1] pt-4">
          <div data-report-marker="early" className="flex items-center gap-3">
            <PacketSageIcon className="h-9 w-9 shrink-0" />
            <div>
              <div className="text-lg font-bold tracking-tight text-text-primary">Packet<span className="font-normal text-[#0062f1]">Sage</span></div>
              <h2 className="text-[10px] font-bold uppercase tracking-[0.2em] text-text-secondary">Network Evidence Report</h2>
            </div>
          </div>
          <span className="border border-slate-400 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.18em] text-slate-700">Draft</span>
        </div>

        <div className="grid gap-5 sm:grid-cols-2">
          <section aria-labelledby="report-identity-heading" className="border-l-2 border-[#0062f1] pl-3">
            <h3 id="report-identity-heading" className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Report identity</h3>
            <dl className="mt-2 grid gap-1.5">
              <div><dt className="inline font-semibold">Case / reference ID: </dt><dd className="inline"><DetailValue value={report.details.caseReferenceId} /></dd></div>
              <div><dt className="inline font-semibold">Investigator / Prepared by: </dt><dd className="inline"><DetailValue value={report.details.investigator} /></dd></div>
              <div><dt className="inline font-semibold">Role or unit: </dt><dd className="inline"><DetailValue value={report.details.roleOrUnit} /></dd></div>
              <div><dt className="inline font-semibold">Organization: </dt><dd className="inline"><DetailValue value={report.details.organization} /></dd></div>
              <div><dt className="inline font-semibold">Report scope / notes: </dt><dd className="inline"><DetailValue value={report.details.scopeNotes} /></dd></div>
            </dl>
          </section>

          <section aria-labelledby="report-generation-heading">
            <h3 id="report-generation-heading" className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Report generation</h3>
            <dl className="mt-2 grid gap-1.5">
              <div><dt className="inline font-semibold">Generated: </dt><dd className="inline font-mono text-[10px] text-text-primary">{report.generation.generatedAt}</dd></div>
              <div><dt className="inline font-semibold">Timezone: </dt><dd className="inline text-text-primary">{report.generation.timeZone}</dd></div>
              <div><dt className="inline font-semibold">Report status: </dt><dd className="inline text-text-primary">{report.generation.status}</dd></div>
              <div><dt className="inline font-semibold">PacketSage version: </dt><dd className="inline text-text-primary">{report.generation.packetSageVersion}</dd></div>
            </dl>
          </section>
        </div>

        <section aria-labelledby="report-evidence-identity-heading" className="border-t border-slate-200 pt-4">
          <h3 id="report-evidence-identity-heading" className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Evidence identity</h3>
          <dl className="mt-2 grid gap-x-5 gap-y-2 sm:grid-cols-2 lg:grid-cols-4">
            <div><dt className="text-text-muted">Evidence filename</dt><dd className="font-semibold text-text-primary">{report.evidence.name}</dd></div>
            <div><dt className="text-text-muted">Evidence identity</dt><dd className="break-all font-mono text-[10px] text-text-primary">{report.evidence.identity}</dd></div>
            <div><dt className="text-text-muted">Evidence type</dt><dd className="font-semibold text-text-primary">{report.evidence.type}</dd></div>
            <div><dt className="text-text-muted">Parse mode</dt><dd className="font-semibold text-text-primary">{report.evidence.parseMode}</dd></div>
            <div className="sm:col-span-2 lg:col-span-4"><dt className="text-text-muted">SHA-256</dt><dd className="break-all font-mono text-[10px] text-text-primary" data-testid="report-checksum">{report.evidence.checksum}</dd></div>
            <div><dt className="text-text-muted">Earliest recorded event</dt><dd className="font-mono text-[10px] text-text-primary">{report.evidence.earliestRecordedEvent || 'No recorded events'}</dd></div>
            <div><dt className="text-text-muted">Latest recorded event</dt><dd className="font-mono text-[10px] text-text-primary">{report.evidence.latestRecordedEvent || 'No recorded events'}</dd></div>
            <div><dt className="text-text-muted">Evidence counts</dt><dd className="text-text-primary">{report.counts.events} events · {report.counts.flows} flows · {report.counts.signals} signals</dd></div>
            <div><dt className="text-text-muted">Report inclusions</dt><dd className="text-text-primary">{report.counts.reviewedFindings} reviewed · {report.counts.includedAssessments} assessments · Overview {report.contextualOverview ? 'included' : 'not included'}</dd></div>
          </dl>
        </section>
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

      <section aria-labelledby="report-timeline" className="report-timeline-section space-y-3">
        <h3 id="report-timeline" className="text-sm font-bold text-text-primary">Timeline</h3>
        {!report.timeline.length ? (
          <p className="rounded-lg bg-surface-muted p-3 text-text-muted">No timeline events were available in the selected evidence.</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border-subtle">
            <table data-testid="report-timeline-table" className="report-timeline-table w-full min-w-[680px] table-fixed text-left text-[10px]">
              <colgroup><col className="w-[26%]" /><col className="w-[35%]" /><col className="w-[16%]" /><col className="w-[23%]" /></colgroup>
              <thead className="bg-surface-muted text-text-muted"><tr><th className="p-2">Recorded time / Evidence ID</th><th className="p-2">Source → Destination</th><th className="p-2">Protocol / Size</th><th className="p-2">Linked observations</th></tr></thead>
              <tbody className="divide-y divide-border-subtle">
                {report.timeline.map(event => (
                  <tr key={event.id}>
                    <td className="p-2 align-top"><time className="block text-text-primary" dateTime={event.timestamp}>{event.timestamp}</time><code className="mt-1 block text-[9px] text-text-muted">{event.id}</code></td>
                    <td className="break-words p-2 align-top font-mono">{event.source} → {event.destination}</td>
                    <td className="p-2 align-top"><span className="block font-semibold text-text-primary">{event.protocol}</span><span className="block text-text-muted">{event.length} bytes</span></td>
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
              <h5 className="mt-3 font-bold text-text-primary">Assessment summary</h5>
              <p className="mt-1 leading-relaxed">{record.assessment.summary}</p>
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

      <section aria-labelledby="report-provenance-limitations" className="space-y-3" data-report-marker="late">
        <h3 id="report-provenance-limitations" className="text-sm font-bold text-text-primary">Provenance and limitations</h3>
        <dl className="grid gap-2 sm:grid-cols-2">
          <div><dt className="font-semibold text-text-primary">Evidence identity</dt><dd className="font-mono text-[10px]">{report.evidence.checksum}</dd></div>
          <div><dt className="font-semibold text-text-primary">Parser mode</dt><dd>{report.evidence.parseMode}</dd></div>
          <div className="sm:col-span-2"><dt className="font-semibold text-text-primary">Relationship boundary</dt><dd>Findings, events, flows, and citations are connected only through retained deterministic identifiers. AI inferences remain separately labelled and require independent validation.</dd></div>
          <div className="sm:col-span-2"><dt className="font-semibold text-text-primary">Timeline boundary</dt><dd>{report.timelineTruncated ? `The bounded report contains ${report.timeline.length} of ${report.counts.events} events.` : `The bounded report contains all ${report.timeline.length} available events.`}</dd></div>
        </dl>
        <p className="border-t border-border-subtle pt-3 text-[10px] text-text-muted">End of PacketSage evidence report draft.</p>
      </section>
    </article>
  );
}

export default function ReportBuilder({
  data,
  investigations,
  captureOverview,
  reportDetails = null,
  onReportDetailsChange,
  signalStatusOverrides = {},
}: ReportBuilderProps) {
  const [previewOpen, setPreviewOpen] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [detailsDraft, setDetailsDraft] = useState<ReportDetails>({
    investigator: '', roleOrUnit: '', organization: '', caseReferenceId: '', scopeNotes: '',
  });
  const [copied, setCopied] = useState(false);
  const [generatedAt] = useState(() => new Date().toISOString());
  const [timeZone] = useState(() => Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC');
  const previewTriggerRef = useRef<HTMLButtonElement>(null);
  const previewDialogRef = useRef<HTMLDivElement>(null);
  const detailsTriggerRef = useRef<HTMLButtonElement>(null);
  const detailsDialogRef = useRef<HTMLDivElement>(null);
  const currentDetailsRecord = useMemo(
    () => data ? reportDetailsForEvidence(reportDetails, data.evidence.id) : null,
    [data, reportDetails],
  );
  const report = useMemo(
    () => data ? buildReportModel(data, investigations, signalStatusOverrides, captureOverview, {
      reportDetails: currentDetailsRecord,
      generatedAt,
      timeZone,
    }) : null,
    [captureOverview, currentDetailsRecord, data, generatedAt, investigations, signalStatusOverrides, timeZone],
  );

  const closePreview = useCallback(() => {
    setPreviewOpen(false);
    window.requestAnimationFrame(() => previewTriggerRef.current?.focus());
  }, []);
  const closeDetails = useCallback(() => setDetailsOpen(false), []);
  useModalFocus(previewOpen, previewDialogRef, previewTriggerRef, closePreview);
  useModalFocus(detailsOpen, detailsDialogRef, detailsTriggerRef, closeDetails, '[data-report-details-initial-focus]');

  if (!report) return <div className="rounded-xl border border-border-subtle bg-surface p-6 text-sm text-text-muted">Import evidence before building a report.</div>;

  const copyMarkdown = async () => {
    await navigator.clipboard.writeText(reportToMarkdown(report));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };
  const reportReady = report.counts.reviewedFindings > 0 || report.counts.includedAssessments > 0;
  const identityIncomplete = reportIdentityIncomplete(report.details);
  const openDetails = () => {
    setDetailsDraft({ ...report.details });
    setDetailsOpen(true);
  };
  const saveDetails = () => {
    if (!data) return;
    onReportDetailsChange?.(createReportDetailsSession(data.evidence.id, detailsDraft));
    setDetailsOpen(false);
  };
  const updateDraft = (field: keyof ReportDetails, value: string) => {
    setDetailsDraft(previous => ({ ...previous, [field]: value }));
  };

  return (
    <div id="report-builder-workspace" className="space-y-5">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end print:hidden">
        <div><p className="text-[10px] font-bold uppercase tracking-widest text-accent-primary">Evidence-grounded export</p><h1 className="text-xl font-bold text-text-primary">Report builder</h1><p className="mt-1 text-xs text-text-muted">Preview and export only reviewed findings and explicitly included assessments.</p></div>
        <div className="flex flex-wrap gap-2">
          <button ref={detailsTriggerRef} type="button" onClick={openDetails} className="inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs font-semibold text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary"><Pencil aria-hidden="true" size={13} /> Edit report details</button>
          <button ref={previewTriggerRef} type="button" onClick={() => setPreviewOpen(true)} className="inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs font-semibold text-text-primary"><Eye size={13} /> Preview</button>
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
        {identityIncomplete && <p className="mt-2 flex items-start gap-1.5 text-[10px] text-status-warning" data-testid="report-identity-warning"><AlertTriangle aria-hidden="true" className="mt-0.5 shrink-0" size={11} /><span>Report identity is incomplete. Add an investigator and case/reference ID when available. Preview, Markdown and Print/PDF remain available.</span></p>}
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6 print:hidden">
        {[
          ['Events', report.counts.events], ['Flows', report.counts.flows], ['Signals', report.counts.signals],
          ['Reviewed findings', report.counts.reviewedFindings], ['Included assessments', report.counts.includedAssessments],
          ['Contextual overview', report.contextualOverview ? 'Included' : 'Not included'],
        ].map(([label, value]) => <div key={label} className="rounded-lg border border-border-subtle bg-surface p-3"><div className="text-[9px] uppercase text-text-muted">{label}</div><div className="mt-1 font-mono text-lg font-bold text-text-primary">{value}</div></div>)}
      </div>

      <ReportDocument report={report} />

      {detailsOpen && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-950/70 p-3 print:hidden sm:p-6" role="presentation">
          <div ref={detailsDialogRef} className="mx-auto w-full max-w-2xl rounded-xl bg-surface p-4 shadow-2xl sm:p-6" role="dialog" aria-modal="true" aria-labelledby="report-details-title" aria-describedby="report-details-description">
            <div className="flex items-start justify-between gap-3">
              <div><h2 id="report-details-title" className="text-lg font-bold text-text-primary">Edit report details</h2><p id="report-details-description" className="mt-1 text-xs text-text-muted">These user-entered values remain in volatile session state for the current evidence.</p></div>
              <button type="button" onClick={closeDetails} aria-label="Cancel editing report details" className="rounded-lg border border-border-subtle p-2 text-text-muted focus:outline-none focus:ring-2 focus:ring-accent-primary"><X aria-hidden="true" size={15} /></button>
            </div>
            <div className="mt-5 grid gap-4 sm:grid-cols-2">
              <label className="grid gap-1.5 text-xs font-semibold text-text-primary">Investigator / Prepared by<input data-report-details-initial-focus autoComplete="off" value={detailsDraft.investigator} maxLength={160} onChange={event => updateDraft('investigator', event.target.value)} className="rounded-lg border border-border-subtle bg-canvas px-3 py-2.5 font-normal focus:outline-none focus:ring-2 focus:ring-accent-primary" /></label>
              <label className="grid gap-1.5 text-xs font-semibold text-text-primary">Role or unit<input autoComplete="off" value={detailsDraft.roleOrUnit} maxLength={160} onChange={event => updateDraft('roleOrUnit', event.target.value)} className="rounded-lg border border-border-subtle bg-canvas px-3 py-2.5 font-normal focus:outline-none focus:ring-2 focus:ring-accent-primary" /></label>
              <label className="grid gap-1.5 text-xs font-semibold text-text-primary">Organization<input autoComplete="off" value={detailsDraft.organization} maxLength={160} onChange={event => updateDraft('organization', event.target.value)} className="rounded-lg border border-border-subtle bg-canvas px-3 py-2.5 font-normal focus:outline-none focus:ring-2 focus:ring-accent-primary" /></label>
              <label className="grid gap-1.5 text-xs font-semibold text-text-primary">Case or reference ID<input autoComplete="off" value={detailsDraft.caseReferenceId} maxLength={160} onChange={event => updateDraft('caseReferenceId', event.target.value)} className="rounded-lg border border-border-subtle bg-canvas px-3 py-2.5 font-normal focus:outline-none focus:ring-2 focus:ring-accent-primary" /></label>
              <label className="grid gap-1.5 text-xs font-semibold text-text-primary sm:col-span-2">Optional report scope / notes<textarea value={detailsDraft.scopeNotes} maxLength={2000} rows={4} onChange={event => updateDraft('scopeNotes', event.target.value)} className="resize-y rounded-lg border border-border-subtle bg-canvas px-3 py-2.5 font-normal focus:outline-none focus:ring-2 focus:ring-accent-primary" /></label>
            </div>
            <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <button type="button" onClick={closeDetails} className="rounded-lg border border-border-subtle px-4 py-2.5 text-xs font-semibold text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary">Cancel</button>
              <button type="button" onClick={saveDetails} className="rounded-lg bg-accent-primary px-4 py-2.5 text-xs font-bold text-white focus:outline-none focus:ring-2 focus:ring-accent-primary focus:ring-offset-2">Save report details</button>
            </div>
          </div>
        </div>
      )}

      {previewOpen && (
        <div ref={previewDialogRef} className="report-preview-dialog fixed inset-0 z-50 overflow-y-auto bg-slate-950/70 p-4 print:hidden" role="dialog" aria-modal="true" aria-labelledby="report-preview-title">
          <div className="mx-auto max-w-5xl space-y-3">
            <div className="flex items-center justify-between"><h2 id="report-preview-title" className="text-sm font-bold text-white">Report preview</h2><button type="button" onClick={closePreview} className="inline-flex items-center gap-1 rounded-lg bg-white px-3 py-2 text-xs font-bold text-slate-900"><X size={13} /> Close preview</button></div>
            <ReportDocument report={report} />
          </div>
        </div>
      )}
    </div>
  );
}
