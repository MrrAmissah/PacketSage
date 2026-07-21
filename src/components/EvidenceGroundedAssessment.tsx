import { useEffect, useMemo, useRef } from 'react';
import { ArrowLeft, ArrowRight, Check, Clipboard, FileSearch, FileText, RotateCcw } from 'lucide-react';
import { assessmentCitationIds } from '../lib/assessmentWorkspace';
import { resolveCitedEvent, resolveCitedFlow } from '../lib/investigation';
import type { FlowSummary, InvestigationRecord, PacketEvent } from '../types';
import InvestigationAssessmentPanel from './InvestigationAssessment';

interface EvidenceGroundedAssessmentProps {
  record: InvestigationRecord;
  flows: FlowSummary[];
  events: PacketEvent[];
  onBack(): void;
  onInclusionChange(included: boolean): void;
  onInspectFlow(flows: FlowSummary[]): void;
  onInspectEvent(eventId: string): void;
  onOpenReport(): void;
  onRerun(): void;
}

export default function EvidenceGroundedAssessment({
  record,
  flows,
  events,
  onBack,
  onInclusionChange,
  onInspectFlow,
  onInspectEvent,
  onOpenReport,
  onRerun,
}: EvidenceGroundedAssessmentProps) {
  const workspaceRef = useRef<HTMLElement>(null);
  const evidenceRef = useRef<HTMLElement>(null);
  const citationIds = useMemo(() => assessmentCitationIds(record.assessment), [record.assessment]);
  const citedFlowIds = useMemo(() => citationIds.filter(id => record.packet.flows.some(flow => flow.id === id)), [citationIds, record.packet.flows]);
  const citedEventIds = useMemo(() => citationIds.filter(id => record.packet.events.some(event => event.id === id)), [citationIds, record.packet.events]);

  useEffect(() => {
    workspaceRef.current?.scrollIntoView({ behavior: 'auto', block: 'start' });
    workspaceRef.current?.focus({ preventScroll: true });
  }, []);

  const inspectCitations = () => {
    evidenceRef.current?.focus({ preventScroll: true });
    evidenceRef.current?.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  };

  return (
    <section ref={workspaceRef} tabIndex={-1} className="space-y-6 focus:outline-none" aria-labelledby="assessment-workspace-title" data-testid="evidence-grounded-assessment-workspace">
      <header className="space-y-5 border-b border-border-subtle pb-5">
        <button type="button" onClick={onBack} className="inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs font-semibold text-text-secondary hover:text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary">
          <ArrowLeft aria-hidden="true" size={13} /> Back to Signals &amp; observations
        </button>
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
          <div className="min-w-0">
            <p className="text-[10px] font-bold uppercase tracking-widest text-accent-primary">Retained signal assessment</p>
            <h1 id="assessment-workspace-title" className="mt-1 text-2xl font-bold text-text-primary">Evidence-grounded assessment</h1>
            <p className="mt-2 max-w-3xl text-lg font-semibold text-text-primary">{record.packet.signal.title}</p>
            <div className="mt-3 flex flex-wrap gap-2 text-xs">
              <span className="rounded-full border border-border-subtle bg-surface px-2.5 py-1 text-text-secondary">{record.packet.signal.category}</span>
              <span className="rounded-full border border-status-warning/30 bg-status-warning-bg/10 px-2.5 py-1 font-semibold uppercase text-status-warning">{record.packet.signal.severity} severity</span>
              <span className="rounded-full border border-border-subtle bg-surface px-2.5 py-1 text-text-secondary">Deterministic confidence: <strong>{record.packet.signal.confidence}</strong></span>
              <span className={`rounded-full border px-2.5 py-1 font-semibold ${record.includedInReport ? 'border-status-success/30 bg-status-success/10 text-status-success' : 'border-border-subtle bg-surface text-text-muted'}`}>{record.includedInReport ? 'Included in report' : 'Not included in report'}</span>
            </div>
          </div>
          <dl className="grid shrink-0 grid-cols-2 gap-3 rounded-xl border border-border-subtle bg-surface p-4 text-center shadow-sm">
            <div><dt className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Related flows</dt><dd className="mt-1 font-mono text-xl font-bold text-text-primary">{record.packet.flows.length}</dd></div>
            <div><dt className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Related events</dt><dd className="mt-1 font-mono text-xl font-bold text-text-primary">{record.packet.events.length}</dd></div>
          </dl>
        </div>
        <details className="max-w-3xl rounded-lg border border-border-subtle bg-surface px-3 py-2 text-[11px] text-text-muted">
          <summary className="cursor-pointer font-semibold text-text-secondary">Technical details and model provenance</summary>
          <dl className="mt-3 grid gap-2 sm:grid-cols-2">
            <div><dt className="font-semibold">Provider</dt><dd>{record.provider}</dd></div>
            <div><dt className="font-semibold">Model</dt><dd>{record.model}</dd></div>
            <div><dt className="font-semibold">Schema</dt><dd>{record.schemaVersion}</dd></div>
            <div><dt className="font-semibold">Generated</dt><dd>{record.createdAt}</dd></div>
            <div className="sm:col-span-2"><dt className="font-semibold">Evidence identity</dt><dd className="break-all font-mono">{record.selectedEvidenceId}</dd></div>
            <div className="sm:col-span-2"><dt className="font-semibold">Packet identity</dt><dd className="break-all font-mono">{record.packetIdentity}</dd></div>
          </dl>
        </details>
      </header>

      <div className="grid min-w-0 gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
        <article className="min-w-0 rounded-xl border border-border-subtle bg-surface p-5 shadow-sm sm:p-7">
          <InvestigationAssessmentPanel
            assessment={record.assessment}
            packet={record.packet}
            flows={flows}
            events={events}
            onNavigateToFlows={onInspectFlow}
            onNavigateToEvent={onInspectEvent}
            variant="full"
          />
        </article>

        <aside className="min-w-0 space-y-5 xl:sticky xl:top-4 xl:h-fit">
          <section ref={evidenceRef} tabIndex={-1} id="assessment-referenced-evidence" className="scroll-mt-4 space-y-4 rounded-xl border border-border-subtle bg-surface p-5 shadow-sm focus:outline-none focus:ring-2 focus:ring-accent-primary" aria-labelledby="referenced-evidence-title">
            <div>
              <p className="text-[9px] font-bold uppercase tracking-widest text-accent-primary">Validated packet references</p>
              <h2 id="referenced-evidence-title" className="mt-1 text-base font-bold text-text-primary">Referenced evidence</h2>
              <p className="mt-1 text-xs leading-relaxed text-text-muted">Only exact retained IDs are shown. Missing current records remain visibly unavailable.</p>
            </div>
            <dl className="grid grid-cols-2 gap-2 text-xs">
              <div className="rounded-lg bg-surface-muted p-3"><dt className="text-[9px] font-bold uppercase text-text-muted">Selected signal</dt><dd className="mt-1 break-all font-mono text-text-primary">{record.signalId}</dd></div>
              <div className="rounded-lg bg-surface-muted p-3"><dt className="text-[9px] font-bold uppercase text-text-muted">Exact citations</dt><dd className="mt-1 font-mono text-lg font-bold text-text-primary">{citationIds.length}</dd></div>
            </dl>

            <div>
              <h3 className="text-xs font-bold text-text-primary">Cited flow IDs</h3>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {citedFlowIds.length ? citedFlowIds.map(id => {
                  const flow = resolveCitedFlow(id, record.packet, flows);
                  return flow ? (
                    <button key={id} type="button" onClick={() => onInspectFlow([flow])} className="inline-flex max-w-full items-center gap-1 rounded border border-accent-primary/25 bg-accent-soft px-2 py-1 font-mono text-[11px] text-accent-primary focus:outline-none focus:ring-2 focus:ring-accent-primary" title={`Open exact flow ${id}`}><span className="truncate">{id}</span><ArrowRight aria-hidden="true" size={10} /></button>
                  ) : <span key={id} className="inline-flex max-w-full rounded border border-border-subtle bg-surface-muted px-2 py-1 font-mono text-[11px] text-text-muted" title="Referenced flow is unavailable in the current evidence"><span className="truncate">{id}</span> · unavailable</span>;
                }) : <p className="text-xs italic text-text-muted">No exact flow citations were retained.</p>}
              </div>
            </div>

            <div>
              <h3 className="text-xs font-bold text-text-primary">Cited event IDs</h3>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {citedEventIds.length ? citedEventIds.map(id => {
                  const event = resolveCitedEvent(id, record.packet, events);
                  return event ? (
                    <button key={id} type="button" onClick={() => onInspectEvent(event.id)} className="inline-flex max-w-full items-center gap-1 rounded border border-accent-primary/25 bg-accent-soft px-2 py-1 font-mono text-[11px] text-accent-primary focus:outline-none focus:ring-2 focus:ring-accent-primary" title={`Open exact event ${id}`}><span className="truncate">{id}</span><ArrowRight aria-hidden="true" size={10} /></button>
                  ) : <span key={id} className="inline-flex max-w-full rounded border border-border-subtle bg-surface-muted px-2 py-1 font-mono text-[11px] text-text-muted" title="Referenced event is unavailable in the current evidence"><span className="truncate">{id}</span> · unavailable</span>;
                }) : <p className="text-xs italic text-text-muted">No exact event citations were retained.</p>}
              </div>
            </div>
          </section>

          <section className="space-y-2 rounded-xl border border-border-subtle bg-surface p-5 shadow-sm" aria-labelledby="assessment-actions-title">
            <h2 id="assessment-actions-title" className="text-sm font-bold text-text-primary">Assessment actions</h2>
            <button type="button" data-testid="assessment-report-inclusion" data-tour-target="assessment-report-inclusion" aria-pressed={record.includedInReport} onClick={() => onInclusionChange(!record.includedInReport)} className={`inline-flex w-full items-center justify-center gap-1.5 rounded-lg border px-3 py-2.5 text-xs font-bold focus:outline-none focus:ring-2 focus:ring-accent-primary ${record.includedInReport ? 'border-status-success/30 bg-status-success/10 text-status-success' : 'border-accent-primary bg-accent-primary text-white hover:bg-accent-primary-hover'}`}>
              {record.includedInReport ? <><Check aria-hidden="true" size={13} /> Remove AI-assisted assessment from report</> : <><Clipboard aria-hidden="true" size={13} /> Include AI-assisted assessment in report</>}
            </button>
            <button type="button" onClick={inspectCitations} className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2.5 text-xs font-semibold text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary"><FileSearch aria-hidden="true" size={13} /> Inspect cited evidence</button>
            <button type="button" onClick={onOpenReport} className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2.5 text-xs font-semibold text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary"><FileText aria-hidden="true" size={13} /> Open Report Builder</button>
            <button type="button" onClick={onRerun} className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2.5 text-xs font-semibold text-accent-primary focus:outline-none focus:ring-2 focus:ring-accent-primary"><RotateCcw aria-hidden="true" size={13} /> Run again with current referenced evidence</button>
            <button type="button" onClick={onBack} className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-xs font-semibold text-text-muted hover:text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary"><ArrowLeft aria-hidden="true" size={13} /> Back to selected signal</button>
          </section>
        </aside>
      </div>
    </section>
  );
}
