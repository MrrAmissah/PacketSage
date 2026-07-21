import React from 'react';
import { AlertCircle, ArrowRight, Eye, Lightbulb, SearchCheck } from 'lucide-react';
import { resolveCitedFlow } from '../lib/investigation';
import type { FlowSummary, InvestigationAssessment, InvestigationEvidencePacket } from '../types';

interface InvestigationAssessmentProps {
  assessment: InvestigationAssessment;
  packet: InvestigationEvidencePacket;
  flows: FlowSummary[];
  onNavigateToFlows: (flows: FlowSummary[]) => void;
}

function confidenceStyle(confidence: 'low' | 'medium' | 'high'): string {
  if (confidence === 'high') return 'bg-status-danger/10 text-status-danger border-status-danger/25';
  if (confidence === 'medium') return 'bg-status-warning-bg/20 text-status-warning border-status-warning/25';
  return 'bg-surface-muted text-text-muted border-border-subtle';
}

export default function InvestigationAssessmentPanel({
  assessment,
  packet,
  flows,
  onNavigateToFlows,
}: InvestigationAssessmentProps) {
  const evidenceChip = (evidenceId: string) => {
    const citedFlow = resolveCitedFlow(evidenceId, packet, flows);
    if (citedFlow) {
      return (
        <button
          type="button"
          key={evidenceId}
          onClick={() => onNavigateToFlows([citedFlow])}
          className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-accent-primary/25 bg-accent-soft text-accent-primary hover:text-accent-primary-hover font-mono text-[9px] cursor-pointer"
          title={`Open exact flow ${evidenceId}`}
        >
          {evidenceId}
          <ArrowRight size={8} />
        </button>
      );
    }
    return (
      <span key={evidenceId} className="inline-flex px-1.5 py-0.5 rounded border border-border-subtle bg-surface-muted text-text-muted font-mono text-[9px]">
        {evidenceId}
      </span>
    );
  };

  return (
    <div data-testid="investigation-assessment" className="space-y-3 rounded-xl border border-accent-primary/20 bg-accent-soft/20 p-3">
      <div className="space-y-1">
        <div className="text-[9px] font-bold uppercase tracking-[0.16em] text-accent-primary">AI-assisted assessment</div>
        <p className="text-[11px] leading-relaxed text-text-primary">{assessment.summary}</p>
      </div>

      <section className="space-y-1.5" aria-labelledby="investigation-observed-heading">
        <h4 id="investigation-observed-heading" className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-text-muted">
          <Eye size={11} /> Observed evidence
        </h4>
        {assessment.observedEvidence.length > 0 ? (
          <ul className="space-y-2">
            {assessment.observedEvidence.map((item, index) => (
              <li key={`${item.statement}-${index}`} className="rounded-lg border border-border-subtle/50 bg-surface p-2 text-[10px] text-text-secondary">
                <p className="leading-relaxed">{item.statement}</p>
                <div className="mt-1.5 flex flex-wrap gap-1">{item.evidenceIds.map(evidenceChip)}</div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[10px] italic text-text-muted">No model statement retained a supported evidence citation.</p>
        )}
      </section>

      <section className="space-y-1.5" aria-labelledby="investigation-inference-heading">
        <h4 id="investigation-inference-heading" className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-text-muted">
          <Lightbulb size={11} /> Analyst inference
        </h4>
        {assessment.inferences.length > 0 ? (
          <ul className="space-y-2">
            {assessment.inferences.map((item, index) => (
              <li key={`${item.statement}-${index}`} className="rounded-lg border border-border-subtle/50 bg-surface p-2 text-[10px] text-text-secondary">
                <div className="flex items-start justify-between gap-2">
                  <p className="leading-relaxed">{item.statement}</p>
                  <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[8px] font-bold uppercase ${confidenceStyle(item.confidence)}`}>
                    {item.confidence}
                  </span>
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1">{item.evidenceIds.map(evidenceChip)}</div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[10px] italic text-text-muted">No supported inference was returned.</p>
        )}
      </section>

      <section className="space-y-1.5 rounded-lg border border-status-warning/20 bg-status-warning-bg/10 p-2" aria-labelledby="investigation-uncertainty-heading">
        <h4 id="investigation-uncertainty-heading" className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-status-warning">
          <AlertCircle size={11} /> Uncertainty / missing evidence
        </h4>
        <div className="text-[9px] font-bold uppercase tracking-wider text-status-warning">Not confirmed</div>
        {assessment.uncertainties.length > 0 ? (
          <ul className="list-disc space-y-1 pl-4 text-[10px] leading-relaxed text-text-secondary">
            {assessment.uncertainties.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
          </ul>
        ) : (
          <p className="text-[10px] italic text-text-muted">The model did not identify additional missing evidence.</p>
        )}
      </section>

      <section className="space-y-1.5" aria-labelledby="investigation-next-steps-heading">
        <h4 id="investigation-next-steps-heading" className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-text-muted">
          <SearchCheck size={11} /> Recommended next investigative steps
        </h4>
        {assessment.nextSteps.length > 0 ? (
          <ol className="space-y-1.5">
            {assessment.nextSteps.map((step, index) => (
              <li key={`${step.action}-${index}`} className="rounded-lg border border-border-subtle/50 bg-surface p-2 text-[10px] text-text-secondary">
                <div className="font-semibold text-text-primary">{index + 1}. {step.action}</div>
                <p className="mt-0.5 leading-relaxed text-text-muted">{step.reason}</p>
              </li>
            ))}
          </ol>
        ) : (
          <p className="text-[10px] italic text-text-muted">No next investigative steps were returned.</p>
        )}
      </section>
    </div>
  );
}
