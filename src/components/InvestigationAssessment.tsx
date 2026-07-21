import React from 'react';
import { AlertCircle, ArrowRight, Eye, Lightbulb, SearchCheck } from 'lucide-react';
import { resolveCitedEvent, resolveCitedFlow } from '../lib/investigation';
import type { FlowSummary, InvestigationAssessment, InvestigationEvidencePacket, PacketEvent } from '../types';

interface InvestigationAssessmentProps {
  assessment: InvestigationAssessment;
  packet: InvestigationEvidencePacket;
  flows: FlowSummary[];
  events?: PacketEvent[];
  onNavigateToFlows: (flows: FlowSummary[]) => void;
  onNavigateToEvent?: (eventId: string) => void;
  variant?: 'compact' | 'full';
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
  events = [],
  onNavigateToFlows,
  onNavigateToEvent,
  variant = 'compact',
}: InvestigationAssessmentProps) {
  const full = variant === 'full';
  const bodyText = full ? 'text-sm' : 'text-[10px]';
  const sectionHeading = full ? 'text-sm' : 'text-[10px] uppercase tracking-wider';
  const chipText = full ? 'text-[11px]' : 'text-[9px]';
  const evidenceChip = (evidenceId: string) => {
    const citedFlow = resolveCitedFlow(evidenceId, packet, flows);
    if (citedFlow) {
      return (
        <button
          type="button"
          key={evidenceId}
          onClick={() => onNavigateToFlows([citedFlow])}
          className={`inline-flex items-center gap-1 rounded border border-accent-primary/25 bg-accent-soft px-1.5 py-0.5 font-mono text-accent-primary hover:text-accent-primary-hover focus:outline-none focus:ring-2 focus:ring-accent-primary ${chipText}`}
          title={`Open exact flow ${evidenceId}`}
        >
          {evidenceId}
          <ArrowRight size={8} />
        </button>
      );
    }
    const citedEvent = resolveCitedEvent(evidenceId, packet, events);
    if (citedEvent && onNavigateToEvent) {
      return (
        <button
          type="button"
          key={evidenceId}
          onClick={() => onNavigateToEvent(citedEvent.id)}
          className={`inline-flex items-center gap-1 rounded border border-accent-primary/25 bg-accent-soft px-1.5 py-0.5 font-mono text-accent-primary hover:text-accent-primary-hover focus:outline-none focus:ring-2 focus:ring-accent-primary ${chipText}`}
          title={`Open exact event ${evidenceId}`}
        >
          {evidenceId}
          <ArrowRight size={full ? 11 : 8} />
        </button>
      );
    }
    return (
      <span key={evidenceId} className={`inline-flex rounded border border-border-subtle bg-surface-muted px-1.5 py-0.5 font-mono text-text-muted ${chipText}`}>
        {evidenceId}
      </span>
    );
  };

  return (
    <div id="investigation-assessment" data-testid="investigation-assessment" className={`${full ? 'space-y-7' : 'space-y-3 rounded-xl border border-accent-primary/20 bg-accent-soft/20 p-3'}`}>
      <div className="space-y-1">
        <h2 className={`${full ? 'text-lg' : 'text-[10px] uppercase tracking-[0.16em]'} font-bold text-text-primary`}>Assessment summary</h2>
        <p className={`${full ? 'mt-3 text-[15px] leading-7' : 'text-[11px] leading-relaxed'} text-text-secondary`}>{assessment.summary}</p>
      </div>

      <section className={full ? 'space-y-3' : 'space-y-1.5'} aria-labelledby="investigation-observed-heading">
        <h3 id="investigation-observed-heading" className={`flex items-center gap-2 font-bold text-text-primary ${sectionHeading}`}>
          <Eye size={full ? 16 : 11} /> Observed evidence
        </h3>
        {assessment.observedEvidence.length > 0 ? (
          <ul className={full ? 'space-y-3' : 'space-y-2'}>
            {assessment.observedEvidence.map((item, index) => (
              <li key={`${item.statement}-${index}`} className={`rounded-lg border border-border-subtle/50 bg-surface ${full ? 'p-4' : 'p-2'} ${bodyText} text-text-secondary`}>
                <p className="leading-relaxed">{item.statement}</p>
                <div className="mt-1.5 flex flex-wrap gap-1">{item.evidenceIds.map(evidenceChip)}</div>
              </li>
            ))}
          </ul>
        ) : (
          <p className={`${bodyText} italic text-text-muted`}>No model statement retained a supported evidence citation.</p>
        )}
      </section>

      <section className={full ? 'space-y-3' : 'space-y-1.5'} aria-labelledby="investigation-inference-heading">
        <h3 id="investigation-inference-heading" className={`flex items-center gap-2 font-bold text-text-primary ${sectionHeading}`}>
          <Lightbulb size={full ? 16 : 11} /> Analyst inference
        </h3>
        {assessment.inferences.length > 0 ? (
          <ul className={full ? 'space-y-3' : 'space-y-2'}>
            {assessment.inferences.map((item, index) => (
              <li key={`${item.statement}-${index}`} className={`rounded-lg border border-border-subtle/50 bg-surface ${full ? 'p-4' : 'p-2'} ${bodyText} text-text-secondary`}>
                <div className="flex items-start justify-between gap-2">
                  <p className="leading-relaxed">{item.statement}</p>
                  <span className={`shrink-0 rounded border px-1.5 py-0.5 ${full ? 'text-[10px]' : 'text-[8px]'} font-bold uppercase ${confidenceStyle(item.confidence)}`}>
                    {item.confidence}
                  </span>
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1">{item.evidenceIds.map(evidenceChip)}</div>
              </li>
            ))}
          </ul>
        ) : (
          <p className={`${bodyText} italic text-text-muted`}>No supported inference was returned.</p>
        )}
      </section>

      <section className={`${full ? 'space-y-3 p-4' : 'space-y-1.5 p-2'} rounded-lg border border-status-warning/20 bg-status-warning-bg/10`} aria-labelledby="investigation-uncertainty-heading">
        <h3 id="investigation-uncertainty-heading" className={`flex items-center gap-2 font-bold text-status-warning ${sectionHeading}`}>
          <AlertCircle size={full ? 16 : 11} /> Uncertainty / missing evidence
        </h3>
        <div className={`${full ? 'text-xs' : 'text-[9px]'} font-bold uppercase tracking-wider text-status-warning`}>Not confirmed</div>
        {assessment.uncertainties.length > 0 ? (
          <ul className={`list-disc space-y-1 pl-5 leading-relaxed text-text-secondary ${bodyText}`}>
            {assessment.uncertainties.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
          </ul>
        ) : (
          <p className={`${bodyText} italic text-text-muted`}>The model did not identify additional missing evidence.</p>
        )}
      </section>

      <section className={full ? 'space-y-3' : 'space-y-1.5'} aria-labelledby="investigation-next-steps-heading">
        <h3 id="investigation-next-steps-heading" className={`flex items-center gap-2 font-bold text-text-primary ${sectionHeading}`}>
          <SearchCheck size={full ? 16 : 11} /> Recommended next investigative steps
        </h3>
        {assessment.nextSteps.length > 0 ? (
          <ol className={full ? 'space-y-3' : 'space-y-1.5'}>
            {assessment.nextSteps.map((step, index) => (
              <li key={`${step.action}-${index}`} className={`rounded-lg border border-border-subtle/50 bg-surface ${full ? 'p-4' : 'p-2'} ${bodyText} text-text-secondary`}>
                <div className="font-semibold text-text-primary">{index + 1}. {step.action}</div>
                <p className="mt-0.5 leading-relaxed text-text-muted">{step.reason}</p>
              </li>
            ))}
          </ol>
        ) : (
          <p className={`${bodyText} italic text-text-muted`}>No next investigative steps were returned.</p>
        )}
      </section>
    </div>
  );
}
