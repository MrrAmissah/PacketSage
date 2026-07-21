import type React from 'react';
import { CheckCircle2, ExternalLink, RotateCcw } from 'lucide-react';
import type { InvestigationRecord } from '../types';

interface CompactInvestigationResultProps {
  record: InvestigationRecord;
  citationCount: number;
  openButtonRef: React.RefObject<HTMLButtonElement | null>;
  onOpen(): void;
  onRerun(): void;
}

export default function CompactInvestigationResult({
  record,
  citationCount,
  openButtonRef,
  onOpen,
  onRerun,
}: CompactInvestigationResultProps) {
  return (
    <section className="space-y-3 rounded-xl border border-accent-primary/20 bg-accent-soft/20 p-3" aria-labelledby="compact-assessment-title" data-testid="compact-investigation-result">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="inline-flex items-center gap-1 text-[9px] font-bold uppercase tracking-widest text-status-success"><CheckCircle2 aria-hidden="true" size={11} /> Completed</p>
          <h4 id="compact-assessment-title" className="mt-1 text-xs font-bold text-text-primary">Assessment available</h4>
        </div>
        <span className={`shrink-0 rounded-full border px-2 py-1 text-[9px] font-bold ${record.includedInReport ? 'border-status-success/30 bg-status-success/10 text-status-success' : 'border-border-subtle bg-surface text-text-muted'}`}>
          {record.includedInReport ? 'Included in report' : 'Not included'}
        </span>
      </div>

      <p className="line-clamp-4 text-[11px] leading-relaxed text-text-secondary">{record.assessment.summary}</p>
      <p className="font-mono text-[9px] text-text-muted">{citationCount} exact citation{citationCount === 1 ? '' : 's'} retained</p>

      <button
        ref={openButtonRef}
        type="button"
        data-testid="open-full-assessment"
        data-tour-target="open-full-assessment"
        onClick={onOpen}
        className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg bg-accent-primary px-3 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-accent-primary-hover focus:outline-none focus:ring-2 focus:ring-accent-primary focus:ring-offset-2"
      >
        Open full assessment <ExternalLink aria-hidden="true" size={12} />
      </button>
      <button type="button" onClick={onRerun} className="inline-flex items-center gap-1 text-[10px] font-semibold text-accent-primary hover:text-accent-primary-hover focus:outline-none focus:ring-2 focus:ring-accent-primary">
        <RotateCcw aria-hidden="true" size={10} /> Run again with current referenced evidence
      </button>
    </section>
  );
}
