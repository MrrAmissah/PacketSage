import React, { useEffect, useRef, useState } from 'react';
import { Check, Compass, RefreshCw, Sparkles } from 'lucide-react';
import type { ParsedResult } from '../lib/parser';
import type { CaptureOverviewRecord } from '../types';
import { completedCaptureOverview, validateCaptureOverviewResponse } from '../lib/captureOverview';

interface Props {
  data: ParsedResult;
  record: CaptureOverviewRecord | null;
  onCompleted(record: CaptureOverviewRecord): void;
  onInvalidated(): void;
  onInclusionChange(included: boolean): void;
}

const sections = [
  ['Capture orientation', 'executiveSummary'], ['Traffic-pattern explanation', 'whatHappened'],
  ['Likely routine activity', 'normalActivity'], ['Review-worthy patterns', 'suspiciousActivity'],
  ['Beginner perspective', 'beginnerExplanation'], ['Technical perspective', 'technicalExplanation'],
  ['Analyst triage questions', 'analystQuestions'], ['Suggested checks', 'recommendedChecks'],
  ['Limitations', 'limitations'],
] as const;

export default function CaptureOverview({ data, record, onCompleted, onInvalidated, onInclusionChange }: Props) {
  const [perspective, setPerspective] = useState('balanced');
  const [state, setState] = useState<'idle' | 'loading' | 'failure'>('idle');
  const [error, setError] = useState('');
  const requestSequence = useRef(0);
  const activeController = useRef<AbortController | null>(null);
  const captureIdentity = data.evidence.id;

  useEffect(() => {
    requestSequence.current += 1;
    activeController.current?.abort();
    activeController.current = null;
    setState('idle');
    setError('');
  }, [captureIdentity]);

  useEffect(() => () => activeController.current?.abort(), []);

  const generate = async () => {
    activeController.current?.abort();
    const controller = new AbortController();
    activeController.current = controller;
    const sequence = ++requestSequence.current;
    onInvalidated();
    setState('loading');
    setError('');
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: controller.signal,
        body: JSON.stringify({
          captureIdentity, fileName: data.evidence.name, perspective,
          flowSummary: data.flows, dnsRecords: data.dns, httpRecords: data.http,
          tlsRecords: data.tls, suspiciousSignals: data.signals, protocolStats: data.protocolStats,
        }),
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(body && typeof body === 'object' && typeof (body as { error?: unknown }).error === 'string' ? (body as { error: string }).error : 'Capture overview could not be completed. Try again.');
      const validated = validateCaptureOverviewResponse(body);
      if (controller.signal.aborted || sequence !== requestSequence.current || captureIdentity !== data.evidence.id) return;
      onCompleted(completedCaptureOverview(captureIdentity, validated));
      setState('idle');
    } catch (cause) {
      if (controller.signal.aborted || sequence !== requestSequence.current) return;
      setState('failure');
      setError(cause instanceof Error ? cause.message : 'Capture overview could not be completed. Try again.');
    } finally {
      if (activeController.current === controller) activeController.current = null;
    }
  };

  const current = record?.captureIdentity === captureIdentity ? record : null;
  return (
    <div className="space-y-5" data-testid="capture-overview">
      <header className="rounded-xl border border-border-subtle bg-surface p-5">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
          <div><p className="text-[10px] font-bold uppercase tracking-widest text-purple-500">Optional whole-capture orientation</p><h1 className="mt-1 flex items-center gap-2 text-xl font-bold text-text-primary"><Compass size={20} /> Capture Overview</h1></div>
          <details className="rounded-lg border border-border-subtle px-3 py-2 text-[10px] text-text-secondary"><summary className="cursor-pointer font-semibold">Technical details</summary><div className="mt-2"><strong>Provider:</strong> Google<br/><strong>Model:</strong> {current?.model || 'recorded after generation'}<br/><strong>Schema:</strong> {current?.schemaVersion || '1'}</div></details>
        </div>
        <p className="mt-4 rounded-lg border border-status-warning/20 bg-status-warning-bg/10 p-3 text-xs leading-relaxed text-text-secondary">This overview is generated from a bounded summary of the loaded capture. It is intended for orientation and does not replace evidence-linked investigation.</p>
        <p className="mt-2 text-[10px] text-text-muted">It cannot create or modify deterministic findings, is not observed evidence, and remains separate from Evidence-grounded Investigation.</p>
      </header>

      <section className="rounded-xl border border-border-subtle bg-surface p-5">
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-xs font-semibold text-text-primary">Perspective<select value={perspective} onChange={event => setPerspective(event.target.value)} disabled={state === 'loading'} className="mt-1 block rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs"><option value="balanced">Balanced orientation</option><option value="beginner">Beginner learning</option><option value="technical">Technical learning</option><option value="triage">Analyst triage</option></select></label>
          <button type="button" onClick={generate} disabled={state === 'loading'} className="inline-flex items-center gap-2 rounded-lg bg-purple-600 px-4 py-2 text-xs font-bold text-white disabled:cursor-not-allowed disabled:opacity-60">{state === 'loading' ? <RefreshCw size={14} className="animate-spin" /> : <Sparkles size={14} />}{state === 'loading' ? 'Generating…' : current ? 'Generate new overview' : 'Generate capture overview'}</button>
        </div>
        {state === 'failure' && <div role="alert" className="mt-4 rounded-lg border border-status-danger/20 bg-status-danger-bg/10 p-3 text-xs"><p className="font-semibold text-status-danger">No overview was generated.</p><p className="mt-1 text-text-secondary">{error}</p><button type="button" onClick={generate} className="mt-2 font-bold text-accent-primary">Retry</button></div>}
      </section>

      {current ? <section className="space-y-4 rounded-xl border border-purple-500/20 bg-surface p-5">
        <header className="flex flex-col justify-between gap-3 sm:flex-row"><div><h2 className="font-bold text-text-primary">Capture overview</h2><p className="text-[10px] text-text-muted">Generated {new Date(current.createdAt).toLocaleString()} · {current.generationState}</p></div><button type="button" aria-pressed={current.includedInReport} onClick={() => onInclusionChange(!current.includedInReport)} className="inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 text-xs font-bold text-text-primary">{current.includedInReport && <Check size={13} />}{current.includedInReport ? 'Overview included as contextual note' : 'Include overview as contextual note'}</button></header>
        <p className="rounded-lg bg-surface-muted p-3 text-[10px] text-text-muted">Context only — not evidence-linked. This section has no evidence citations.</p>
        <div className="grid gap-3 lg:grid-cols-2">{sections.map(([label, field]) => <article key={field} className="rounded-lg border border-border-subtle p-3"><h3 className="text-xs font-bold text-text-primary">{label}</h3><p className="mt-2 whitespace-pre-wrap text-xs leading-relaxed text-text-secondary">{current.result[field]}</p></article>)}</div>
      </section> : state !== 'loading' && <p className="rounded-xl border border-dashed border-border-subtle p-5 text-xs text-text-muted">No capture overview has been retained for this evidence.</p>}
    </div>
  );
}
