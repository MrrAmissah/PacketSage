import React, { useMemo } from 'react';
import { Activity, ArrowRight, Database, FileText, Globe, Layers, Server, ShieldCheck } from 'lucide-react';
import type { ParsedResult } from '../lib/parser';
import { commandCenterLimitation, commandCenterNextActions, observedEventDescription, recordedHostnames } from '../lib/commandCenterPresentation';

interface CommandCenterProps {
  data: ParsedResult | null;
  onNavigate: (tab: string) => void;
  signalStatusOverrides?: Record<string, string>;
}

function endpoint(ip: string, port: number): string {
  const address = ip.includes(':') ? `[${ip}]` : ip;
  return `${address}:${port > 0 ? port : 'unknown'}`;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export default function CommandCenter({ data, onNavigate, signalStatusOverrides = {} }: CommandCenterProps) {
  if (!data) {
    return <section className="flex flex-col items-center justify-center py-24 text-center"><Server aria-hidden="true" size={32} className="mb-4 text-text-muted" /><h1 className="text-sm font-semibold text-text-primary">No network evidence loaded</h1><p className="mt-2 max-w-md text-xs text-text-muted">Import a supported capture or structured export to begin.</p><button type="button" onClick={() => onNavigate('import')} className="mt-5 rounded-lg bg-accent-primary px-4 py-2 text-xs font-bold text-white">Go to Evidence Import</button></section>;
  }

  const { evidence, events, flows, dns, http, tls, signals, protocolStats } = data;
  const endpoints = useMemo(() => Array.from(new Set(events.flatMap(event => [event.sourceIp, event.destinationIp]))), [events]);
  const hostnames = useMemo(() => recordedHostnames(data), [data]);
  const actions = useMemo(() => commandCenterNextActions(data), [data]);
  const reviewedCount = signals.filter(signal => (signalStatusOverrides[signal.id] || signal.status) === 'Added to report').length;
  const totalBytes = events.reduce((sum, event) => sum + event.length, 0);

  return (
    <section id="command-center-workspace" className="space-y-6" aria-labelledby="command-center-title">
      <header className="flex flex-col justify-between gap-4 border-b border-border-subtle pb-4 sm:flex-row sm:items-start">
        <div className="flex min-w-0 items-start gap-3"><div className="rounded-xl bg-accent-primary p-3 text-white"><FileText aria-hidden="true" size={20} /></div><div className="min-w-0"><p className="text-[10px] font-bold uppercase tracking-widest text-accent-primary">Forensic workspace</p><h1 id="command-center-title" className="truncate text-xl font-bold text-text-primary">{evidence.name}</h1><p className="mt-1 text-xs text-text-muted">{evidence.sourceFormat} · {evidence.parseMode} · {formatSize(evidence.size)}</p></div></div>
        {evidence.parseMode === 'demo' && <span className="w-fit rounded-full border border-status-warning/20 bg-status-warning-bg px-3 py-1 text-[10px] font-bold uppercase text-status-warning">Generated sample</span>}
      </header>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {[
          ['Events', events.length], ['Flows', flows.length], ['Endpoints', endpoints.length], ['Observed bytes', totalBytes], ['Signals', signals.length], ['Reviewed findings', reviewedCount],
        ].map(([label, value]) => <article key={label} className="rounded-xl border border-border-subtle bg-surface p-4"><p className="text-[9px] font-bold uppercase tracking-wider text-text-muted">{label}</p><p className="mt-1 font-mono text-lg font-bold text-text-primary">{value}</p></article>)}
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="space-y-5">
          <section className="rounded-xl border border-border-subtle bg-surface p-5" aria-labelledby="protocol-summary-title"><div className="mb-4 flex items-center justify-between"><div><h2 id="protocol-summary-title" className="text-sm font-bold text-text-primary">Observed protocol statistics</h2><p className="mt-1 text-[11px] text-text-muted">Counts and bytes from normalized events only.</p></div><Globe aria-hidden="true" size={16} className="text-accent-primary" /></div>{protocolStats.length ? <div className="grid gap-2 sm:grid-cols-2">{protocolStats.map(stat => <button key={stat.protocol} type="button" onClick={() => onNavigate('protocols')} className="rounded-lg border border-border-subtle p-3 text-left hover:bg-surface-muted"><div className="flex items-center justify-between gap-3"><span className="font-mono text-xs font-bold text-text-primary">{stat.protocol}</span><span className="font-mono text-[10px] text-text-muted">{stat.percentage}%</span></div><p className="mt-2 text-[10px] text-text-muted">{stat.count} records · {stat.byteCount} bytes</p></button>)}</div> : <p className="rounded-lg bg-surface-muted p-4 text-xs text-text-muted">No protocol statistics were produced for this evidence.</p>}</section>

          <section className="rounded-xl border border-border-subtle bg-surface p-5" aria-labelledby="signals-summary-title"><div className="mb-4 flex items-center justify-between"><div><h2 id="signals-summary-title" className="text-sm font-bold text-text-primary">Signals requiring review</h2><p className="mt-1 text-[11px] text-text-muted">Deterministic observations generated from the loaded records.</p></div><ShieldCheck aria-hidden="true" size={16} className="text-accent-primary" /></div>{signals.length ? <ul className="space-y-2">{signals.slice(0, 4).map(signal => <li key={signal.id}><button type="button" onClick={() => onNavigate('signals')} className="w-full rounded-lg border border-border-subtle p-3 text-left hover:bg-surface-muted"><div className="flex items-center justify-between gap-3"><span className="text-xs font-semibold text-text-primary">{signal.title}</span><span className="text-[9px] font-bold uppercase text-text-muted">{signal.severity}</span></div><p className="mt-1 line-clamp-2 text-[10px] text-text-muted">{signal.observedEvidence}</p></button></li>)}</ul> : <p className="rounded-lg bg-surface-muted p-4 text-xs text-text-muted">No deterministic signals were generated from the loaded evidence.</p>}</section>

          <section className="rounded-xl border border-border-subtle bg-surface p-5" aria-labelledby="timeline-preview-title"><div className="mb-4 flex items-center justify-between"><div><h2 id="timeline-preview-title" className="text-sm font-bold text-text-primary">Observed timeline preview</h2><p className="mt-1 text-[11px] text-text-muted">Earliest normalized records.</p></div><Activity aria-hidden="true" size={16} className="text-accent-primary" /></div>{events.length ? <ul className="divide-y divide-border-subtle">{[...events].sort((left, right) => left.timestamp.localeCompare(right.timestamp)).slice(0, 5).map(event => <li key={event.id} className="py-3"><div className="flex flex-col justify-between gap-1 sm:flex-row"><code className="text-[10px] text-text-muted">{event.timestamp}</code><span className="text-[9px] font-bold uppercase text-text-muted">{event.protocol}</span></div><p className="mt-1 text-xs text-text-primary">{observedEventDescription(event)}</p><p className="mt-1 font-mono text-[10px] text-text-muted">{endpoint(event.sourceIp, event.sourcePort)} → {endpoint(event.destinationIp, event.destinationPort)} · {event.length} bytes</p></li>)}</ul> : <p className="rounded-lg bg-surface-muted p-4 text-xs text-text-muted">No normalized events are available.</p>}</section>
        </div>

        <aside className="h-fit space-y-5 rounded-xl border border-border-subtle bg-surface p-5 xl:sticky xl:top-4" aria-label="Investigation brief">
          <div><h2 className="text-sm font-bold text-text-primary">Evidence brief</h2><p className="mt-1 text-[11px] text-text-muted">Current content is limited to this loaded evidence.</p></div>
          <dl className="grid gap-3 text-[11px]"><div><dt className="font-semibold text-text-muted">Decoded metadata</dt><dd className="mt-1 text-text-secondary">{dns.length} DNS · {http.length} HTTP · {tls.length} TLS records</dd></div><div><dt className="font-semibold text-text-muted">Recorded hostnames</dt><dd className="mt-1">{hostnames.length ? <span className="flex flex-wrap gap-1">{hostnames.map(host => <code key={host} className="rounded bg-surface-muted px-1.5 py-0.5 text-[10px]">{host}</code>)}</span> : <span className="text-text-muted">No hostname metadata was recorded.</span>}</dd></div><div><dt className="font-semibold text-text-muted">Limitations</dt><dd className="mt-1 leading-relaxed text-text-muted">{commandCenterLimitation(evidence.parseMode)}</dd></div></dl>
          <div><h3 className="mb-2 text-[10px] font-bold uppercase tracking-wider text-text-muted">Available next actions</h3><div className="space-y-2">{actions.map(action => <button key={action.destination} type="button" onClick={() => onNavigate(action.destination)} className="flex w-full items-center justify-between rounded-lg border border-border-subtle p-3 text-left text-xs font-semibold text-text-primary hover:bg-surface-muted"><span className="flex items-center gap-2">{action.destination === 'flows' ? <Layers aria-hidden="true" size={13} /> : action.destination === 'import' ? <Database aria-hidden="true" size={13} /> : <ShieldCheck aria-hidden="true" size={13} />}{action.label}</span><ArrowRight aria-hidden="true" size={12} /></button>)}</div></div>
        </aside>
      </div>
    </section>
  );
}
