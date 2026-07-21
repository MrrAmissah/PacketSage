import React, { useMemo, useState } from 'react';
import { Activity, ArrowRight, Search, X } from 'lucide-react';
import type { FlowSummary, PacketEvent, SuspiciousSignal } from '../types';
import { flowsForEvent, signalsForEvent } from '../lib/evidenceRelationships';

interface IncidentTimelineProps {
  events: PacketEvent[];
  flows?: FlowSummary[];
  signals?: SuspiciousSignal[];
  onNavigateToFlows?: (flows: FlowSummary[]) => void;
}

function endpoint(ip: string, port: number): string {
  const address = ip.includes(':') ? `[${ip}]` : ip;
  return `${address}:${port > 0 ? port : 'unknown'}`;
}

function timestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString();
}

export default function IncidentTimeline({ events, flows = [], signals = [], onNavigateToFlows }: IncidentTimelineProps) {
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const sortedEvents = useMemo(() => [...events].sort((left, right) => left.timestamp.localeCompare(right.timestamp) || left.id.localeCompare(right.id)), [events]);
  const protocols = useMemo(() => Array.from(new Set(events.map(event => event.protocol))).sort(), [events]);
  const visibleEvents = useMemo(() => sortedEvents.filter(event => {
    const text = `${event.id} ${event.timestamp} ${event.sourceIp} ${event.sourcePort || ''} ${event.destinationIp} ${event.destinationPort || ''} ${event.protocol} ${event.service || ''} ${event.info || ''}`.toLowerCase();
    return (protocolFilter === 'ALL' || event.protocol === protocolFilter) && text.includes(search.trim().toLowerCase());
  }), [sortedEvents, protocolFilter, search]);
  const selectedEvent = events.find(event => event.id === selectedEventId) || null;
  const relatedFlows = selectedEvent ? flowsForEvent(selectedEvent.id, flows) : [];
  const relatedSignals = selectedEvent ? signalsForEvent(selectedEvent.id, signals) : [];

  return (
    <section className="space-y-5" aria-labelledby="timeline-title">
      <header className="border-b border-border-subtle pb-4">
        <p className="text-[10px] font-bold uppercase tracking-widest text-accent-primary">Observed chronology</p>
        <h1 id="timeline-title" className="text-xl font-bold text-text-primary">Incident timeline</h1>
        <p className="mt-1 text-xs text-text-muted">Chronological normalized records. Related flows and signals resolve only through explicit parser-established IDs.</p>
      </header>

      <div className="grid gap-3 rounded-xl border border-border-subtle bg-surface p-3 sm:grid-cols-[minmax(0,1fr)_auto]">
        <label className="relative"><span className="sr-only">Search timeline events</span><Search aria-hidden="true" size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" /><input value={search} onChange={event => setSearch(event.target.value)} className="w-full rounded-lg border border-border-subtle bg-canvas py-2 pl-9 pr-3 text-xs" placeholder="Search observed event fields" /></label>
        <label className="text-[10px] text-text-muted">Protocol<select aria-label="Filter timeline by protocol" value={protocolFilter} onChange={event => setProtocolFilter(event.target.value)} className="ml-2 rounded border border-border-subtle bg-canvas px-2 py-2 text-xs text-text-primary"><option>ALL</option>{protocols.map(protocol => <option key={protocol}>{protocol}</option>)}</select></label>
      </div>

      <div className={`grid gap-5 ${selectedEvent ? 'xl:grid-cols-[minmax(0,1fr)_360px]' : ''}`}>
        <ol className="space-y-2" aria-label="Timeline events">
          {visibleEvents.map(event => {
            const exactFlowCount = flowsForEvent(event.id, flows).length;
            const exactSignalCount = signalsForEvent(event.id, signals).length;
            return (
              <li key={event.id}>
                <button type="button" onClick={() => setSelectedEventId(event.id)} aria-pressed={selectedEventId === event.id} className={`w-full rounded-xl border p-4 text-left transition-colors focus:outline-none focus:ring-2 focus:ring-accent-primary ${selectedEventId === event.id ? 'border-accent-primary bg-accent-soft' : 'border-border-subtle bg-surface hover:bg-surface-muted/40'}`}>
                  <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-start"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><Activity aria-hidden="true" size={13} className="text-accent-primary" /><code className="text-[10px] text-text-muted">{event.id}</code><span className="rounded bg-surface-muted px-1.5 py-0.5 text-[9px] font-bold uppercase text-text-secondary">{event.protocol}</span>{event.service && <span className="text-[10px] text-text-muted">{event.service}</span>}</div><p className="mt-2 text-xs text-text-primary">{event.info || 'No decoded description was recorded.'}</p><p className="mt-2 font-mono text-[10px] text-text-muted">{endpoint(event.sourceIp, event.sourcePort)} → {endpoint(event.destinationIp, event.destinationPort)}</p></div><time className="shrink-0 font-mono text-[10px] text-text-muted" dateTime={event.timestamp}>{timestamp(event.timestamp)}</time></div>
                  <p className="mt-3 text-[9px] text-text-muted">Exact relationships: {exactFlowCount} flow{exactFlowCount === 1 ? '' : 's'} · {exactSignalCount} signal{exactSignalCount === 1 ? '' : 's'}</p>
                </button>
              </li>
            );
          })}
          {!visibleEvents.length && <li className="rounded-xl border border-dashed border-border-subtle bg-surface p-10 text-center text-xs text-text-muted">No observed timeline events match these filters.</li>}
        </ol>

        {selectedEvent && (
          <aside className="h-fit space-y-4 rounded-xl border border-border-subtle bg-surface p-4 shadow-sm" aria-label={`Timeline event detail ${selectedEvent.id}`}>
            <header className="flex items-start justify-between border-b border-border-subtle pb-3"><div><p className="text-[9px] font-bold uppercase tracking-widest text-accent-primary">Observed event</p><h2 className="font-mono text-xs font-bold text-text-primary">{selectedEvent.id}</h2></div><button type="button" onClick={() => setSelectedEventId(null)} aria-label="Close timeline event details" className="rounded border border-border-subtle p-1.5 text-text-muted"><X aria-hidden="true" size={13} /></button></header>
            <dl className="grid gap-2 text-[11px]"><div><dt className="text-text-muted">Timestamp</dt><dd className="font-mono">{timestamp(selectedEvent.timestamp)}</dd></div><div><dt className="text-text-muted">Source</dt><dd className="font-mono">{endpoint(selectedEvent.sourceIp, selectedEvent.sourcePort)}</dd></div><div><dt className="text-text-muted">Destination</dt><dd className="font-mono">{endpoint(selectedEvent.destinationIp, selectedEvent.destinationPort)}</dd></div><div className="grid grid-cols-2"><div><dt className="text-text-muted">Protocol</dt><dd>{selectedEvent.protocol}</dd></div><div><dt className="text-text-muted">Length</dt><dd>{selectedEvent.length} bytes</dd></div></div><div><dt className="text-text-muted">Decoded description</dt><dd>{selectedEvent.info || 'Not recorded'}</dd></div></dl>
            <section><h3 className="mb-2 text-[10px] font-bold uppercase tracking-wider text-text-muted">Exact related flows ({relatedFlows.length})</h3>{relatedFlows.length ? <ul className="space-y-2">{relatedFlows.map(flow => <li key={flow.id} className="rounded-lg border border-border-subtle p-2 text-[10px]"><code>{flow.id}</code><p className="mt-1 font-mono text-text-muted">{endpoint(flow.sourceIp, flow.sourcePort)} → {endpoint(flow.destinationIp, flow.destinationPort)}</p></li>)}</ul> : <p className="text-[11px] text-text-muted">No flow explicitly records this event ID.</p>}</section>
            <section><h3 className="mb-2 text-[10px] font-bold uppercase tracking-wider text-text-muted">Exact related signals ({relatedSignals.length})</h3>{relatedSignals.length ? <ul className="space-y-2">{relatedSignals.map(signal => <li key={signal.id} className="rounded-lg border border-border-subtle p-2 text-[10px]"><span className="font-semibold text-text-primary">{signal.title}</span><code className="mt-1 block">{signal.id}</code></li>)}</ul> : <p className="text-[11px] text-text-muted">No signal explicitly records this event ID.</p>}</section>
            <button type="button" disabled={!relatedFlows.length || !onNavigateToFlows} onClick={() => onNavigateToFlows?.(relatedFlows)} className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg bg-accent-primary py-2 text-xs font-bold text-white disabled:cursor-not-allowed disabled:bg-surface-muted disabled:text-text-muted">{relatedFlows.length ? 'Open exact related flow' : 'Related flow unavailable'}<ArrowRight aria-hidden="true" size={12} /></button>
          </aside>
        )}
      </div>
    </section>
  );
}
