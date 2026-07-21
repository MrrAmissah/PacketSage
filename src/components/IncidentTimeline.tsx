import React, { useEffect, useMemo, useState } from 'react';
import { Activity, ArrowDown, ArrowRight, ArrowUp, FileText, Globe, Network, RotateCcw, Search, ShieldCheck, X } from 'lucide-react';
import type { FlowSummary, PacketEvent, SuspiciousSignal } from '../types';
import { flowsForEvent, signalsForEvent } from '../lib/evidenceRelationships';

interface IncidentTimelineProps {
  events: PacketEvent[];
  flows?: FlowSummary[];
  signals?: SuspiciousSignal[];
  focusedEventId?: string | null;
  onFocusedEventHandled?: () => void;
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

function timelineTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString().slice(11, 19);
}

function relativeTimelineTime(value: string, startTime: number | null): string {
  const eventTime = new Date(value).getTime();
  if (startTime === null || Number.isNaN(eventTime)) return 'offset unknown';
  const totalSeconds = Math.max(0, Math.floor((eventTime - startTime) / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return `+${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

function markerForEvent(event: PacketEvent) {
  const recordedLabels = [event.protocol, event.service].filter(Boolean).map(value => value!.toUpperCase());
  if (recordedLabels.includes('DNS')) return { Icon: Globe, style: 'border-violet-700 bg-violet-500 text-white' };
  if (recordedLabels.some(value => value === 'HTTP' || value === 'HTTP/1.1' || value === 'HTTP/2')) return { Icon: FileText, style: 'border-amber-600 bg-amber-500 text-white' };
  if (recordedLabels.some(value => value === 'TLS' || value === 'HTTPS' || value.startsWith('TLSV'))) return { Icon: ShieldCheck, style: 'border-emerald-700 bg-emerald-600 text-white' };
  if (recordedLabels.some(value => value === 'TCP' || value === 'UDP')) return { Icon: Network, style: 'border-sky-700 bg-sky-600 text-white' };
  return { Icon: Activity, style: 'border-slate-600 bg-slate-500 text-white' };
}

function observedEventLabel(event: PacketEvent): string {
  const protocol = event.protocol || 'Network';
  const service = event.service && event.service.toLowerCase() !== protocol.toLowerCase() ? `${event.service} / ` : '';
  return `${service}${protocol} event observed`;
}

function observedEventDescription(event: PacketEvent): string {
  const service = event.service ? ` for the recorded ${event.service} service` : '';
  const detail = event.info ? ` The decoder described it as: ${event.info}` : ' The decoder did not provide an additional description.';
  return `At ${timestamp(event.timestamp)}, PacketSage recorded ${event.protocol} network traffic${service}. It travelled from source ${endpoint(event.sourceIp, event.sourcePort)} to destination ${endpoint(event.destinationIp, event.destinationPort)}, and the normalized record reports ${event.length} bytes.${detail}`;
}

export default function IncidentTimeline({ events, flows = [], signals = [], focusedEventId = null, onFocusedEventHandled, onNavigateToFlows }: IncidentTimelineProps) {
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [serviceFilter, setServiceFilter] = useState('ALL');
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [timeFilter, setTimeFilter] = useState('ALL');
  const [ascending, setAscending] = useState(true);

  useEffect(() => {
    if (!focusedEventId) return;
    const exactEvent = events.find(event => event.id === focusedEventId);
    if (!exactEvent) {
      onFocusedEventHandled?.();
      return;
    }
    setSearch('');
    setProtocolFilter('ALL');
    setServiceFilter('ALL');
    setSourceFilter('ALL');
    setTimeFilter('ALL');
    setAscending(true);
    setSelectedEventId(exactEvent.id);
    const frame = window.requestAnimationFrame(() => {
      const target = document.getElementById(`timeline-event-${exactEvent.id}`);
      target?.focus({ preventScroll: true });
      target?.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' });
      onFocusedEventHandled?.();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [events, focusedEventId, onFocusedEventHandled]);
  const sortedEvents = useMemo(() => [...events].sort((left, right) => left.timestamp.localeCompare(right.timestamp) || left.id.localeCompare(right.id)), [events]);
  const protocols = useMemo(() => Array.from(new Set(events.map(event => event.protocol))).sort(), [events]);
  const services = useMemo(() => Array.from(new Set(events.map(event => event.service).filter((service): service is string => Boolean(service)))).sort(), [events]);
  const sources = useMemo(() => Array.from(new Set(events.map(event => event.sourceIp))).sort(), [events]);
  const captureStartTime = useMemo(() => {
    const validTimes = sortedEvents.map(event => new Date(event.timestamp).getTime()).filter(Number.isFinite);
    return validTimes.length ? Math.min(...validTimes) : null;
  }, [sortedEvents]);
  const visibleEvents = useMemo(() => sortedEvents.filter(event => {
    const text = `${event.id} ${event.timestamp} ${event.sourceIp} ${event.sourcePort || ''} ${event.destinationIp} ${event.destinationPort || ''} ${event.protocol} ${event.service || ''} ${event.info || ''}`.toLowerCase();
    const eventTime = new Date(event.timestamp).getTime();
    const offset = captureStartTime === null || Number.isNaN(eventTime) ? null : eventTime - captureStartTime;
    const inTimeRange = timeFilter === 'ALL'
      || (timeFilter === 'FIRST_5_SECONDS' && offset !== null && offset <= 5_000)
      || (timeFilter === 'FIRST_MINUTE' && offset !== null && offset <= 60_000)
      || (timeFilter === 'AFTER_FIRST_MINUTE' && offset !== null && offset > 60_000);
    return inTimeRange
      && (protocolFilter === 'ALL' || event.protocol === protocolFilter)
      && (serviceFilter === 'ALL' || event.service === serviceFilter)
      && (sourceFilter === 'ALL' || event.sourceIp === sourceFilter)
      && text.includes(search.trim().toLowerCase());
  }).sort((left, right) => ascending
    ? left.timestamp.localeCompare(right.timestamp) || left.id.localeCompare(right.id)
    : right.timestamp.localeCompare(left.timestamp) || right.id.localeCompare(left.id)), [sortedEvents, captureStartTime, timeFilter, protocolFilter, serviceFilter, sourceFilter, search, ascending]);
  const visibleRange = useMemo(() => {
    const validTimes = visibleEvents.map(event => new Date(event.timestamp).getTime()).filter(Number.isFinite);
    if (!validTimes.length) return 'Unavailable';
    return `${new Date(Math.min(...validTimes)).toISOString().slice(11, 19)} – ${new Date(Math.max(...validTimes)).toISOString().slice(11, 19)} UTC`;
  }, [visibleEvents]);
  const visibleLinkedFlowCount = useMemo(() => new Set(visibleEvents.flatMap(event => flowsForEvent(event.id, flows).map(flow => flow.id))).size, [visibleEvents, flows]);
  const visibleLinkedSignalCount = useMemo(() => new Set(visibleEvents.flatMap(event => signalsForEvent(event.id, signals).map(signal => signal.id))).size, [visibleEvents, signals]);
  const filtersActive = Boolean(search || protocolFilter !== 'ALL' || serviceFilter !== 'ALL' || sourceFilter !== 'ALL' || timeFilter !== 'ALL');
  const resetFilters = () => {
    setSearch('');
    setProtocolFilter('ALL');
    setServiceFilter('ALL');
    setSourceFilter('ALL');
    setTimeFilter('ALL');
  };
  const selectedEvent = events.find(event => event.id === selectedEventId) || null;
  const relatedFlows = selectedEvent ? flowsForEvent(selectedEvent.id, flows) : [];
  const relatedSignals = selectedEvent ? signalsForEvent(selectedEvent.id, signals) : [];

  return (
    <section className="space-y-5" aria-labelledby="timeline-title">
      <header className="border-b border-border-subtle pb-4">
        <p className="text-[10px] font-bold uppercase tracking-widest text-accent-primary">Observed chronology</p>
        <h1 id="timeline-title" className="text-xl font-bold text-text-primary">Incident timeline</h1>
        <p className="mt-1 text-xs text-text-muted">Chronological normalized records. Related flows and signals resolve only through explicit parser-established IDs.</p>
        <dl className="mt-4 grid grid-cols-2 gap-3 border-t border-border-subtle/60 pt-3 md:grid-cols-4" data-testid="timeline-metadata">
          <div><dt className="text-[9px] font-bold uppercase tracking-wider text-text-muted">Timeline events</dt><dd className="mt-0.5 text-xs font-medium text-text-primary"><span className="font-mono">{visibleEvents.length}</span> of <span className="font-mono">{events.length}</span></dd></div>
          <div><dt className="text-[9px] font-bold uppercase tracking-wider text-text-muted">Displayed range</dt><dd className="mt-0.5 truncate font-mono text-[10px] font-medium text-text-primary">{visibleRange}</dd></div>
          <div><dt className="text-[9px] font-bold uppercase tracking-wider text-text-muted">Exact linked signals</dt><dd className="mt-0.5 text-xs font-medium text-text-primary"><span className="font-mono">{visibleLinkedSignalCount}</span> observed</dd></div>
          <div><dt className="text-[9px] font-bold uppercase tracking-wider text-text-muted">Exact related flows</dt><dd className="mt-0.5 text-xs font-medium text-text-primary"><span className="font-mono">{visibleLinkedFlowCount}</span> observed</dd></div>
        </dl>
      </header>

      <div className="flex flex-col gap-3 rounded-xl border border-border-subtle bg-surface p-3 shadow-sm xl:flex-row xl:items-center" data-testid="timeline-filter-bar">
        <label className="relative min-w-0 flex-1 xl:max-w-sm"><span className="sr-only">Search timeline events</span><Search aria-hidden="true" size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" /><input value={search} onChange={event => setSearch(event.target.value)} className="w-full rounded-lg border border-border-subtle bg-canvas py-2 pl-9 pr-3 text-xs" placeholder="Search details, endpoints, IDs…" /></label>
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
          <label className="text-[9px] font-bold uppercase tracking-wider text-text-muted">Time<select aria-label="Filter timeline by capture time" value={timeFilter} onChange={event => setTimeFilter(event.target.value)} className="ml-1.5 rounded border border-border-subtle bg-canvas px-2 py-2 text-xs font-normal normal-case tracking-normal text-text-primary"><option value="ALL">All times</option><option value="FIRST_5_SECONDS">First 5s</option><option value="FIRST_MINUTE">First 1m</option><option value="AFTER_FIRST_MINUTE">After 1m</option></select></label>
          <label className="text-[9px] font-bold uppercase tracking-wider text-text-muted">Protocol<select aria-label="Filter timeline by protocol" value={protocolFilter} onChange={event => setProtocolFilter(event.target.value)} className="ml-1.5 rounded border border-border-subtle bg-canvas px-2 py-2 text-xs font-normal normal-case tracking-normal text-text-primary"><option>ALL</option>{protocols.map(protocol => <option key={protocol}>{protocol}</option>)}</select></label>
          {services.length > 0 && <label className="text-[9px] font-bold uppercase tracking-wider text-text-muted">Service<select aria-label="Filter timeline by recorded service" value={serviceFilter} onChange={event => setServiceFilter(event.target.value)} className="ml-1.5 rounded border border-border-subtle bg-canvas px-2 py-2 text-xs font-normal normal-case tracking-normal text-text-primary"><option>ALL</option>{services.map(service => <option key={service}>{service}</option>)}</select></label>}
          {sources.length > 1 && <label className="text-[9px] font-bold uppercase tracking-wider text-text-muted">Source<select aria-label="Filter timeline by source endpoint" value={sourceFilter} onChange={event => setSourceFilter(event.target.value)} className="ml-1.5 max-w-40 rounded border border-border-subtle bg-canvas px-2 py-2 text-xs font-normal normal-case tracking-normal text-text-primary"><option>ALL</option>{sources.map(source => <option key={source}>{source}</option>)}</select></label>}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button type="button" onClick={() => setAscending(value => !value)} className="inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-canvas px-2.5 py-2 text-[10px] font-semibold text-text-secondary"><span aria-hidden="true">{ascending ? <ArrowDown size={12} /> : <ArrowUp size={12} />}</span>{ascending ? 'Earliest first' : 'Latest first'}</button>
          {filtersActive && <button type="button" onClick={resetFilters} className="inline-flex items-center gap-1.5 rounded-lg border border-accent-primary/20 bg-accent-soft px-2.5 py-2 text-[10px] font-bold text-accent-primary"><RotateCcw aria-hidden="true" size={12} />Reset</button>}
        </div>
      </div>

      <div className={`grid gap-5 ${selectedEvent ? 'xl:grid-cols-[minmax(0,1fr)_360px]' : ''}`}>
        <div className="min-w-0">
          <div className="mb-3 flex items-center justify-between gap-2 border-b border-border-subtle/60 px-1 pb-2">
            <h2 className="text-xs font-bold uppercase tracking-wider text-text-primary">Capture session reconstruction</h2>
            <span className="shrink-0 font-mono text-[10px] text-text-muted">{visibleEvents.length} observed event{visibleEvents.length === 1 ? '' : 's'}</span>
          </div>
        <ol className="space-y-2" aria-label="Timeline events" data-testid="connected-incident-timeline">
          {visibleEvents.map((event, index) => {
            const exactFlowCount = flowsForEvent(event.id, flows).length;
            const exactSignalCount = signalsForEvent(event.id, signals).length;
            const { Icon: MarkerIcon, style: markerStyle } = markerForEvent(event);
            const isFirst = index === 0;
            const isLast = index === visibleEvents.length - 1;
            const isSelected = selectedEventId === event.id;
            return (
              <li key={event.id} className="grid min-h-[4.5rem] grid-cols-[3.4rem_2.5rem_minmax(0,1fr)] items-stretch gap-2 sm:grid-cols-[5rem_2.5rem_minmax(0,1fr)] sm:gap-3">
                <time className="flex min-w-0 flex-col justify-center text-right font-mono" dateTime={event.timestamp}>
                  <span className="truncate text-[10px] font-bold text-text-primary sm:text-[11px]">{timelineTime(event.timestamp)}</span>
                  <span className="mt-0.5 hidden text-[9px] text-text-muted sm:block">{relativeTimelineTime(event.timestamp, captureStartTime)}</span>
                </time>
                <div className="relative flex w-10 shrink-0 items-center justify-center" aria-hidden="true" data-testid="timeline-marker-column">
                  <span data-testid="timeline-spine-segment" className={`absolute w-0.5 bg-border-subtle dark:bg-slate-700 ${isFirst ? 'top-1/2' : 'top-0'} ${isLast ? 'bottom-1/2' : 'bottom-0'}`} />
                  <span className={`relative z-10 flex h-8 w-8 items-center justify-center rounded-lg border shadow-sm transition-transform ${markerStyle} ${isSelected ? 'scale-110 ring-2 ring-accent-primary ring-offset-2 ring-offset-white dark:ring-offset-slate-950' : ''}`} data-testid="timeline-event-marker">
                    <MarkerIcon size={14} className="stroke-[2.5]" />
                  </span>
                </div>
                <button id={`timeline-event-${event.id}`} type="button" onClick={() => setSelectedEventId(event.id)} aria-pressed={isSelected} className={`min-w-0 w-full rounded-xl border p-4 text-left transition-colors focus:outline-none focus:ring-2 focus:ring-accent-primary ${isSelected ? 'border-accent-primary bg-accent-soft' : 'border-border-subtle bg-surface hover:bg-surface-muted/40'}`}>
                  <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-start"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><Activity aria-hidden="true" size={13} className="text-accent-primary" /><code className="text-[10px] text-text-muted">{event.id}</code><span className="rounded bg-surface-muted px-1.5 py-0.5 text-[9px] font-bold uppercase text-text-secondary">{event.protocol}</span>{event.service && <span className="text-[10px] text-text-muted">{event.service}</span>}</div><p className="mt-2 text-xs font-semibold text-text-primary">{observedEventLabel(event)}</p><p className="mt-1 text-[11px] text-text-secondary">{event.info || 'No decoded description was recorded.'}</p><p className="mt-2 font-mono text-[10px] text-text-muted">{endpoint(event.sourceIp, event.sourcePort)} → {endpoint(event.destinationIp, event.destinationPort)}</p></div><time className="shrink-0 font-mono text-[10px] text-text-muted" dateTime={event.timestamp}>{timestamp(event.timestamp)}</time></div>
                  <p className="mt-3 text-[9px] text-text-muted">Exact relationships: {exactFlowCount} flow{exactFlowCount === 1 ? '' : 's'} · {exactSignalCount} signal{exactSignalCount === 1 ? '' : 's'}</p>
                </button>
              </li>
            );
          })}
          {!visibleEvents.length && <li className="rounded-xl border border-dashed border-border-subtle bg-surface p-10 text-center text-xs text-text-muted">No observed timeline events match these filters.</li>}
        </ol>
        </div>

        {selectedEvent && (
          <aside className="h-fit space-y-4 rounded-xl border border-border-subtle bg-surface p-4 shadow-sm" aria-label={`Timeline event detail ${selectedEvent.id}`}>
            <header className="flex items-start justify-between border-b border-border-subtle pb-3"><div><p className="text-[9px] font-bold uppercase tracking-widest text-accent-primary">Observed event</p><h2 className="font-mono text-xs font-bold text-text-primary">{selectedEvent.id}</h2></div><button type="button" onClick={() => setSelectedEventId(null)} aria-label="Close timeline event details" className="rounded border border-border-subtle p-1.5 text-text-muted"><X aria-hidden="true" size={13} /></button></header>
            <section><h3 className="mb-2 text-[10px] font-bold uppercase tracking-wider text-text-muted">Event description</h3><p className="rounded-lg border border-border-subtle bg-canvas p-3 text-[11px] leading-relaxed text-text-secondary">{observedEventDescription(selectedEvent)}</p></section>
            <section data-testid="timeline-evidence-preview" aria-labelledby="timeline-evidence-preview-title">
              <div className="mb-2 flex items-center gap-1.5"><FileText aria-hidden="true" size={12} className="text-accent-primary" /><h3 id="timeline-evidence-preview-title" className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Evidence preview</h3></div>
              <p className="mb-2 text-[10px] leading-relaxed text-text-muted">Exact normalized metadata recorded for this event. Packet payload content and fields the parser did not provide are not shown.</p>
              <dl className="divide-y divide-border-subtle/60 overflow-hidden rounded-lg border border-border-subtle bg-canvas text-[10px]">
                <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 p-2.5"><dt className="font-semibold text-text-muted">Evidence ID</dt><dd className="break-all font-mono text-text-primary">{selectedEvent.id}</dd></div>
                <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 p-2.5"><dt className="font-semibold text-text-muted">Recorded time</dt><dd className="break-all font-mono text-text-primary">{timestamp(selectedEvent.timestamp)}</dd></div>
                <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 p-2.5"><dt className="font-semibold text-text-muted">Source endpoint</dt><dd className="break-all font-mono text-text-primary">{endpoint(selectedEvent.sourceIp, selectedEvent.sourcePort)}</dd></div>
                <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 p-2.5"><dt className="font-semibold text-text-muted">Destination</dt><dd className="break-all font-mono text-text-primary">{endpoint(selectedEvent.destinationIp, selectedEvent.destinationPort)}</dd></div>
                <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 p-2.5"><dt className="font-semibold text-text-muted">Protocol</dt><dd className="font-mono text-text-primary">{selectedEvent.protocol}</dd></div>
                {selectedEvent.service && <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 p-2.5"><dt className="font-semibold text-text-muted">Recorded service</dt><dd className="font-mono text-text-primary">{selectedEvent.service}</dd></div>}
                <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 p-2.5"><dt className="font-semibold text-text-muted">Record length</dt><dd className="font-mono text-text-primary">{selectedEvent.length} bytes</dd></div>
                {selectedEvent.capturedLength !== undefined && <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 p-2.5"><dt className="font-semibold text-text-muted">Captured length</dt><dd className="font-mono text-text-primary">{selectedEvent.capturedLength} bytes</dd></div>}
                {selectedEvent.originalLength !== undefined && <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 p-2.5"><dt className="font-semibold text-text-muted">Original length</dt><dd className="font-mono text-text-primary">{selectedEvent.originalLength} bytes</dd></div>}
                {selectedEvent.sourceType && <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 p-2.5"><dt className="font-semibold text-text-muted">Parser source</dt><dd className="font-mono text-text-primary">{selectedEvent.sourceType}</dd></div>}
                <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 p-2.5"><dt className="font-semibold text-text-muted">Decoder detail</dt><dd className="break-words font-mono leading-relaxed text-text-primary">{selectedEvent.info || 'Not provided'}</dd></div>
              </dl>
            </section>
            <section data-testid="timeline-related-observations">
              <h3 className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Related observations ({relatedSignals.length})</h3>
              <p className="mb-2 mt-1 text-[10px] leading-relaxed text-text-muted">Only observations that explicitly reference this event ID are shown.</p>
              {relatedSignals.length ? <ul className="space-y-2">{relatedSignals.map(signal => <li key={signal.id} className="rounded-lg border border-border-subtle p-2.5 text-[10px]"><div className="flex items-start justify-between gap-2"><span className="font-semibold text-text-primary">{signal.title}</span><span className="shrink-0 rounded bg-surface-muted px-1.5 py-0.5 text-[8px] font-bold uppercase text-text-secondary">{signal.severity}</span></div><p className="mt-1 text-text-muted">{signal.category}</p><code className="mt-1 block break-all text-text-secondary">{signal.id}</code></li>)}</ul> : <p className="text-[11px] text-text-muted">No observation explicitly records this event ID.</p>}
            </section>
            <section><h3 className="mb-2 text-[10px] font-bold uppercase tracking-wider text-text-muted">Exact related flows ({relatedFlows.length})</h3>{relatedFlows.length ? <ul className="space-y-2">{relatedFlows.map(flow => <li key={flow.id} className="rounded-lg border border-border-subtle p-2 text-[10px]"><code>{flow.id}</code><p className="mt-1 font-mono text-text-muted">{endpoint(flow.sourceIp, flow.sourcePort)} → {endpoint(flow.destinationIp, flow.destinationPort)}</p></li>)}</ul> : <p className="text-[11px] text-text-muted">No flow explicitly records this event ID.</p>}</section>
            <button type="button" disabled={!relatedFlows.length || !onNavigateToFlows} onClick={() => onNavigateToFlows?.(relatedFlows)} className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg bg-accent-primary py-2 text-xs font-bold text-white disabled:cursor-not-allowed disabled:bg-surface-muted disabled:text-text-muted">{relatedFlows.length ? 'Open exact related flow' : 'Related flow unavailable'}<ArrowRight aria-hidden="true" size={12} /></button>
          </aside>
        )}
      </div>
    </section>
  );
}
