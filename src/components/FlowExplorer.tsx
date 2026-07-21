import React, { useMemo, useState } from 'react';
import { Clipboard, Check, Layers, Search, X } from 'lucide-react';
import type { FlowSummary, PacketEvent, SuspiciousSignal } from '../types';
import { eventsForFlow, signalsForFlow } from '../lib/evidenceRelationships';

interface FlowExplorerProps {
  flows: FlowSummary[];
  events: PacketEvent[];
  signals: SuspiciousSignal[];
  onSelectFlow: (flow: FlowSummary) => void;
  selectedFlow: FlowSummary | null;
  onCloseDrawer: () => void;
  evidenceName?: string;
}

function endpoint(ip: string, port: number): string {
  const address = ip.includes(':') ? `[${ip}]` : ip;
  return `${address}:${port > 0 ? port : 'unknown'}`;
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString();
}

const riskPillClasses: Record<FlowSummary['riskLevel'], string> = {
  info: 'border-slate-500/25 bg-slate-600 text-white dark:bg-slate-500',
  low: 'border-emerald-500/25 bg-emerald-600 text-white dark:bg-emerald-500',
  medium: 'border-amber-400/30 bg-amber-500 text-white',
  high: 'border-red-500/25 bg-status-danger text-white',
};

function RiskPill({ level }: { level: FlowSummary['riskLevel'] }) {
  return (
    <span
      data-risk-pill={level}
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-wider shadow-xs ${riskPillClasses[level]}`}
    >
      {level}
    </span>
  );
}

export default function FlowExplorer({
  flows,
  events,
  signals,
  onSelectFlow,
  selectedFlow,
  onCloseDrawer,
  evidenceName,
}: FlowExplorerProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [directionFilter, setDirectionFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState<'bytes' | 'packets' | 'duration' | 'time'>('bytes');
  const [copied, setCopied] = useState(false);

  const protocolOptions = useMemo(() => Array.from(new Set(flows.map(flow => flow.protocol.toUpperCase()))).sort(), [flows]);
  const riskOptions = useMemo(() => Array.from(new Set(flows.map(flow => flow.riskLevel.toUpperCase()))).sort(), [flows]);
  const directionOptions = useMemo(() => Array.from(new Set(flows.map(flow => flow.direction.toUpperCase()))).sort(), [flows]);
  const filteredFlows = useMemo(() => flows
    .filter(flow => {
      const term = searchTerm.trim().toLowerCase();
      const searchable = `${flow.sourceIp} ${flow.sourcePort || ''} ${flow.destinationIp} ${flow.destinationPort || ''} ${flow.protocol} ${flow.service || ''}`.toLowerCase();
      return (!term || searchable.includes(term))
        && (protocolFilter === 'ALL' || flow.protocol.toUpperCase() === protocolFilter)
        && (riskFilter === 'ALL' || flow.riskLevel.toUpperCase() === riskFilter)
        && (directionFilter === 'ALL' || flow.direction.toUpperCase() === directionFilter);
    })
    .sort((left, right) => {
      if (sortBy === 'bytes') return right.byteCount - left.byteCount;
      if (sortBy === 'packets') return right.packetCount - left.packetCount;
      if (sortBy === 'duration') return right.duration - left.duration;
      return right.firstSeen.localeCompare(left.firstSeen);
    }), [flows, searchTerm, protocolFilter, riskFilter, directionFilter, sortBy]);

  const relatedEvents = selectedFlow ? eventsForFlow(selectedFlow, events) : [];
  const linkedSignals = selectedFlow ? signalsForFlow(selectedFlow.id, signals) : [];
  const linkedFlowIds = new Set(signals.flatMap(signal => signal.relatedFlowIds || []));

  const copySummary = async () => {
    if (!selectedFlow) return;
    await navigator.clipboard.writeText(`Flow ${selectedFlow.id}: ${endpoint(selectedFlow.sourceIp, selectedFlow.sourcePort)} -> ${endpoint(selectedFlow.destinationIp, selectedFlow.destinationPort)} (${selectedFlow.protocol})`);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  const selectFromKeyboard = (event: React.KeyboardEvent<HTMLTableRowElement>, flow: FlowSummary) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    onSelectFlow(flow);
  };

  return (
    <section className="space-y-5" aria-labelledby="flow-explorer-title">
      <header className="border-b border-border-subtle pb-4">
        <p className="text-[10px] font-bold uppercase tracking-widest text-accent-primary">Exact flow records</p>
        <h1 id="flow-explorer-title" className="text-xl font-bold text-text-primary">Flow explorer</h1>
        <p className="mt-1 text-xs text-text-muted">Related events and signals appear only when parser-established IDs connect them.</p>
        <dl className="mt-3 flex flex-wrap gap-x-5 gap-y-2 text-[11px]">
          <div><dt className="inline text-text-muted">Active evidence: </dt><dd className="inline font-mono text-text-primary">{evidenceName || 'No evidence name recorded'}</dd></div>
          <div><dt className="inline text-text-muted">Flows: </dt><dd className="inline font-mono text-text-primary">{flows.length}</dd></div>
          <div><dt className="inline text-text-muted">Exactly linked: </dt><dd className="inline font-mono text-text-primary">{flows.filter(flow => linkedFlowIds.has(flow.id)).length}</dd></div>
        </dl>
      </header>

      <div className="rounded-xl border border-border-subtle bg-surface p-3 shadow-sm">
        <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_repeat(4,auto)]">
          <label className="relative"><span className="sr-only">Search flows</span><Search aria-hidden="true" size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" /><input value={searchTerm} onChange={event => setSearchTerm(event.target.value)} className="w-full rounded-lg border border-border-subtle bg-canvas py-2 pl-9 pr-3 text-xs" placeholder="Filter by observed endpoint, port, protocol, or service" /></label>
          <label className="text-[10px] text-text-muted">Protocol<select aria-label="Filter flows by protocol" value={protocolFilter} onChange={event => setProtocolFilter(event.target.value)} className="ml-2 rounded border border-border-subtle bg-canvas px-2 py-1.5 text-xs text-text-primary"><option>ALL</option>{protocolOptions.map(value => <option key={value}>{value}</option>)}</select></label>
          <label className="text-[10px] text-text-muted">Risk<select aria-label="Filter flows by risk" value={riskFilter} onChange={event => setRiskFilter(event.target.value)} className="ml-2 rounded border border-border-subtle bg-canvas px-2 py-1.5 text-xs text-text-primary"><option>ALL</option>{riskOptions.map(value => <option key={value}>{value}</option>)}</select></label>
          <label className="text-[10px] text-text-muted">Direction<select aria-label="Filter flows by direction" value={directionFilter} onChange={event => setDirectionFilter(event.target.value)} className="ml-2 rounded border border-border-subtle bg-canvas px-2 py-1.5 text-xs text-text-primary"><option>ALL</option>{directionOptions.map(value => <option key={value}>{value}</option>)}</select></label>
          <label className="text-[10px] text-text-muted">Sort<select aria-label="Sort flows" value={sortBy} onChange={event => setSortBy(event.target.value as typeof sortBy)} className="ml-2 rounded border border-border-subtle bg-canvas px-2 py-1.5 text-xs text-text-primary"><option value="bytes">Bytes</option><option value="packets">Packets</option><option value="duration">Duration</option><option value="time">First seen</option></select></label>
        </div>
      </div>

      <div id="flow-explorer-workspace" className={`grid gap-5 ${selectedFlow ? 'xl:grid-cols-[minmax(0,1fr)_360px]' : ''}`}>
        <div className="overflow-x-auto rounded-xl border border-border-subtle bg-surface shadow-sm">
          <table id="flows-table" className="w-full min-w-[850px] text-left text-xs">
            <thead className="bg-surface-muted text-[10px] uppercase tracking-wider text-text-muted"><tr><th className="p-3">First seen</th><th className="p-3">Source</th><th className="p-3">Destination</th><th className="p-3">Protocol</th><th className="p-3 text-right">Packets</th><th className="p-3 text-right">Bytes</th><th className="p-3 text-right">Duration</th><th className="p-3">Risk</th></tr></thead>
            <tbody className="divide-y divide-border-subtle">
              {filteredFlows.map(flow => (
                <tr key={flow.id} id={`flow-row-${flow.id}`} role="button" tabIndex={0} aria-label={`Inspect flow ${flow.id}`} aria-pressed={selectedFlow?.id === flow.id} onClick={() => onSelectFlow(flow)} onKeyDown={event => selectFromKeyboard(event, flow)} className={`cursor-pointer focus:outline-none focus:ring-2 focus:ring-inset focus:ring-accent-primary ${selectedFlow?.id === flow.id ? 'bg-accent-soft' : 'hover:bg-surface-muted/50'}`}>
                  <td className="p-3 font-mono text-[10px] text-text-muted">{formatTime(flow.firstSeen)}</td><td className="p-3 font-mono">{endpoint(flow.sourceIp, flow.sourcePort)}</td><td className="p-3 font-mono">{endpoint(flow.destinationIp, flow.destinationPort)}</td><td className="p-3">{flow.protocol}{flow.service ? ` · ${flow.service}` : ''}</td><td className="p-3 text-right font-mono">{flow.packetCount}</td><td className="p-3 text-right font-mono">{flow.byteCount}</td><td className="p-3 text-right font-mono">{flow.duration.toFixed(3)}s</td><td className="p-3"><RiskPill level={flow.riskLevel} /></td>
                </tr>
              ))}
              {!filteredFlows.length && <tr><td colSpan={8} className="p-10 text-center text-text-muted">No observed flows match these filters.</td></tr>}
            </tbody>
          </table>
        </div>

        {selectedFlow && (
          <aside className="h-fit space-y-4 rounded-xl border border-border-subtle bg-surface p-4 shadow-sm" aria-label={`Flow detail ${selectedFlow.id}`}>
            <header className="flex items-start justify-between gap-3 border-b border-border-subtle pb-3"><div><p className="text-[9px] font-bold uppercase tracking-widest text-accent-primary">Observed flow</p><h2 className="font-mono text-xs font-bold text-text-primary">{selectedFlow.id}</h2></div><button type="button" onClick={onCloseDrawer} aria-label="Close flow details" className="rounded border border-border-subtle p-1.5 text-text-muted"><X aria-hidden="true" size={13} /></button></header>
            <dl className="grid gap-2 text-[11px]">
              <div><dt className="text-text-muted">Source</dt><dd className="font-mono text-text-primary">{endpoint(selectedFlow.sourceIp, selectedFlow.sourcePort)}</dd></div>
              <div><dt className="text-text-muted">Destination</dt><dd className="font-mono text-text-primary">{endpoint(selectedFlow.destinationIp, selectedFlow.destinationPort)}</dd></div>
              <div className="grid grid-cols-2 gap-2"><div><dt className="text-text-muted">Protocol</dt><dd>{selectedFlow.protocol}</dd></div><div><dt className="text-text-muted">Service</dt><dd>{selectedFlow.service || 'Not recorded'}</dd></div></div>
              <div className="grid grid-cols-2 gap-2"><div><dt className="text-text-muted">Packets</dt><dd>{selectedFlow.packetCount}</dd></div><div><dt className="text-text-muted">Bytes</dt><dd>{selectedFlow.byteCount}</dd></div></div>
              <div className="grid grid-cols-2 gap-2"><div><dt className="text-text-muted">Direction</dt><dd>{selectedFlow.direction}</dd></div><div><dt className="text-text-muted">Risk label</dt><dd className="mt-0.5"><RiskPill level={selectedFlow.riskLevel} /></dd></div></div>
              <div><dt className="text-text-muted">Observed interval</dt><dd className="font-mono text-[10px]">{formatTime(selectedFlow.firstSeen)} — {formatTime(selectedFlow.lastSeen)}</dd></div>
            </dl>

            <section aria-labelledby="flow-events-title"><h3 id="flow-events-title" className="mb-2 text-[10px] font-bold uppercase tracking-wider text-text-muted">Exactly related events ({relatedEvents.length})</h3>{relatedEvents.length ? <ul className="max-h-48 space-y-2 overflow-y-auto">{relatedEvents.map(event => <li key={event.id} className="rounded-lg border border-border-subtle bg-canvas p-2 text-[10px]"><code>{event.id}</code><p className="mt-1 text-text-secondary">{event.info || `${event.protocol} record`}</p><p className="mt-1 font-mono text-text-muted">{event.length} bytes · {formatTime(event.timestamp)}</p></li>)}</ul> : <p className="text-[11px] text-text-muted">No loaded event matches this flow’s recorded related event IDs.</p>}</section>

            <section aria-labelledby="flow-signals-title"><h3 id="flow-signals-title" className="mb-2 text-[10px] font-bold uppercase tracking-wider text-text-muted">Exactly linked signals ({linkedSignals.length})</h3>{linkedSignals.length ? <ul className="space-y-2">{linkedSignals.map(signal => <li key={signal.id} className="rounded-lg border border-border-subtle p-2 text-[10px]"><div className="flex items-center justify-between gap-2"><span className="font-semibold text-text-primary">{signal.title}</span><span className="uppercase text-text-muted">{signal.severity}</span></div><code className="mt-1 block">{signal.id}</code></li>)}</ul> : <p className="text-[11px] text-text-muted">No signal explicitly references this flow ID.</p>}</section>

            <p className="flex gap-2 rounded-lg bg-surface-muted p-3 text-[10px] leading-relaxed text-text-muted"><Layers aria-hidden="true" size={13} className="shrink-0" />No connection state, host identity, encryption state, or outcome is inferred when it is absent from normalized evidence.</p>
            <button type="button" onClick={copySummary} className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-border-subtle bg-surface-muted py-2 text-xs font-semibold text-text-primary">{copied ? <Check aria-hidden="true" size={12} /> : <Clipboard aria-hidden="true" size={12} />}{copied ? 'Copied' : 'Copy observed flow summary'}</button>
          </aside>
        )}
      </div>
    </section>
  );
}
