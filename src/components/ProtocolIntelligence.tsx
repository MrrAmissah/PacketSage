import React, { useMemo, useState } from 'react';
import { Activity, Database, Globe, Lock, Search, ShieldCheck } from 'lucide-react';
import type { DnsRecord, HttpRecord, ProtocolStat, TlsRecord } from '../types';
import { buildProtocolFlags, buildProtocolInventory } from '../lib/protocolPresentation';

interface ProtocolIntelligenceProps {
  dns: DnsRecord[];
  http: HttpRecord[];
  tls: TlsRecord[];
  stats: ProtocolStat[];
}

type Tab = 'overview' | 'dns' | 'http' | 'tls' | 'flags';

const PROTOCOL_COLORS = ['#0062f1', '#2f95ea', '#10b981', '#f59e0b', '#a855f7', '#64748b'];

function recorded(value: string | number | undefined): string {
  return value === undefined || value === '' ? 'Not recorded' : String(value);
}

function EmptyState({ children }: { children: React.ReactNode }) {
  return <p className="rounded-xl border border-dashed border-border-subtle bg-surface p-8 text-center text-xs text-text-muted">{children}</p>;
}

export default function ProtocolIntelligence({ dns, http, tls, stats }: ProtocolIntelligenceProps) {
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [search, setSearch] = useState('');
  const inventory = useMemo(() => buildProtocolInventory(stats, dns, http, tls), [stats, dns, http, tls]);
  const flags = useMemo(() => buildProtocolFlags(dns, http, tls), [dns, http, tls]);
  const observedStats = useMemo(() => stats.filter(stat => stat.count > 0), [stats]);
  const query = search.trim().toLowerCase();
  const filteredDns = dns.filter(record => `${record.clientIp} ${record.query} ${record.queryType} ${record.response} ${record.rcode}`.toLowerCase().includes(query));
  const filteredHttp = http.filter(record => `${record.clientIp} ${record.host} ${record.method} ${record.uri} ${record.statusCode}`.toLowerCase().includes(query));
  const filteredTls = tls.filter(record => `${record.clientIp} ${record.serverIp} ${record.sni} ${record.version || ''} ${record.ja3 || ''}`.toLowerCase().includes(query));
  const maxRecords = Math.max(1, ...inventory.map(item => item.recordCount));
  const cleartextCount = http.filter(record => record.cleartext).length;

  const donutSegments = useMemo(() => {
    const circumference = 314.16;
    let offset = 0;
    return observedStats.map((stat, index) => {
      const length = (stat.percentage / 100) * circumference;
      const segment = { ...stat, color: PROTOCOL_COLORS[index % PROTOCOL_COLORS.length], length, offset: circumference - offset };
      offset += length;
      return segment;
    });
  }, [observedStats]);

  const selectTab = (tab: Tab) => {
    setActiveTab(tab);
    setSearch('');
  };

  return (
    <section className="space-y-5" aria-labelledby="protocol-intelligence-title">
      <header className="border-b border-border-subtle pb-4">
        <p className="text-[10px] font-bold uppercase tracking-widest text-accent-primary">Normalized evidence</p>
        <h1 id="protocol-intelligence-title" className="text-xl font-bold text-text-primary">Protocol intelligence</h1>
        <p className="mt-1 text-xs text-text-muted">Inspect protocol statistics and decoded metadata from the current evidence.</p>
      </header>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6" aria-label="Protocol evidence summary">
        {[
          { label: 'Protocols', value: inventory.length, icon: Database, tone: 'text-accent-primary' },
          { label: 'DNS queries', value: dns.length, icon: Globe, tone: 'text-accent-primary' },
          { label: 'HTTP traces', value: http.length, icon: Activity, tone: cleartextCount ? 'text-status-warning' : 'text-accent-primary' },
          { label: 'TLS handshakes', value: tls.length, icon: Lock, tone: 'text-status-success' },
          { label: 'Cleartext', value: cleartextCount, icon: Lock, tone: cleartextCount ? 'text-status-warning' : 'text-text-muted' },
          { label: 'Recorded flags', value: flags.length, icon: ShieldCheck, tone: flags.length ? 'text-status-danger' : 'text-text-muted' },
        ].map(metric => {
          const Icon = metric.icon;
          return <article key={metric.label} className="flex h-[76px] min-w-0 flex-col justify-between rounded-xl border border-border-subtle bg-surface p-3 shadow-sm"><div className="flex items-center justify-between gap-2"><span className="truncate text-[10px] font-bold uppercase tracking-wider text-text-muted">{metric.label}</span><Icon aria-hidden="true" size={13} className={metric.tone} /></div><span className={`font-mono text-lg font-bold ${metric.tone}`}>{metric.value}</span></article>;
        })}
      </div>

      <nav aria-label="Protocol intelligence sections" className="flex max-w-full gap-1 overflow-x-auto rounded-xl border border-border-subtle bg-surface-muted p-1">
        {([
          ['overview', 'Overview'], ['dns', `DNS activity (${dns.length})`], ['http', `HTTP activity (${http.length})`],
          ['tls', `TLS handshakes (${tls.length})`], ['flags', `Recorded flags (${flags.length})`],
        ] as const).map(([id, label]) => (
          <button key={id} type="button" onClick={() => selectTab(id)} aria-pressed={activeTab === id} className={`whitespace-nowrap rounded-lg px-3 py-2 text-[10px] font-bold uppercase tracking-wider ${activeTab === id ? 'border border-border-subtle bg-surface text-accent-primary shadow-sm' : 'text-text-muted hover:text-text-primary'}`}>
            {label}
          </button>
        ))}
      </nav>

      {activeTab !== 'overview' && activeTab !== 'flags' && (
        <label className="relative block max-w-md">
          <span className="sr-only">Search {activeTab.toUpperCase()} records</span>
          <Search aria-hidden="true" size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input value={search} onChange={event => setSearch(event.target.value)} className="w-full rounded-lg border border-border-subtle bg-surface py-2 pl-9 pr-3 text-xs text-text-primary" placeholder={`Search ${activeTab.toUpperCase()} records`} />
        </label>
      )}

      {activeTab === 'overview' && (
        inventory.length ? (
          <div className="space-y-5" data-testid="protocol-inventory">
            <div className="grid gap-5 lg:grid-cols-2">
              <article className="rounded-xl border border-border-subtle bg-surface p-5 shadow-sm">
                <h2 className="text-xs font-bold uppercase tracking-wider text-text-primary">Protocol distribution</h2>
                {donutSegments.length ? <div className="mt-4 grid gap-4 sm:grid-cols-[150px_1fr] sm:items-center">
                  <div className="relative mx-auto h-32 w-32">
                    <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90" aria-label={`${donutSegments.length} observed protocols`}>
                      <circle cx="60" cy="60" r="50" fill="none" stroke="currentColor" strokeWidth="10" className="text-surface-muted" />
                      {donutSegments.map(segment => <circle key={segment.protocol} cx="60" cy="60" r="50" fill="none" stroke={segment.color} strokeWidth="10" strokeDasharray={`${segment.length} 314.16`} strokeDashoffset={segment.offset} />)}
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center"><span className="text-[9px] uppercase text-text-muted">Total</span><strong className="font-mono text-sm text-text-primary">100%</strong></div>
                  </div>
                  <ul className="space-y-2">{donutSegments.map(segment => <li key={segment.protocol} className="flex items-center justify-between gap-3 text-[11px]"><span className="flex items-center gap-2 font-mono font-bold text-text-primary"><span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: segment.color }} />{segment.protocol}</span><span className="rounded border border-accent-primary/10 bg-accent-soft/40 px-1.5 py-0.5 font-mono text-[9px] font-bold text-accent-primary">{segment.percentage}%</span></li>)}</ul>
                </div> : <p className="mt-4 rounded-lg bg-surface-muted p-4 text-xs text-text-muted">No normalized protocol statistics were produced.</p>}
              </article>

              <article className="rounded-xl border border-border-subtle bg-surface p-5 shadow-sm">
                <h2 className="text-xs font-bold uppercase tracking-wider text-text-primary">Observed records by protocol</h2>
                <div className="mt-5 space-y-3">{inventory.map((item, index) => <div key={item.id} className="grid grid-cols-[80px_1fr_48px] items-center gap-3 text-[11px]"><span className="truncate font-mono font-bold text-text-primary">{item.label}</span><div className="h-2 overflow-hidden rounded-full bg-surface-muted"><span className="block h-full rounded-full" style={{ width: `${(item.recordCount / maxRecords) * 100}%`, backgroundColor: PROTOCOL_COLORS[index % PROTOCOL_COLORS.length] }} /></div><span className="text-right font-mono text-text-muted">{item.recordCount}</span></div>)}</div>
              </article>
            </div>

            <article className="overflow-hidden rounded-xl border border-border-subtle bg-surface shadow-sm">
              <div className="border-b border-border-subtle px-4 py-3"><h2 className="text-xs font-bold uppercase tracking-wider text-text-primary">Protocol details</h2></div>
              <div className="overflow-x-auto"><table className="w-full min-w-[720px] text-left text-xs"><thead className="bg-surface-muted text-[10px] uppercase tracking-wider text-text-muted"><tr><th className="p-3">Protocol</th><th className="p-3">Observed records</th><th className="p-3">Packet share</th><th className="p-3">Packet count</th><th className="p-3">Observed bytes</th><th className="p-3">Decoded meaning</th></tr></thead><tbody className="divide-y divide-border-subtle">{inventory.map(item => <tr key={item.id}><td className="p-3 font-mono font-bold text-text-primary">{item.label}</td><td className="p-3 font-mono">{item.recordCount}</td><td className="p-3 font-mono">{item.percentage === null ? 'Not recorded' : `${item.percentage}%`}</td><td className="p-3 font-mono">{item.packetCount ?? 'Not recorded'}</td><td className="p-3 font-mono">{item.byteCount ?? 'Not recorded'}</td><td className="p-3 text-text-muted">{item.explanation}</td></tr>)}</tbody></table></div>
            </article>
          </div>
        ) : <EmptyState>No protocol statistics or decoded protocol records were present in this evidence.</EmptyState>
      )}

      {activeTab === 'dns' && (
        filteredDns.length ? <div className="overflow-x-auto rounded-xl border border-border-subtle bg-surface shadow-sm"><table className="w-full min-w-[700px] text-left text-xs"><thead className="bg-surface-muted text-text-muted"><tr><th className="p-3">Timestamp</th><th className="p-3">Client</th><th className="p-3">Query</th><th className="p-3">Type</th><th className="p-3">Response</th><th className="p-3">RCODE</th></tr></thead><tbody className="divide-y divide-border-subtle">{filteredDns.map((record, index) => <tr key={record.id || `${record.timestamp}:${index}`}><td className="p-3 font-mono">{recorded(record.timestamp)}</td><td className="p-3 font-mono">{recorded(record.clientIp)}</td><td className="p-3 font-mono">{recorded(record.query)}</td><td className="p-3">{recorded(record.queryType)}</td><td className="p-3 font-mono">{recorded(record.response)}</td><td className="p-3">{recorded(record.rcode)}</td></tr>)}</tbody></table></div> : <EmptyState>{dns.length ? 'No DNS records match the current search.' : 'No DNS records were decoded from this evidence.'}</EmptyState>
      )}

      {activeTab === 'http' && (
        filteredHttp.length ? <div className="overflow-x-auto rounded-xl border border-border-subtle bg-surface shadow-sm"><table className="w-full min-w-[760px] text-left text-xs"><thead className="bg-surface-muted text-text-muted"><tr><th className="p-3">Timestamp</th><th className="p-3">Client</th><th className="p-3">Host</th><th className="p-3">Method</th><th className="p-3">URI</th><th className="p-3">Status</th></tr></thead><tbody className="divide-y divide-border-subtle">{filteredHttp.map((record, index) => <tr key={record.id || `${record.timestamp}:${index}`}><td className="p-3 font-mono">{recorded(record.timestamp)}</td><td className="p-3 font-mono">{recorded(record.clientIp)}</td><td className="p-3 font-mono">{recorded(record.host)}</td><td className="p-3">{recorded(record.method)}</td><td className="p-3 font-mono">{recorded(record.uri)}</td><td className="p-3">{recorded(record.statusCode)}</td></tr>)}</tbody></table></div> : <EmptyState>{http.length ? 'No HTTP records match the current search.' : 'No HTTP records were decoded from this evidence.'}</EmptyState>
      )}

      {activeTab === 'tls' && (
        filteredTls.length ? <div className="overflow-x-auto rounded-xl border border-border-subtle bg-surface shadow-sm"><table className="w-full min-w-[760px] text-left text-xs"><thead className="bg-surface-muted text-text-muted"><tr><th className="p-3">Timestamp</th><th className="p-3">Client</th><th className="p-3">Server</th><th className="p-3">SNI</th><th className="p-3">Version</th><th className="p-3">JA3</th></tr></thead><tbody className="divide-y divide-border-subtle">{filteredTls.map((record, index) => <tr key={record.id || `${record.timestamp}:${index}`}><td className="p-3 font-mono">{recorded(record.timestamp)}</td><td className="p-3 font-mono">{recorded(record.clientIp)}</td><td className="p-3 font-mono">{recorded(record.serverIp)}</td><td className="p-3 font-mono">{recorded(record.sni)}</td><td className="p-3">{recorded(record.version)}</td><td className="p-3 font-mono">{recorded(record.ja3)}</td></tr>)}</tbody></table></div> : <EmptyState>{tls.length ? 'No TLS records match the current search.' : 'No TLS records were decoded from this evidence.'}</EmptyState>
      )}

      {activeTab === 'flags' && (
        flags.length ? <ul className="grid gap-3 sm:grid-cols-2">{flags.map(flag => <li key={flag.id} className="rounded-xl border border-border-subtle bg-surface p-4 shadow-sm"><div className="flex items-center justify-between gap-3"><span className="font-mono text-[10px] font-bold text-accent-primary">{flag.type}</span><ShieldCheck aria-hidden="true" size={14} className="text-status-warning" /></div><p className="mt-2 text-xs font-semibold text-text-primary">{flag.label}</p><p className="mt-1 text-[11px] text-text-muted">{flag.detail}</p></li>)}</ul> : <EmptyState>No decoded DNS response or source risk labels require display.</EmptyState>
      )}

      <p className="flex items-center gap-2 text-[10px] text-text-muted"><Globe aria-hidden="true" size={12} /> Protocol records are shown as decoded metadata. <Lock aria-hidden="true" size={12} /> No payload interpretation is added here.</p>
    </section>
  );
}
