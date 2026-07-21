import React, { useMemo, useState } from 'react';
import { Activity, Globe, Lock, Search, ShieldCheck } from 'lucide-react';
import type { DnsRecord, HttpRecord, ProtocolStat, TlsRecord } from '../types';
import { buildProtocolFlags, buildProtocolInventory } from '../lib/protocolPresentation';

interface ProtocolIntelligenceProps {
  dns: DnsRecord[];
  http: HttpRecord[];
  tls: TlsRecord[];
  stats: ProtocolStat[];
}

type Tab = 'overview' | 'dns' | 'http' | 'tls' | 'flags';

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
  const query = search.trim().toLowerCase();
  const filteredDns = dns.filter(record => `${record.clientIp} ${record.query} ${record.queryType} ${record.response} ${record.rcode}`.toLowerCase().includes(query));
  const filteredHttp = http.filter(record => `${record.clientIp} ${record.host} ${record.method} ${record.uri} ${record.statusCode}`.toLowerCase().includes(query));
  const filteredTls = tls.filter(record => `${record.clientIp} ${record.serverIp} ${record.sni} ${record.version || ''} ${record.ja3 || ''}`.toLowerCase().includes(query));

  const selectTab = (tab: Tab) => {
    setActiveTab(tab);
    setSearch('');
  };

  return (
    <section className="space-y-5" aria-labelledby="protocol-intelligence-title">
      <header className="border-b border-border-subtle pb-4">
        <p className="text-[10px] font-bold uppercase tracking-widest text-accent-primary">Normalized evidence</p>
        <h1 id="protocol-intelligence-title" className="text-xl font-bold text-text-primary">Protocol intelligence</h1>
        <p className="mt-1 text-xs text-text-muted">Only protocol statistics and decoded metadata present in the loaded evidence are shown.</p>
      </header>

      <nav aria-label="Protocol intelligence sections" className="flex flex-wrap gap-2">
        {([
          ['overview', 'Overview'], ['dns', `DNS (${dns.length})`], ['http', `HTTP (${http.length})`],
          ['tls', `TLS (${tls.length})`], ['flags', `Recorded flags (${flags.length})`],
        ] as const).map(([id, label]) => (
          <button key={id} type="button" onClick={() => selectTab(id)} aria-pressed={activeTab === id} className={`rounded-lg border px-3 py-2 text-xs font-semibold ${activeTab === id ? 'border-accent-primary bg-accent-soft text-accent-primary' : 'border-border-subtle bg-surface text-text-secondary'}`}>
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
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3" data-testid="protocol-inventory">
            {inventory.map(item => (
              <article key={item.id} className="rounded-xl border border-border-subtle bg-surface p-4">
                <div className="flex items-center justify-between gap-3">
                  <h2 className="font-mono text-sm font-bold text-text-primary">{item.label}</h2>
                  <Activity aria-hidden="true" size={15} className="text-accent-primary" />
                </div>
                <dl className="mt-3 grid grid-cols-2 gap-2 text-[11px]">
                  <div><dt className="text-text-muted">Observed records</dt><dd className="font-mono font-semibold text-text-primary">{item.recordCount}</dd></div>
                  <div><dt className="text-text-muted">Packet share</dt><dd className="font-mono font-semibold text-text-primary">{item.percentage === null ? 'Not recorded' : `${item.percentage}%`}</dd></div>
                  <div><dt className="text-text-muted">Packet count</dt><dd className="font-mono font-semibold text-text-primary">{item.packetCount ?? 'Not recorded'}</dd></div>
                  <div><dt className="text-text-muted">Observed bytes</dt><dd className="font-mono font-semibold text-text-primary">{item.byteCount ?? 'Not recorded'}</dd></div>
                </dl>
                <p className="mt-3 text-[11px] leading-relaxed text-text-muted">{item.explanation}</p>
              </article>
            ))}
          </div>
        ) : <EmptyState>No protocol statistics or decoded protocol records were present in this evidence.</EmptyState>
      )}

      {activeTab === 'dns' && (
        filteredDns.length ? <div className="overflow-x-auto rounded-xl border border-border-subtle bg-surface"><table className="w-full min-w-[700px] text-left text-xs"><thead className="bg-surface-muted text-text-muted"><tr><th className="p-3">Timestamp</th><th className="p-3">Client</th><th className="p-3">Query</th><th className="p-3">Type</th><th className="p-3">Response</th><th className="p-3">RCODE</th></tr></thead><tbody className="divide-y divide-border-subtle">{filteredDns.map((record, index) => <tr key={record.id || `${record.timestamp}:${index}`}><td className="p-3 font-mono">{recorded(record.timestamp)}</td><td className="p-3 font-mono">{recorded(record.clientIp)}</td><td className="p-3 font-mono">{recorded(record.query)}</td><td className="p-3">{recorded(record.queryType)}</td><td className="p-3 font-mono">{recorded(record.response)}</td><td className="p-3">{recorded(record.rcode)}</td></tr>)}</tbody></table></div> : <EmptyState>{dns.length ? 'No DNS records match the current search.' : 'No DNS records were decoded from this evidence.'}</EmptyState>
      )}

      {activeTab === 'http' && (
        filteredHttp.length ? <div className="overflow-x-auto rounded-xl border border-border-subtle bg-surface"><table className="w-full min-w-[760px] text-left text-xs"><thead className="bg-surface-muted text-text-muted"><tr><th className="p-3">Timestamp</th><th className="p-3">Client</th><th className="p-3">Host</th><th className="p-3">Method</th><th className="p-3">URI</th><th className="p-3">Status</th></tr></thead><tbody className="divide-y divide-border-subtle">{filteredHttp.map((record, index) => <tr key={record.id || `${record.timestamp}:${index}`}><td className="p-3 font-mono">{recorded(record.timestamp)}</td><td className="p-3 font-mono">{recorded(record.clientIp)}</td><td className="p-3 font-mono">{recorded(record.host)}</td><td className="p-3">{recorded(record.method)}</td><td className="p-3 font-mono">{recorded(record.uri)}</td><td className="p-3">{recorded(record.statusCode)}</td></tr>)}</tbody></table></div> : <EmptyState>{http.length ? 'No HTTP records match the current search.' : 'No HTTP records were decoded from this evidence.'}</EmptyState>
      )}

      {activeTab === 'tls' && (
        filteredTls.length ? <div className="overflow-x-auto rounded-xl border border-border-subtle bg-surface"><table className="w-full min-w-[760px] text-left text-xs"><thead className="bg-surface-muted text-text-muted"><tr><th className="p-3">Timestamp</th><th className="p-3">Client</th><th className="p-3">Server</th><th className="p-3">SNI</th><th className="p-3">Version</th><th className="p-3">JA3</th></tr></thead><tbody className="divide-y divide-border-subtle">{filteredTls.map((record, index) => <tr key={record.id || `${record.timestamp}:${index}`}><td className="p-3 font-mono">{recorded(record.timestamp)}</td><td className="p-3 font-mono">{recorded(record.clientIp)}</td><td className="p-3 font-mono">{recorded(record.serverIp)}</td><td className="p-3 font-mono">{recorded(record.sni)}</td><td className="p-3">{recorded(record.version)}</td><td className="max-w-[260px] truncate p-3 font-mono" title={record.ja3}>{recorded(record.ja3)}</td></tr>)}</tbody></table></div> : <EmptyState>{tls.length ? 'No TLS records match the current search.' : 'No TLS records were decoded from this evidence.'}</EmptyState>
      )}

      {activeTab === 'flags' && (
        flags.length ? <div className="space-y-2">{flags.map(flag => <article key={`${flag.type}:${flag.id}`} className="rounded-xl border border-border-subtle bg-surface p-4"><div className="flex items-center gap-2"><ShieldCheck aria-hidden="true" size={14} className="text-status-warning" /><h2 className="text-xs font-bold text-text-primary">{flag.type}: {flag.label}</h2></div><p className="mt-2 text-[11px] text-text-muted">{flag.detail}</p></article>)}</div> : <EmptyState>No source records contain a non-informational risk label or DNS response flag.</EmptyState>
      )}

      <p className="flex items-center gap-2 text-[10px] text-text-muted"><Globe aria-hidden="true" size={12} /> Protocol records are shown as decoded metadata. <Lock aria-hidden="true" size={12} /> No payload interpretation is added here.</p>
    </section>
  );
}
