import React, { useState } from 'react';
import { Search, AlertTriangle, X, Layers, Clipboard, Check } from 'lucide-react';
import { FlowSummary, PacketEvent } from '../types';
import InfoPopover from './InfoPopover';

interface FlowExplorerProps {
  flows: FlowSummary[];
  events: PacketEvent[];
  onSelectFlow: (flow: FlowSummary) => void;
  selectedFlow: FlowSummary | null;
  onCloseDrawer: () => void;
  evidenceName?: string;
}

export default function FlowExplorer({
  flows,
  events,
  onSelectFlow,
  selectedFlow,
  onCloseDrawer,
  evidenceName
}: FlowExplorerProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [directionFilter, setDirectionFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState<'bytes' | 'packets' | 'duration' | 'time'>('bytes');

  const [copied, setCopied] = useState(false);
  const [addedToReport, setAddedToReport] = useState(false);
  const [showSignalTip, setShowSignalTip] = useState(false);

  const isPrivateIp = (ip: string) => {
    return ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.') || ip.startsWith('172.31.') || ip === '127.0.0.1' || ip === '::1';
  };

  const getHostInfo = (ip: string) => {
    if (ip === '10.0.0.15') return 'Workstation (finance-pc)';
    if (ip === '10.0.0.18') return 'Database Server (db-prod-01)';
    if (ip === '10.0.0.1') return 'Internal DNS (dc-01)';
    if (ip === '203.0.113.15') return 'Public Web Host';
    if (ip === '185.190.140.12') return 'Remote Host (AS-20473)';
    if (ip === '198.51.100.42') return 'External Peer (AS-15169)';
    return isPrivateIp(ip) ? 'Internal Asset' : 'External Host';
  };

  const getCryptoStatus = (service?: string) => {
    const s = (service || '').toLowerCase();
    if (['https', 'tls', 'ssl', 'ssh'].includes(s)) {
      return { label: 'Encrypted', class: 'border border-status-success/40 text-status-success bg-status-success-bg/40 font-semibold' };
    }
    if (['http', 'dns', 'ftp', 'tftp', 'telnet'].includes(s)) {
      return { label: 'Cleartext (Unsecure)', class: 'border border-status-warning/40 text-status-warning bg-status-warning-bg/40 font-semibold' };
    }
    return { label: 'Plain / Text', class: 'bg-surface-muted border border-border-subtle text-text-muted' };
  };

  const getLinkedSignals = (flow: FlowSummary) => {
    if (flow.riskLevel === 'high') {
      return [{ severity: 'HIGH', title: 'Suspicious outbound pattern', desc: 'Anomalous socket session matching outbound data baselines.' }];
    }
    if (flow.riskLevel === 'medium') {
      return [{ severity: 'MEDIUM', title: 'Cleartext payload transfer', desc: 'Unencrypted Application-layer records observed in telemetry.' }];
    }
    if (flow.riskLevel === 'low') {
      return [{ severity: 'LOW', title: 'Minor telemetry deviation', desc: 'Slight anomaly identified in connection telemetry parameters.' }];
    }
    return [];
  };

  const getRedactedEvidence = (flow: FlowSummary, packets: PacketEvent[]) => {
    const httpPacket = packets.find(p => p.info.toLowerCase().includes('password') || p.info.toLowerCase().includes('username'));
    if (httpPacket) {
      let raw = httpPacket.info;
      raw = raw.replace(/password=\w+/gi, 'password=[redacted]');
      raw = raw.replace(/username=\w+/gi, 'username=[redacted]');
      raw = raw.replace(/secret=\w+/gi, 'secret=[redacted]');
      return `RAW TRANSACTION RECORD:\n${raw}`;
    }
    if (flow.riskLevel === 'high') {
      return `ESTABLISHED TELEMETRY:\nSYN_SENT -> ESTABLISHED\nPayload: ${flow.byteCount} bytes\nPort: ${flow.destinationPort}\nStatus: closed_by_reset`;
    }
    return `FLOW TELEMETRY RECORD:\nTime: ${flow.firstSeen}\nBytes: ${flow.byteCount}\nPackets: ${flow.packetCount}\nDuration: ${flow.duration.toFixed(3)}s`;
  };

  const handleCopy = () => {
    if (!selectedFlow) return;
    const txt = `Flow: ${selectedFlow.sourceIp}:${selectedFlow.sourcePort} -> ${selectedFlow.destinationIp}:${selectedFlow.destinationPort} (${selectedFlow.protocol})`;
    navigator.clipboard.writeText(txt).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const handleAddToReport = () => {
    setAddedToReport(true);
    setTimeout(() => setAddedToReport(false), 2000);
  };

  const handleShowSignalTip = () => {
    setShowSignalTip(true);
    setTimeout(() => setShowSignalTip(false), 3000);
  };

  const filteredFlows = flows
    .filter(flow => {
      const term = searchTerm.toLowerCase();
      const matchSearch =
        flow.sourceIp.toLowerCase().includes(term) ||
        flow.destinationIp.toLowerCase().includes(term) ||
        String(flow.sourcePort).includes(term) ||
        String(flow.destinationPort).includes(term) ||
        (flow.service || '').toLowerCase().includes(term);

      const matchProto = protocolFilter === 'ALL' || flow.protocol.toUpperCase() === protocolFilter;
      const matchRisk = riskFilter === 'ALL' || flow.riskLevel.toUpperCase() === riskFilter;
      const matchDir = directionFilter === 'ALL' || flow.direction.toUpperCase() === directionFilter;

      return matchSearch && matchProto && matchRisk && matchDir;
    })
    .sort((a, b) => {
      if (sortBy === 'bytes') return b.byteCount - a.byteCount;
      if (sortBy === 'packets') return b.packetCount - a.packetCount;
      if (sortBy === 'duration') return b.duration - a.duration;
      return new Date(b.firstSeen).getTime() - new Date(a.firstSeen).getTime();
    });

  const relatedPackets = selectedFlow
    ? events.filter(evt => {
        return (
          (evt.sourceIp === selectedFlow.sourceIp && evt.sourcePort === selectedFlow.sourcePort && evt.destinationIp === selectedFlow.destinationIp && evt.destinationPort === selectedFlow.destinationPort && evt.protocol === selectedFlow.protocol) ||
          (evt.sourceIp === selectedFlow.destinationIp && evt.sourcePort === selectedFlow.destinationPort && evt.destinationIp === selectedFlow.sourceIp && evt.destinationPort === selectedFlow.sourcePort && evt.protocol === selectedFlow.protocol)
        );
      })
    : [];

  const linkedSignalsCount = flows.filter(f => f.riskLevel === 'high' || f.riskLevel === 'medium').length;

  const cellPadding = selectedFlow ? 'px-1.5 md:px-2 lg:px-2.5' : 'px-2.5 sm:px-3.5';
  const badgePadding = selectedFlow ? 'px-1 py-0.5 text-[9px]' : 'px-1.5 py-0.5 text-[10px]';

  return (
    <div className="space-y-5">
      {/* 1. Page Header */}
      <div className="pb-3 border-b border-border-subtle/50">
        <h1 className="text-xl font-bold tracking-tight text-text-primary">Flow explorer</h1>
        <p className="text-xs text-text-muted mt-0.5">
          Inspect decoded conversations, endpoints, protocol activity, and related evidence.
        </p>
        
        {/* Metadata Strip */}
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 mt-2.5 text-[11px] text-text-muted">
          <div className="flex items-center gap-1">
            <span className="font-bold text-text-muted uppercase tracking-wider text-[9px]">Active file:</span>
            <span className="font-mono text-text-primary bg-surface-muted/60 px-1.5 py-0.5 rounded border border-border-subtle/30 text-[10px]">
              {evidenceName || 'portal_breach_investigation.pcap'}
            </span>
          </div>
          <div className="h-3 w-[1px] bg-border-subtle/40 hidden sm:block" />
          <div className="flex items-center gap-1.5">
            <span className="font-bold text-text-muted uppercase tracking-wider text-[9px]">Total flows:</span>
            <span className="font-mono font-bold text-text-primary">{flows.length}</span>
          </div>
          <div className="h-3 w-[1px] bg-border-subtle/40 hidden sm:block" />
          <div className="flex items-center gap-1.5">
            <span className="font-bold text-text-muted uppercase tracking-wider text-[9px]">Protocols:</span>
            <span className="font-mono font-semibold text-text-primary">
              {Array.from(new Set(flows.map(f => f.protocol.toUpperCase()))).join(', ')}
            </span>
          </div>
          <div className="h-3 w-[1px] bg-border-subtle/40 hidden sm:block" />
          <div className="flex items-center gap-1.5">
            <span className="font-bold text-text-muted uppercase tracking-wider text-[9px]">Linked signals:</span>
            <span className={`font-mono font-bold ${linkedSignalsCount > 0 ? 'text-status-danger' : 'text-text-primary'}`}>
              {linkedSignalsCount}
            </span>
          </div>
        </div>
      </div>

      {/* 2. Grid Workspace */}
      <div id="flow-explorer-workspace" className={`grid grid-cols-1 gap-5 relative font-sans ${selectedFlow ? 'xl:grid-cols-[minmax(0,1fr)_340px]' : 'grid-cols-1'}`}>
        
        {/* Left main inspect container */}
        <div className="space-y-4 min-w-0">
          
          {/* Analyst Control Strip */}
          <div className="p-3 bg-surface rounded-xl border border-border-subtle space-y-3 shadow-sm">
            <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
              {/* Search */}
              <div className="relative flex-1">
                <Search className="absolute left-2.5 top-2 text-text-muted" size={13} />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Filter by IP, port, protocol or service..."
                  className="w-full bg-canvas border border-border-subtle rounded-lg pl-8 pr-4 py-1 text-xs text-text-primary placeholder:text-text-muted focus:border-accent-primary/40 focus:outline-none focus:ring-1 h-7.5"
                />
              </div>
              
              {/* Sort & Reset */}
              <div className="flex items-center gap-3 justify-between">
                <div className="flex items-center gap-1 text-xs text-text-muted h-7.5">
                  <span className="text-[11px] whitespace-nowrap">Sort by:</span>
                  <select
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value as any)}
                    className="bg-canvas border border-border-subtle rounded-lg px-2 py-0.5 text-text-secondary focus:outline-none text-[11px] cursor-pointer font-medium h-7"
                  >
                    <option value="bytes">Bytes</option>
                    <option value="packets">Packets</option>
                    <option value="duration">Duration</option>
                    <option value="time">First seen</option>
                  </select>
                </div>

                {(searchTerm || protocolFilter !== 'ALL' || riskFilter !== 'ALL' || directionFilter !== 'ALL') && (
                  <button
                    onClick={() => {
                      setSearchTerm('');
                      setProtocolFilter('ALL');
                      setRiskFilter('ALL');
                      setDirectionFilter('ALL');
                    }}
                    className="px-2.5 py-1 text-[11px] font-semibold text-accent-primary hover:text-accent-primary-hover bg-accent-soft border border-accent-primary/20 rounded-md h-7 cursor-pointer"
                  >
                    Reset
                  </button>
                )}
              </div>
            </div>

            {/* Filters Row */}
            <div className="flex flex-wrap gap-x-5 gap-y-2 pt-2.5 border-t border-border-subtle/40 text-xs items-center">
              <div className="flex items-center gap-1.5">
                <span className="text-text-muted text-[10px] font-bold uppercase tracking-wider">Protocol:</span>
                <div className="flex bg-canvas rounded-md p-0.5 border border-border-subtle">
                  {['ALL', 'TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS'].map(p => (
                    <button
                      key={p}
                      onClick={() => setProtocolFilter(p)}
                      className={`px-1.5 py-0.5 rounded text-[10px] font-medium cursor-pointer transition-colors ${
                        protocolFilter === p ? 'bg-accent-soft text-accent-primary font-bold' : 'text-text-muted hover:text-text-primary'
                      }`}
                    >
                      {p}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-text-muted text-[10px] font-bold uppercase tracking-wider">Risk:</span>
                <div className="flex bg-canvas rounded-md p-0.5 border border-border-subtle">
                  {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map(r => (
                    <button
                      key={r}
                      onClick={() => setRiskFilter(r)}
                      className={`px-1.5 py-0.5 rounded text-[10px] font-medium cursor-pointer transition-colors ${
                        riskFilter === r ? 'bg-accent-soft text-accent-primary font-bold' : 'text-text-muted hover:text-text-primary'
                      }`}
                    >
                      {r}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-text-muted text-[10px] font-bold uppercase tracking-wider">Direction:</span>
                <div className="flex bg-canvas rounded-md p-0.5 border border-border-subtle">
                  {['ALL', 'OUTBOUND', 'INBOUND', 'INTERNAL'].map(d => (
                    <button
                      key={d}
                      onClick={() => setDirectionFilter(d)}
                      className={`px-1.5 py-0.5 rounded text-[10px] font-medium cursor-pointer transition-colors ${
                        directionFilter === d ? 'bg-accent-soft text-accent-primary font-bold' : 'text-text-muted hover:text-text-primary'
                      }`}
                    >
                      {d}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Flows Table */}
          <div className="bg-surface rounded-xl border border-border-subtle overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table id="flows-table" className="w-full text-left text-xs">
                <thead className="bg-surface-muted border-b border-border-subtle text-text-muted select-none">
                  <tr>
                    <th className={`py-2.5 ${cellPadding} font-bold text-[10px] tracking-wider uppercase whitespace-nowrap`}>Start time</th>
                    <th className={`py-2.5 ${cellPadding} font-bold text-[10px] tracking-wider uppercase whitespace-nowrap`}>Source</th>
                    <th className={`py-2.5 ${cellPadding} font-bold text-[10px] tracking-wider uppercase whitespace-nowrap`}>Destination</th>
                    <th className={`py-2.5 ${cellPadding} font-bold text-[10px] tracking-wider uppercase whitespace-nowrap`}>Protocol</th>
                    <th className={`py-2.5 ${cellPadding} text-right font-bold text-[10px] tracking-wider uppercase whitespace-nowrap`}>Packets</th>
                    <th className={`py-2.5 ${cellPadding} text-right font-bold text-[10px] tracking-wider uppercase whitespace-nowrap`}>Bytes</th>
                    <th className={`py-2.5 ${cellPadding} text-right font-bold text-[10px] tracking-wider uppercase whitespace-nowrap`}>Duration</th>
                    <th className={`py-2.5 ${cellPadding} font-bold text-[10px] tracking-wider uppercase whitespace-nowrap`}>
                      <div className="flex items-center gap-1">
                        <span>Risk</span>
                        <InfoPopover content="Risk reflects PacketSage’s review priority based on decoded metadata, protocol behavior, and related observations. It is not a confirmation of compromise." align="left" />
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/30">
                  {filteredFlows.length > 0 ? (
                    filteredFlows.map((flow) => {
                      const isSelected = selectedFlow?.id === flow.id;
                      return (
                        <tr
                          id={`flow-row-${flow.id}`}
                          key={flow.id}
                          onClick={() => onSelectFlow(flow)}
                          className={`hover:bg-surface-muted/50 cursor-pointer transition-colors ${
                            isSelected ? 'bg-accent-soft border-l-2 border-l-accent-primary font-semibold' : ''
                          }`}
                        >
                          <td className={`py-2.5 ${cellPadding} text-text-muted font-mono text-[11px] whitespace-nowrap`}>
                            {new Date(flow.firstSeen).toISOString().slice(11, 19)}
                          </td>
                          <td className={`py-2.5 ${cellPadding} text-text-primary font-mono text-[11px] whitespace-nowrap`}>
                            {flow.sourceIp}
                            <span className="text-text-muted font-mono text-[11px]">:{flow.sourcePort}</span>
                          </td>
                          <td className={`py-2.5 ${cellPadding} text-text-primary font-mono text-[11px] whitespace-nowrap`}>
                            {flow.destinationIp}
                            <span className="text-text-muted font-mono text-[11px]">:{flow.destinationPort}</span>
                          </td>
                          <td className={`py-2.5 ${cellPadding} font-mono whitespace-nowrap`}>
                            <span className={`bg-surface-muted text-text-secondary rounded border border-border-subtle/40 uppercase tracking-wider font-mono font-semibold whitespace-nowrap ${badgePadding}`}>
                              {flow.protocol} ({flow.service || 'plain'})
                            </span>
                          </td>
                          <td className={`py-2.5 ${cellPadding} text-right text-text-secondary font-mono text-[11px] tabular-nums whitespace-nowrap`}>{flow.packetCount}</td>
                          <td className={`py-2.5 ${cellPadding} text-right text-text-secondary font-mono text-[11px] tabular-nums whitespace-nowrap`}>
                            {flow.byteCount >= 1024 * 1024
                              ? `${(flow.byteCount / (1024 * 1024)).toFixed(1)} MB`
                              : `${(flow.byteCount / 1024).toFixed(1)} KB`}
                          </td>
                          <td className={`py-2.5 ${cellPadding} text-right text-text-muted font-mono text-[11px] tabular-nums whitespace-nowrap`}>{flow.duration.toFixed(2)}s</td>
                          <td className={`py-2.5 ${cellPadding} font-sans whitespace-nowrap`}>
                            <span
                              className={`px-2 py-0.5 rounded-lg text-[10px] font-bold tracking-wider uppercase border whitespace-nowrap ${
                                flow.riskLevel === 'high'
                                  ? 'bg-status-danger text-white border-transparent shadow-xs'
                                  : flow.riskLevel === 'medium'
                                  ? 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/15 font-semibold'
                                  : flow.riskLevel === 'low' || flow.riskLevel === 'info'
                                  ? 'bg-surface-muted text-text-muted border border-border-subtle font-normal'
                                  : 'bg-status-success text-white border-transparent shadow-xs font-bold'
                              }`}
                            >
                              {flow.riskLevel}
                            </span>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={8} className="py-10 text-center text-text-muted text-xs">
                        No flows match current filtering criteria.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* 3. Selected-Flow Cohesive Analyst Detail Rail */}
        {selectedFlow && (
          <div className="w-full p-4 bg-surface rounded-xl border border-border-subtle space-y-3.5 h-fit overflow-y-auto shadow-md animate-in slide-in-from-right duration-150">
            {/* Header */}
            <div className="flex justify-between items-start pb-2.5 border-b border-border-subtle/50">
              <div className="space-y-0.5">
                <span className="text-[9px] font-bold text-accent-primary tracking-wider uppercase block">Conversation forensics</span>
                <h3 className="text-xs font-bold text-text-primary">Flow analysis detail</h3>
              </div>
              <button
                onClick={onCloseDrawer}
                className="p-1 text-text-muted hover:text-text-primary bg-surface-muted rounded border border-border-subtle cursor-pointer transition-colors"
              >
                <X size={12} />
              </button>
            </div>

            {/* Quick Overview */}
            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between font-semibold text-text-primary">
                <span className="truncate max-w-[200px] font-mono">{selectedFlow.sourceIp} → {selectedFlow.destinationIp}</span>
                <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold tracking-wider uppercase border ${
                  selectedFlow.riskLevel === 'high'
                    ? 'bg-status-danger text-white border-transparent shadow-xs'
                    : selectedFlow.riskLevel === 'medium'
                    ? 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/15 font-semibold'
                    : selectedFlow.riskLevel === 'low' || selectedFlow.riskLevel === 'info'
                    ? 'bg-surface-muted text-text-muted border border-border-subtle font-normal'
                    : 'bg-status-success text-white border-transparent shadow-xs'
                }`}>
                  {selectedFlow.riskLevel}
                </span>
              </div>
              <div className="flex justify-between items-center text-[10px] text-text-muted">
                <span>First seen: <strong className="font-mono text-text-secondary font-medium">{new Date(selectedFlow.firstSeen).toISOString().slice(11, 19)}</strong></span>
                <span>Duration: <strong className="font-mono text-text-secondary font-medium">{selectedFlow.duration.toFixed(3)}s</strong></span>
              </div>
            </div>

            {/* Threat Caveat/Notice replacing alarmist alerts */}
            {selectedFlow.riskLevel === 'high' && (
              <div className="p-3 bg-status-danger-bg/25 border border-status-danger/15 rounded-xl flex gap-2">
                <AlertTriangle className="text-status-danger shrink-0 self-start mt-0.5" size={13} />
                <div className="space-y-0.5">
                  <span className="text-[10px] font-bold text-status-danger uppercase tracking-wider block">Analyst validation required</span>
                  <p className="text-[11px] text-text-secondary leading-relaxed font-normal">
                    This flow matches a suspicious outbound pattern. Review surrounding records and host telemetry before drawing conclusions.
                  </p>
                </div>
              </div>
            )}

            {/* A. Stats */}
            <div className="py-2.5 border-b border-border-subtle/40">
              <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-wider mb-1.5">Flow stats</h4>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                <div className="flex justify-between items-center py-0.5 border-b border-border-subtle/20">
                  <span className="text-text-muted text-[11px]">Packets</span>
                  <span className="font-mono text-text-primary font-semibold">{selectedFlow.packetCount}</span>
                </div>
                <div className="flex justify-between items-center py-0.5 border-b border-border-subtle/20">
                  <span className="text-text-muted text-[11px]">Bytes</span>
                  <span className="font-mono text-text-primary font-semibold">
                    {selectedFlow.byteCount >= 1024 * 1024
                      ? `${(selectedFlow.byteCount / (1024 * 1024)).toFixed(1)} MB`
                      : `${(selectedFlow.byteCount / 1024).toFixed(1)} KB`}
                  </span>
                </div>
                <div className="flex justify-between items-center py-0.5 border-b border-border-subtle/20">
                  <span className="text-text-muted text-[11px]">Duration</span>
                  <span className="font-mono text-text-primary font-semibold">{selectedFlow.duration.toFixed(3)}s</span>
                </div>
                <div className="flex justify-between items-center py-0.5 border-b border-border-subtle/20">
                  <span className="text-text-muted text-[11px]">Segments</span>
                  <span className="font-mono text-text-primary font-semibold">{relatedPackets.length} records</span>
                </div>
              </div>
            </div>

            {/* B. Endpoints */}
            <div className="py-2.5 border-b border-border-subtle/40">
              <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-wider mb-1.5">Endpoints</h4>
              <div className="grid grid-cols-2 gap-3.5 text-xs">
                <div className="space-y-0.5">
                  <span className="text-[9px] text-text-muted uppercase tracking-wider block font-semibold">Source</span>
                  <span className="font-mono text-text-primary block truncate font-semibold">
                    {selectedFlow.sourceIp}<span className="text-text-muted">:{selectedFlow.sourcePort}</span>
                  </span>
                  <span className="inline-block px-1 py-0.2 bg-surface-muted text-text-secondary border border-border-subtle/30 text-[9px] rounded font-medium">
                    {isPrivateIp(selectedFlow.sourceIp) ? 'Internal' : 'External'}
                  </span>
                  <span className="text-[10px] text-text-muted block truncate mt-0.5">{getHostInfo(selectedFlow.sourceIp)}</span>
                </div>

                <div className="space-y-0.5">
                  <span className="text-[9px] text-text-muted uppercase tracking-wider block font-semibold">Destination</span>
                  <span className="font-mono text-text-primary block truncate font-semibold">
                    {selectedFlow.destinationIp}<span className="text-text-muted">:{selectedFlow.destinationPort}</span>
                  </span>
                  <span className="inline-block px-1 py-0.2 bg-surface-muted text-text-secondary border border-border-subtle/30 text-[9px] rounded font-medium">
                    {isPrivateIp(selectedFlow.destinationIp) ? 'Internal' : 'External'}
                  </span>
                  <span className="text-[10px] text-text-muted block truncate mt-0.5">{getHostInfo(selectedFlow.destinationIp)}</span>
                </div>
              </div>
            </div>

            {/* C. Protocols */}
            <div className="py-2.5 border-b border-border-subtle/40">
              <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-wider mb-1.5">Protocol details</h4>
              <div className="space-y-1.5 text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-text-muted">Transport layer</span>
                  <span className="font-mono text-text-primary font-semibold">{selectedFlow.protocol}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-text-muted">Application protocol</span>
                  <span className="font-mono text-text-primary font-semibold uppercase">{selectedFlow.service || 'Unknown'}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-text-muted">Direction</span>
                  <span className="font-mono text-text-primary font-semibold uppercase">{selectedFlow.direction}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-text-muted">Crypto security</span>
                  <span className={`font-mono text-[9px] font-bold px-1.5 py-0.2 rounded border ${getCryptoStatus(selectedFlow.service).class}`}>
                    {getCryptoStatus(selectedFlow.service).label}
                  </span>
                </div>
              </div>
            </div>

            {/* D. Transactions */}
            <div className="py-2.5 border-b border-border-subtle/40">
              <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-wider mb-1.5">
                Decoded segments ({relatedPackets.length})
              </h4>
              {relatedPackets.length > 0 ? (
                <div className="space-y-1.5 max-h-32 overflow-y-auto pr-1">
                  {relatedPackets.map((pkt) => (
                    <div key={pkt.id} className="p-2 bg-canvas rounded-lg border border-border-subtle/30 font-mono text-[10px]">
                      <div className="flex justify-between text-text-muted text-[8px] mb-0.5">
                        <span>No. {pkt.id.split('-').pop()}</span>
                        <span>{new Date(pkt.timestamp).toISOString().slice(11, 19)}</span>
                      </div>
                      <div className="text-text-primary truncate font-medium">{pkt.info}</div>
                      <div className="text-right text-[8px] text-text-muted mt-0.5">{pkt.length} bytes</div>
                    </div>
                  ))}
                </div>
              ) : (
                <span className="text-[11px] text-text-muted italic block">No decrypted protocol segments.</span>
              )}
            </div>

            {/* E. Linked Signals */}
            <div className="py-2.5 border-b border-border-subtle/40">
              <div className="flex items-center gap-1.5 mb-1.5">
                <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-wider">Linked signals</h4>
                <InfoPopover content="Related signals are observations connected to this flow by host, protocol, timing, or destination context. Analysts should validate them before adding conclusions to a report." align="left" />
              </div>
              {getLinkedSignals(selectedFlow).length > 0 ? (
                <div className="space-y-1.5">
                  {getLinkedSignals(selectedFlow).map((sig, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-xs">
                      <span className={`font-mono text-[8px] font-bold px-1.5 py-0.5 rounded border shrink-0 uppercase ${
                        sig.severity === 'HIGH'
                          ? 'bg-status-danger text-white border-transparent'
                          : sig.severity === 'MEDIUM'
                          ? 'border border-status-warning/40 text-status-warning bg-status-warning-bg/40'
                          : 'bg-surface-muted border border-border-subtle text-text-muted'
                      }`}>
                        {sig.severity}
                      </span>
                      <div className="space-y-0.5">
                        <span className="font-semibold text-text-primary block text-[11px]">{sig.title}</span>
                        <p className="text-[10px] text-text-muted leading-tight">{sig.desc}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <span className="text-[11px] text-text-muted italic block">No linked alert signals detected.</span>
              )}
            </div>

            {/* F. Observed Evidence Snippet with Redaction */}
            <div className="py-2.5 border-b border-border-subtle/40">
              <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-wider mb-1.5">Observed evidence</h4>
              <pre className="p-2 bg-canvas rounded-lg border border-border-subtle/40 font-mono text-[9px] text-text-secondary leading-normal overflow-x-auto whitespace-pre-wrap select-all">
                {getRedactedEvidence(selectedFlow, relatedPackets)}
              </pre>
            </div>

            {/* G. Caveats & Checks */}
            <div className="py-2 border-b border-border-subtle/40 text-[10px] leading-relaxed text-text-muted space-y-2">
              <div>
                <span className="font-bold text-text-secondary block mb-0.5">What this does not prove</span>
                <p>This flow does not confirm account compromise, lateral movement, or data theft. It shows observed network activity that requires analyst review.</p>
              </div>
              <div>
                <span className="font-bold text-text-secondary block mb-0.5">Recommended checks</span>
                <ul className="list-disc pl-3.5 space-y-0.5">
                  <li>Verify whether destination host is expected.</li>
                  <li>Review authentication logs for matching source activity.</li>
                  <li>Inspect surrounding flows for identical telemetry signatures.</li>
                  <li>Confirm whether cleartext protocol transfer was intentional.</li>
                </ul>
              </div>
            </div>

            {/* Actions */}
            <div className="pt-1 space-y-2">
              <button
                onClick={handleAddToReport}
                className="w-full py-1.5 bg-accent-primary hover:bg-accent-primary-hover text-white rounded-lg text-xs font-semibold cursor-pointer transition-all flex items-center justify-center gap-1.5 shadow-sm"
              >
                {addedToReport ? <><Check size={12} /> Added to report</> : 'Add this flow to report'}
              </button>
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={handleCopy}
                  className="py-1.5 bg-surface-muted hover:bg-surface-muted/80 text-text-primary border border-border-subtle rounded-lg text-xs font-medium cursor-pointer transition-colors flex items-center justify-center gap-1"
                >
                  {copied ? <><Check size={11} className="text-status-success" /> Copied!</> : <><Clipboard size={11} /> Copy summary</>}
                </button>
                <button
                  onClick={handleShowSignalTip}
                  className="py-1.5 bg-surface-muted hover:bg-surface-muted/80 text-text-primary border border-border-subtle rounded-lg text-xs font-medium cursor-pointer transition-colors flex items-center justify-center gap-1"
                >
                  {showSignalTip ? 'Check Signals Tab' : 'Related signals'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
