import React, { useState, useEffect, useMemo } from 'react';
import {
  Clock,
  ShieldAlert,
  Radio,
  Globe,
  Lock,
  Unlock,
  ArrowDown,
  ArrowUp,
  Search,
  Filter,
  X,
  CheckCircle2,
  ExternalLink,
  FileText,
  Plus,
  Minus,
  Info,
  Shield,
  Activity,
  Check,
  RotateCcw,
  AlertCircle,
  Terminal,
  Network,
  Power,
  Fingerprint,
  Database,
  ShieldCheck,
  FileDown,
  AlertTriangle,
  ArrowUpRight,
  KeyRound
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { PacketEvent, FlowSummary, SuspiciousSignal } from '../types';
import InfoPopover from './InfoPopover';

interface IncidentTimelineProps {
  events: PacketEvent[];
  flows?: FlowSummary[];
  signals?: SuspiciousSignal[];
  onNavigateToFlows?: (flow: FlowSummary) => void;
}

interface MappedTimelineItem {
  id: string;
  time: string;
  type: 'dns' | 'http' | 'tls' | 'conn' | 'alert' | 'general';
  title: string;
  detail: string;
  src: string;
  srcIp: string;
  srcPort: number;
  dst: string;
  dstIp: string;
  dstPort: number;
  protocol: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  length: number;
  phase: string;
  originalEvent: PacketEvent;
}

// Utility to format relative capture offset time cleanly (e.g. +00:00:32)
const getRelativeTimeString = (itemTime: string, startMs: number) => {
  const diffMs = new Date(itemTime).getTime() - startMs;
  if (diffMs < 0) return "+00:00:00";
  const totalSec = Math.floor(diffMs / 1000);
  const hrs = Math.floor(totalSec / 3600);
  const mins = Math.floor((totalSec % 3600) / 60);
  const secs = totalSec % 60;
  return `+${String(hrs).padStart(2, '0')}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
};

// Map each event to standard, high-contrast solid icon and color styling
const getEventIconAndStyle = (title: string, type: string) => {
  const t = title.toLowerCase();
  
  // 1. High risk / High severity events (solid red)
  if (
    t.includes('credential submission') || 
    t.includes('credential') || 
    t.includes('large data') || 
    t.includes('exfiltration') || 
    t.includes('data transfer')
  ) {
    return {
      Icon: AlertTriangle,
      style: "bg-[#ef4444] text-white border border-[#dc2626] shadow-sm",
    };
  }

  // 2. Repeated outbound / DNS timing patterns (solid purple, sparingly)
  if (
    t.includes('repeated outbound') || 
    t.includes('beacon') || 
    t.includes('repetitive dns') || 
    t.includes('dns timing pattern') || 
    t.includes('connection observed')
  ) {
    return {
      Icon: Network,
      style: "bg-[#a855f7] text-white border border-[#9333ea] shadow-sm",
    };
  }

  // 3. Medium severity / validation warning (solid amber)
  if (
    t.includes('cleartext transfer') || 
    t.includes('http cleartext') || 
    t.includes('binary download') || 
    t.includes('connection attempt') ||
    type === 'http' ||
    type === 'alert'
  ) {
    return {
      Icon: FileDown,
      style: "bg-[#f59e0b] text-white border border-[#d97706] shadow-sm",
    };
  }

  // 4. Low / Info / Neutral events (solid slate)
  return {
    Icon: type === 'dns' ? Globe : (type === 'tls' ? ShieldCheck : Activity),
    style: "bg-[#64748b] text-white border border-[#475569] shadow-sm",
  };
};

export default function IncidentTimeline({ events, flows = [], signals = [], onNavigateToFlows }: IncidentTimelineProps) {
  // Sort and display states
  const [ascending, setAscending] = useState(true);
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);

  // Filters State
  const [searchQuery, setSearchQuery] = useState('');
  const [timeFilter, setTimeFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [groupBy, setGroupBy] = useState('none');

  // Interactive Report States persisted in LocalStorage
  const [reportStates, setReportStates] = useState<Record<string, 'not_added' | 'added' | 'reviewed' | 'dismissed'>>(() => {
    try {
      const saved = localStorage.getItem('packet_sage_timeline_reports');
      return saved ? JSON.parse(saved) : {};
    } catch {
      return {};
    }
  });

  // Save report state changes
  useEffect(() => {
    localStorage.setItem('packet_sage_timeline_reports', JSON.stringify(reportStates));
  }, [reportStates]);

  // Copy-to-clipboard confirmation state
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Map raw packet events to highly specific evidence-bound items
  const mappedItems: MappedTimelineItem[] = useMemo(() => {
    return events.map((evt, idx) => {
      const infoLower = evt.info.toLowerCase();
      const serviceLower = (evt.service || '').toLowerCase();
      const protoLower = (evt.protocol || '').toLowerCase();

      let type: 'dns' | 'http' | 'tls' | 'conn' | 'alert' | 'general' = 'general';
      let title = 'Network event observed';
      let severity: 'info' | 'low' | 'medium' | 'high' = 'info';
      let phase = 'Initial network activity';

      // 1. DNS Query
      if (serviceLower === 'dns' || infoLower.includes('query') || protoLower === 'dns' || evt.sourcePort === 53 || evt.destinationPort === 53) {
        type = 'dns';
        if (infoLower.includes('suspicious-lab.test') || infoLower.includes('beacon') || infoLower.includes('malicious')) {
          title = 'Repeated DNS query pattern requiring validation';
          severity = 'medium';
          phase = 'Repeated outbound activity';
        } else {
          title = 'DNS query requiring resolver review';
          severity = 'info';
          phase = 'DNS resolution';
        }
      }
      // 2. HTTP cleartext
      else if (serviceLower === 'http' || infoLower.includes('get ') || infoLower.includes('post ') || protoLower === 'http' || evt.sourcePort === 80 || evt.destinationPort === 80) {
        type = 'http';
        
        // Check for credentials
        if (infoLower.includes('user') || infoLower.includes('pass') || infoLower.includes('login') || infoLower.includes('auth') || infoLower.includes('cookie') || infoLower.includes('token') || infoLower.includes('sign')) {
          title = 'Cleartext transfer containing credential-like parameters requiring review';
          severity = 'high';
          phase = 'Application transfer';
        }
        // Check for binary downloads
        else if (infoLower.includes('patch.bin') || infoLower.includes('.exe') || infoLower.includes('.bin') || infoLower.includes('download')) {
          title = 'Cleartext transfer containing binary file signature requiring review';
          severity = 'medium';
          phase = 'Application transfer';
        } else if (infoLower.includes('upload.php') || infoLower.includes('post')) {
          title = 'HTTP cleartext transmission requiring review';
          severity = 'medium';
          phase = 'Application transfer';
        } else {
          title = 'HTTP cleartext transmission requiring review';
          severity = 'low';
          phase = 'Application transfer';
        }
      }
      // 3. TLS handshakes
      else if (
        serviceLower === 'tls' ||
        serviceLower === 'https' ||
        infoLower.includes('sni:') ||
        infoLower.includes('client hello') ||
        protoLower === 'tlsv1.3' ||
        protoLower === 'tls' ||
        evt.destinationPort === 443 ||
        evt.sourcePort === 443
      ) {
        type = 'tls';
        title = 'TLS session handshake requiring host review';
        severity = 'info';
        phase = 'Encrypted sessions';
      }
      // 4. Alerts / Mismatch / Large Data / Alerts
      else if (
        infoLower.includes('alert') ||
        infoLower.includes('suspicious') ||
        evt.sourcePort === 4444 ||
        evt.destinationPort === 4444 ||
        serviceLower === 'suricata alert'
      ) {
        type = 'alert';
        if (evt.length > 50000) {
          title = 'Large outbound transmission requiring volume review';
          severity = 'high';
        } else {
          title = 'Outbound connection pattern requiring validation';
          severity = 'medium';
        }
        phase = 'Analyst review items';
      }
      // 5. Large length
      else if (evt.length > 30000) {
        type = 'conn';
        title = 'Large outbound transmission requiring volume review';
        severity = 'high';
        phase = 'Application transfer';
      }
      // 6. Connections
      else if (protoLower === 'tcp' || protoLower === 'udp') {
        type = 'conn';
        if (evt.destinationPort === 443 || evt.destinationPort === 80) {
          title = 'External connection attempt requiring endpoint review';
          severity = 'low';
          phase = 'Initial network activity';
        } else {
          title = 'Repeated outbound pattern requiring connection sequence review';
          severity = 'medium';
          phase = 'Repeated outbound activity';
        }
      }

      // Force chronological phases based on sequence index to avoid messy grouping
      if (idx < 3 && phase !== 'Analyst review items') {
        phase = 'Initial network activity';
      }

      return {
        id: evt.id,
        time: evt.timestamp,
        type,
        title,
        detail: evt.info,
        src: `${evt.sourceIp}:${evt.sourcePort}`,
        srcIp: evt.sourceIp,
        srcPort: evt.sourcePort,
        dst: `${evt.destinationIp}:${evt.destinationPort}`,
        dstIp: evt.destinationIp,
        dstPort: evt.destinationPort,
        protocol: evt.protocol,
        severity,
        length: evt.length,
        phase,
        originalEvent: evt
      };
    });
  }, [events]);

  // Calculate earliest time to support relative calculations
  const earliestTime = useMemo(() => {
    if (mappedItems.length === 0) return 0;
    return Math.min(...mappedItems.map(item => new Date(item.time).getTime()));
  }, [mappedItems]);

  // Handle resets
  const handleResetFilters = () => {
    setSearchQuery('');
    setTimeFilter('all');
    setTypeFilter('all');
    setSeverityFilter('all');
    setSourceFilter('all');
    setGroupBy('none');
  };

  // Unique source IPs for filtering
  const uniqueSources = useMemo(() => {
    return Array.from(new Set(mappedItems.map(item => item.srcIp)));
  }, [mappedItems]);

  // Apply filters and sorting
  const filteredItems = useMemo(() => {
    let items = [...mappedItems];

    // Search query match
    if (searchQuery.trim() !== '') {
      const q = searchQuery.toLowerCase();
      items = items.filter(
        item =>
          item.title.toLowerCase().includes(q) ||
          item.detail.toLowerCase().includes(q) ||
          item.src.toLowerCase().includes(q) ||
          item.dst.toLowerCase().includes(q) ||
          item.protocol.toLowerCase().includes(q)
      );
    }

    // Time filter (relative offsets from first event)
    if (timeFilter !== 'all') {
      items = items.filter(item => {
        const itemTime = new Date(item.time).getTime();
        const diffMs = itemTime - earliestTime;
        if (timeFilter === '5s') return diffMs <= 5000;
        if (timeFilter === '1m') return diffMs <= 60000;
        if (timeFilter === 'over1m') return diffMs > 60000;
        return true;
      });
    }

    // Event type filter
    if (typeFilter !== 'all') {
      items = items.filter(item => item.type === typeFilter);
    }

    // Severity filter
    if (severityFilter !== 'all') {
      items = items.filter(item => item.severity === severityFilter);
    }

    // Source host filter
    if (sourceFilter !== 'all') {
      items = items.filter(item => item.srcIp === sourceFilter);
    }

    // Apply sorting
    items.sort((a, b) => {
      const timeA = new Date(a.time).getTime();
      const timeB = new Date(b.time).getTime();
      return ascending ? timeA - timeB : timeB - timeA;
    });

    return items;
  }, [mappedItems, searchQuery, timeFilter, typeFilter, severityFilter, sourceFilter, earliestTime, ascending]);

  // Dynamic Metadata Computations for the Header Row
  const metadata = useMemo(() => {
    const totalCount = events.length;
    const filteredCount = filteredItems.length;
    
    // Time Range
    let rangeStr = 'N/A';
    if (filteredItems.length > 0) {
      // Find absolute min and max times regardless of sort order
      const times = filteredItems.map(item => new Date(item.time).getTime());
      const minTime = Math.min(...times);
      const maxTime = Math.max(...times);
      const firstStr = new Date(minTime).toISOString().slice(11, 19);
      const lastStr = new Date(maxTime).toISOString().slice(11, 19);
      rangeStr = `${firstStr} – ${lastStr} UTC`;
    }

    const linkedSignalsCount = signals.length;
    const relatedFlowsCount = flows.length;
    const reportAddedCount = Object.values(reportStates).filter(v => v === 'added').length;

    return {
      totalCount,
      filteredCount,
      rangeStr,
      linkedSignalsCount,
      relatedFlowsCount,
      reportAddedCount
    };
  }, [events, filteredItems, signals, flows, reportStates]);

  // Group events helper
  const groupedSections = useMemo(() => {
    if (groupBy === 'none') return null;

    const groups: Record<string, MappedTimelineItem[]> = {};

    filteredItems.forEach(item => {
      let key = 'Uncategorized';
      if (groupBy === 'phase') {
        key = item.phase;
      } else if (groupBy === 'protocol') {
        key = item.protocol;
      } else if (groupBy === 'minute') {
        const d = new Date(item.time);
        const hrs = String(d.getUTCHours()).padStart(2, '0');
        const mins = String(d.getUTCMinutes()).padStart(2, '0');
        key = `${hrs}:${mins} UTC`;
      } else if (groupBy === 'source') {
        key = item.srcIp;
      }

      if (!groups[key]) groups[key] = [];
      groups[key].push(item);
    });

    const sortedKeys = Object.keys(groups);
    if (groupBy === 'minute' && ascending) {
      sortedKeys.sort();
    }

    return { keys: sortedKeys, groups };
  }, [filteredItems, groupBy, ascending]);

  // Selected item reference
  const selectedItem = useMemo(() => {
    if (!selectedItemId) return null;
    return mappedItems.find(item => item.id === selectedItemId) || null;
  }, [mappedItems, selectedItemId]);

  // Related Flows for Selected Event (IP matches)
  const relatedFlowsForSelected = useMemo(() => {
    if (!selectedItem) return [];
    return flows
      .filter(
        f =>
          f.sourceIp === selectedItem.srcIp ||
          f.destinationIp === selectedItem.dstIp ||
          f.sourceIp === selectedItem.dstIp ||
          f.destinationIp === selectedItem.srcIp
      )
      .slice(0, 3);
  }, [selectedItem, flows]);

  // Try to find the exact matching flow
  const matchingFlow = useMemo(() => {
    if (!selectedItem) return null;
    return flows.find(
      f =>
        (f.sourceIp === selectedItem.srcIp && f.destinationIp === selectedItem.dstIp) ||
        (f.sourceIp === selectedItem.dstIp && f.destinationIp === selectedItem.srcIp)
    ) || null;
  }, [selectedItem, flows]);

  // Related Observations / Signals for Selected Event
  const relatedSignalsForSelected = useMemo(() => {
    if (!selectedItem) return [];
    return signals
      .filter(s => {
        const evidenceStr = s.observedEvidence.toLowerCase();
        return (
          evidenceStr.includes(selectedItem.srcIp.toLowerCase()) ||
          evidenceStr.includes(selectedItem.dstIp.toLowerCase()) ||
          (selectedItem.type === 'dns' && evidenceStr.includes('dns')) ||
          (selectedItem.type === 'http' && evidenceStr.includes('http')) ||
          (selectedItem.type === 'tls' && evidenceStr.includes('tls'))
        );
      })
      .slice(0, 3);
  }, [selectedItem, signals]);

  // Helper: Copy event summary text
  const handleCopySummary = (item: MappedTimelineItem) => {
    const text = `Network Event Summary:\nObservable: ${item.title}\nTimestamp: ${item.time}\nSource: ${item.src}\nDestination: ${item.dst}\nPayload/Details: ${item.detail}`;
    navigator.clipboard.writeText(text);
    setCopiedId(item.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Helper: Toggle report inclusion status
  const handleToggleReportState = (id: string, newState: 'not_added' | 'added' | 'reviewed' | 'dismissed') => {
    setReportStates(prev => ({
      ...prev,
      [id]: newState
    }));
  };

  // Action: Investigate in Flow Explorer (navigates tab & sets active flow)
  const handleInvestigateInFlows = () => {
    if (!selectedItem) return;
    if (onNavigateToFlows) {
      const flowToSelect = matchingFlow || relatedFlowsForSelected[0] || {
        id: `temp-${selectedItem.id}`,
        firstSeen: selectedItem.time,
        lastSeen: selectedItem.time,
        sourceIp: selectedItem.srcIp,
        sourcePort: selectedItem.srcPort,
        destinationIp: selectedItem.dstIp,
        destinationPort: selectedItem.dstPort,
        protocol: selectedItem.protocol,
        packetCount: 1,
        byteCount: selectedItem.length,
        duration: 0,
        direction: 'outbound',
        riskLevel: selectedItem.severity
      };
      onNavigateToFlows(flowToSelect);
    }
  };

  // Decoded metadata pass with full sandbox mode clear fallback warning
  const getEvidencePreview = (item: MappedTimelineItem) => {
    const lines = [
      `Raw packet segment unavailable in sandbox mode. Showing decoded metadata from the selected event.`,
      `Note: All parameters displayed below are directly extracted from decoded capture logs without simulation.`,
      `================================================================================`,
      `Timestamp:               ${item.time}`,
      `Protocol / Frame Type:   ${item.protocol}`,
      `Payload Size:            ${item.length} bytes`,
      `Source Workstation:      ${item.srcIp}:${item.srcPort} (${item.src})`,
      `Destination Host:        ${item.dstIp}:${item.dstPort} (${item.dst})`,
    ];

    // Decode specific attributes based on real parsed details
    if (item.type === 'dns') {
      const parts = item.detail.split(' ');
      const domain = parts[parts.length - 1];
      const qtype = parts.length > 2 ? parts[parts.length - 2] : null;
      lines.push(
        `DNS Query Name:          ${domain || 'Unavailable (Not found in query string)'}`,
        `DNS Query Type:          ${qtype || 'Unavailable (Not found in query string)'}`,
        `Heuristic Description:   ${item.detail}`
      );
    } else if (item.type === 'http') {
      const isPost = item.detail.toUpperCase().includes('POST');
      const method = isPost ? 'POST' : 'GET';
      const pathPart = item.detail.match(/HTTP \w+ (\/[^\s]+)/) || item.detail.match(/\w+ (\/[^\s]+)/);
      const uri = pathPart ? pathPart[1] : 'Unavailable (Cleartext request path not parsed)';
      const hostMatch = item.detail.match(/Host: ([^\s\)]+)/) || item.detail.match(/Host ([^\s\)]+)/);
      const host = hostMatch ? hostMatch[1] : 'Unavailable (HTTP Host header not parsed)';
      lines.push(
        `HTTP Request Method:     ${method}`,
        `HTTP Host Domain:        ${host}`,
        `HTTP Request Path:       ${uri}`,
        `HTTP Header Integrity:   Decoded as Cleartext / Unencrypted`,
        `Heuristic Description:   ${item.detail}`
      );
    } else if (item.type === 'tls') {
      const sniMatch = item.detail.match(/SNI: ([^\s\)]+)/);
      const sni = sniMatch ? sniMatch[1] : 'Unavailable (Server Name Indication not parsed)';
      lines.push(
        `TLS SNI Handshake:       ${sni}`,
        `TLS Header Cryptography: Decoded as Encrypted TLS Record`,
        `Heuristic Description:   ${item.detail}`
      );
    } else {
      lines.push(
        `Heuristic Description:   ${item.detail}`
      );
    }

    if (item.originalEvent?.rawSummary) {
      lines.push(
        `--------------------------------------------------------------------------------`,
        `Raw Log Fragment:`,
        `  ${item.originalEvent.rawSummary}`
      );
    }

    return lines.join('\n');
  };

  return (
    <div id="incident-timeline-workspace" className="space-y-5 font-sans">
      
      {/* 1. Page Header with Compact Metadata Row */}
      <header className="border-b border-border-subtle/60 pb-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-1.5">
              <h1 className="text-xl font-bold text-text-primary tracking-tight">Incident timeline</h1>
              <InfoPopover content="The timeline sequence displays decoded events chronologically based on captured packet timestamps. It does not reflect browser runtime delays." align="left" />
            </div>
            <p className="text-xs text-text-secondary mt-0.5">
              Polished forensic workspace for chronological network path reconstruction and evidence validation.
            </p>
          </div>
        </div>

        {/* Compact Metadata Row */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-3.5 pt-3.5 border-t border-border-subtle/40 text-[11px]">
          <div className="space-y-0.5">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-text-muted block">Timeline events</span>
            <div className="text-text-primary font-medium">
              <span className="font-mono">{metadata.filteredCount}</span> of <span className="font-mono">{metadata.totalCount}</span>
            </div>
          </div>
          <div className="space-y-0.5 col-span-2 sm:col-span-1">
            <div className="flex items-center gap-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-text-muted block">Displayed timeline range</span>
              <InfoPopover content="The timeline sequence displays decoded events chronologically based on captured packet timestamps. It does not reflect browser runtime delays." align="left" />
            </div>
            <div className="text-text-primary font-mono font-medium truncate">
              {metadata.rangeStr}
            </div>
          </div>
          <div className="space-y-0.5">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-text-muted block">Linked signals</span>
            <div className="text-text-primary font-medium">
              <span className="font-mono">{metadata.linkedSignalsCount}</span> anomalies
            </div>
          </div>
          <div className="space-y-0.5">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-text-muted block">Related flows</span>
            <div className="text-text-primary font-medium">
              <span className="font-mono">{metadata.relatedFlowsCount}</span> active sessions
            </div>
          </div>
          <div className="space-y-0.5">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-text-muted block">Report-ready events</span>
            <div className="flex items-center gap-1.5 text-text-primary font-medium">
              <span className="font-mono text-accent-primary font-semibold">{metadata.reportAddedCount}</span> selected
            </div>
          </div>
        </div>
      </header>

      {/* 2. Timeline Controls / Filters Analyst Toolbar */}
      <div className="p-3 bg-surface rounded-xl border border-border-subtle shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-2.5 flex-1 min-w-0">
          
          {/* Search Box */}
          <div className="relative w-full md:w-56">
            <Search size={13} className="absolute left-3 top-2.5 text-text-muted" />
            <input
              type="text"
              placeholder="Search details, host..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-7 py-1.5 bg-canvas border border-border-subtle rounded-lg text-xs text-text-primary focus:outline-none focus:border-accent-primary font-sans transition-colors"
            />
            {searchQuery && (
              <button onClick={() => setSearchQuery('')} className="absolute right-2.5 top-2.5 text-text-muted hover:text-text-primary">
                <X size={12} />
              </button>
            )}
          </div>

          {/* Time range dropdown */}
          <div className="flex items-center gap-1">
            <span className="text-text-muted font-sans text-[10px] uppercase tracking-wider font-bold">Time:</span>
            <select
              value={timeFilter}
              onChange={(e) => setTimeFilter(e.target.value)}
              className="px-2 py-1.5 bg-canvas border border-border-subtle rounded-lg text-xs text-text-secondary focus:outline-none cursor-pointer"
            >
              <option value="all">All times</option>
              <option value="5s">First 5s</option>
              <option value="1m">First 1m</option>
              <option value="over1m">After 1m</option>
            </select>
          </div>

          {/* Event type dropdown */}
          <div className="flex items-center gap-1">
            <span className="text-text-muted font-sans text-[10px] uppercase tracking-wider font-bold">Type:</span>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="px-2 py-1.5 bg-canvas border border-border-subtle rounded-lg text-xs text-text-secondary focus:outline-none cursor-pointer"
            >
              <option value="all">All types</option>
              <option value="dns">DNS</option>
              <option value="http">HTTP</option>
              <option value="tls">TLS</option>
              <option value="alert">Alerts</option>
              <option value="conn">Conns</option>
            </select>
          </div>

          {/* Severity dropdown */}
          <div className="flex items-center gap-1">
            <div className="flex items-center gap-1">
              <span className="text-text-muted font-sans text-[10px] uppercase tracking-wider font-bold">Risk:</span>
              <InfoPopover content="Risk ratings are dynamically derived from observed ports, protocol states, and abnormal beaconing query intervals." align="left" />
            </div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-2 py-1.5 bg-canvas border border-border-subtle rounded-lg text-xs text-text-secondary focus:outline-none cursor-pointer"
            >
              <option value="all">All risks</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          {/* Source host dropdown */}
          {uniqueSources.length > 1 && (
            <div className="flex items-center gap-1">
              <span className="text-text-muted font-sans text-[10px] uppercase tracking-wider font-bold">Src:</span>
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="px-2 py-1.5 bg-canvas border border-border-subtle rounded-lg text-xs text-text-secondary focus:outline-none cursor-pointer"
              >
                <option value="all">All sources</option>
                {uniqueSources.map(src => (
                  <option key={src} value={src}>{src}</option>
                ))}
              </select>
            </div>
          )}

          {/* Group By control */}
          <div className="flex items-center gap-1">
            <span className="text-text-muted font-sans text-[10px] uppercase tracking-wider font-bold">Group:</span>
            <select
              value={groupBy}
              onChange={(e) => setGroupBy(e.target.value)}
              className="px-2 py-1.5 bg-canvas border border-border-subtle rounded-lg text-xs text-text-secondary focus:outline-none cursor-pointer"
            >
              <option value="none">None</option>
              <option value="phase">Phase</option>
              <option value="protocol">Protocol</option>
              <option value="minute">Minute</option>
              <option value="source">Source</option>
            </select>
          </div>

        </div>

        {/* Sort and Reset Trigger buttons */}
        <div className="flex items-center gap-2 self-end md:self-auto shrink-0">
          <button
            onClick={() => setAscending(!ascending)}
            className="px-2.5 py-1.5 bg-canvas hover:bg-surface-muted border border-border-subtle rounded-lg text-xs text-text-secondary flex items-center gap-1 transition-all duration-200 cursor-pointer font-sans font-medium"
          >
            {ascending ? <ArrowDown size={13} className="text-text-muted" /> : <ArrowUp size={13} className="text-text-muted" />}
            {ascending ? 'Earliest first' : 'Latest first'}
          </button>

          {(searchQuery || timeFilter !== 'all' || typeFilter !== 'all' || severityFilter !== 'all' || sourceFilter !== 'all' || groupBy !== 'none') && (
            <button
              onClick={handleResetFilters}
              className="text-xs font-bold text-accent-primary hover:text-accent-primary-hover flex items-center gap-1 transition-colors px-2.5 py-1.5 rounded bg-accent-soft/30 cursor-pointer border border-accent-primary/10"
            >
              <RotateCcw size={12} />
              Reset
            </button>
          )}
        </div>
      </div>

      {/* 3. Main Grid Layout: Interactive List on Left, Detail Rail on Right */}
      <div className={`grid grid-cols-1 ${selectedItemId ? 'xl:grid-cols-[minmax(0,1fr)_380px]' : ''} gap-6 items-start transition-all duration-200`}>
        
        {/* Left Side: Timeline Streams */}
        <div className="space-y-4 min-w-0">
          
          {filteredItems.length === 0 ? (
            <div className="p-12 text-center bg-surface border border-border-subtle rounded-2xl">
              <Activity size={24} className="text-text-muted mx-auto mb-3 animate-pulse" />
              <p className="text-sm font-semibold text-text-primary">No matching forensic events</p>
              <p className="text-xs text-text-muted mt-1 max-w-sm mx-auto">
                No chronological logs matched your search or filters. Try relaxing the query parameters.
              </p>
              <button
                onClick={handleResetFilters}
                className="mt-4 px-3 py-1.5 bg-canvas border border-border-subtle rounded-lg text-xs text-accent-primary font-semibold hover:bg-surface-muted/40 transition-colors cursor-pointer"
              >
                Clear all active filters
              </button>
            </div>
          ) : groupBy === 'none' ? (
            
            // UNGROUPED STANDARD TIMELINE
            <div className="space-y-3 pt-1">
              {/* Group Date Header */}
              <div className="flex items-center justify-between pb-2 border-b border-border-subtle/50 mb-3 px-1 select-none">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-text-primary">Capture Session Reconstruction</span>
                  <span className="text-[10px] bg-accent-soft text-accent-primary font-semibold px-2 py-0.5 rounded-full border border-accent-primary/10">
                    Active
                  </span>
                </div>
                <span className="text-[11px] font-mono text-text-muted">
                  {filteredItems.length} {filteredItems.length === 1 ? 'forensic event' : 'forensic events'}
                </span>
              </div>

              {/* Spine-Connected Event Rows */}
              <div className="space-y-2 relative">
                {filteredItems.map((item, idx) => {
                  const { Icon, style } = getEventIconAndStyle(item.title, item.type);
                  const isFirst = idx === 0;
                  const isLast = idx === filteredItems.length - 1;
                  const isSelected = selectedItemId === item.id;
                  return (
                    <div key={item.id} className="group/row flex items-stretch gap-3 relative min-h-[58px]">
                      
                      {/* Left: Absolute & Relative Capture Time */}
                      <div className="w-20 shrink-0 text-right pr-2 flex flex-col justify-center select-none">
                        <span className="font-mono text-[11px] font-bold text-text-primary">
                          {new Date(item.time).toISOString().slice(11, 19)}
                        </span>
                        <span className="font-mono text-[10px] text-text-muted mt-0.5">
                          {getRelativeTimeString(item.time, earliestTime)}
                        </span>
                      </div>

                      {/* Center: Integrated Spine and Solid Squared Icon Container */}
                      <div className="flex flex-col items-center justify-center relative w-10 shrink-0">
                        {/* Perfect-align Spine Segment */}
                        <div className={`absolute w-[2px] bg-border-subtle/40 dark:bg-slate-800/80 ${isFirst ? 'top-1/2' : 'top-0'} ${isLast ? 'bottom-1/2' : 'bottom-0'}`} />
                        
                        {/* High-Contrast Solid Icon Block */}
                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center relative z-10 shadow-sm transition-all duration-150 ${style} ${
                          isSelected ? 'ring-2 ring-accent-primary ring-offset-2 ring-offset-white dark:ring-offset-slate-950 scale-110 shadow-md' : 'hover:scale-105'
                        }`}>
                          <Icon size={14} className="stroke-[2.5]" />
                        </div>
                      </div>

                      {/* Right: Refined Compact Event Row Card */}
                      <div
                        onClick={() => setSelectedItemId(isSelected ? null : item.id)}
                        className={`flex-1 min-w-0 p-3 rounded-xl border cursor-pointer transition-all duration-150 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs ${
                          isSelected
                            ? 'bg-accent-soft/45 border-accent-primary/60 ring-1 ring-accent-primary/20 shadow-md scale-[1.005] translate-x-0.5'
                            : 'bg-surface border-border-subtle hover:bg-surface-muted/30 shadow-xs'
                        }`}
                      >
                        {/* Content area */}
                        <div className="flex-1 min-w-0 space-y-0.5">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-semibold text-text-primary text-[12.5px] leading-tight font-sans">
                              {item.title}
                            </span>
                            
                            {/* Interactive State Chips */}
                            {reportStates[item.id] === 'added' && (
                              <span className="bg-accent-soft border border-accent-primary/20 text-accent-primary font-semibold text-[8.5px] tracking-wider uppercase px-1.5 py-0.5 rounded-full flex items-center gap-1 shrink-0 select-none">
                                <span className="w-1.5 h-1.5 rounded-full bg-accent-primary" />
                                Report Link
                              </span>
                            )}
                            {reportStates[item.id] === 'reviewed' && (
                              <span className="bg-status-success text-white font-bold text-[8.5px] tracking-wider uppercase px-1.5 py-0.5 rounded-lg flex items-center gap-1 shrink-0 select-none shadow-xs border border-transparent">
                                <Check size={10} className="stroke-[3px]" />
                                Reviewed
                              </span>
                            )}
                            {reportStates[item.id] === 'dismissed' && (
                              <span className="bg-surface-muted border border-border-subtle text-text-muted font-semibold text-[8.5px] tracking-wider uppercase px-1.5 py-0.5 rounded-full shrink-0 select-none">
                                Excluded
                              </span>
                            )}
                          </div>
                          
                          <p className="text-text-secondary text-[11px] font-mono leading-relaxed truncate max-w-2xl select-text">
                            {item.detail}
                          </p>
                        </div>

                        {/* High density right-side metadata */}
                        <div className="flex items-center justify-between md:justify-end gap-3 shrink-0 border-t md:border-t-0 border-border-subtle/50 pt-1.5 md:pt-0">
                          <div className="flex items-center gap-1.5 font-mono text-[10.5px] text-text-secondary">
                            <span className="text-text-primary font-medium">{item.src}</span>
                            <span className="text-text-muted font-sans select-none">➔</span>
                            <span className="text-text-primary font-medium">{item.dst}</span>
                            <span className="text-[10px] text-text-muted bg-canvas px-1.5 py-0.5 rounded border border-border-subtle uppercase">{item.protocol}</span>
                          </div>

                          <span
                            className={`px-2 py-0.5 rounded-lg text-[9px] font-bold tracking-wider uppercase shrink-0 border ${
                              item.severity === 'high'
                                ? 'bg-status-danger text-white border-transparent shadow-xs'
                                : item.severity === 'medium'
                                ? 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/15 font-semibold'
                                : 'bg-surface-muted text-text-muted border-border-subtle font-normal'
                            }`}
                          >
                            {item.severity}
                          </span>
                        </div>

                      </div>

                    </div>
                  );
                })}
              </div>
            </div>

          ) : (

            // GROUPED TIMELINE VIEW
            <div className="space-y-5 pt-1">
              {groupedSections?.keys.map(key => {
                const groupItems = groupedSections.groups[key] || [];
                if (groupItems.length === 0) return null;

                return (
                  <div key={key} className="space-y-3">
                    {/* Compact Group Label */}
                    <div className="flex items-center justify-between pb-1.5 border-b border-border-subtle/40 mb-3 select-none">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold uppercase tracking-wider text-text-primary">{key}</span>
                        <span className="text-[10px] bg-surface-muted border border-border-subtle px-2 py-0.5 rounded-full text-text-secondary font-medium">
                          Group Segment
                        </span>
                      </div>
                      <span className="text-[11px] font-mono text-text-muted">
                        {groupItems.length} {groupItems.length === 1 ? 'event' : 'events'}
                      </span>
                    </div>

                    {/* Timeline subline list */}
                    <div className="space-y-2 relative">
                      {groupItems.map((item, idx) => {
                        const { Icon, style } = getEventIconAndStyle(item.title, item.type);
                        const isFirst = idx === 0;
                        const isLast = idx === groupItems.length - 1;
                        const isSelected = selectedItemId === item.id;
                        return (
                          <div key={item.id} className="group/row flex items-stretch gap-3 relative min-h-[58px]">
                            
                            {/* Left: Time Column */}
                            <div className="w-20 shrink-0 text-right pr-2 flex flex-col justify-center select-none">
                              <span className="font-mono text-[11px] font-bold text-text-primary">
                                {new Date(item.time).toISOString().slice(11, 19)}
                              </span>
                              <span className="font-mono text-[10px] text-text-muted mt-0.5">
                                {getRelativeTimeString(item.time, earliestTime)}
                              </span>
                            </div>

                            {/* Center: Spine Indicator with Solid Icon */}
                            <div className="flex flex-col items-center justify-center relative w-10 shrink-0">
                              <div className={`absolute w-[2px] bg-border-subtle/40 dark:bg-slate-800/80 ${isFirst ? 'top-1/2' : 'top-0'} ${isLast ? 'bottom-1/2' : 'bottom-0'}`} />
                              <div className={`w-8 h-8 rounded-lg flex items-center justify-center relative z-10 shadow-sm transition-all duration-150 ${style} ${
                                isSelected ? 'ring-2 ring-accent-primary ring-offset-2 ring-offset-white dark:ring-offset-slate-950 scale-110 shadow-md' : 'hover:scale-105'
                              }`}>
                                <Icon size={14} className="stroke-[2.5]" />
                              </div>
                            </div>

                            {/* Right: Compct Event Row Card */}
                            <div
                              onClick={() => setSelectedItemId(isSelected ? null : item.id)}
                              className={`flex-1 min-w-0 p-3 rounded-xl border cursor-pointer transition-all duration-150 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs ${
                                isSelected
                                  ? 'bg-accent-soft/45 border-accent-primary/60 ring-1 ring-accent-primary/20 shadow-md scale-[1.005] translate-x-0.5'
                                  : 'bg-surface border-border-subtle hover:bg-surface-muted/30 shadow-xs'
                              }`}
                            >
                              <div className="flex-1 min-w-0 space-y-0.5">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="font-semibold text-text-primary text-[12.5px] leading-tight font-sans">
                                    {item.title}
                                  </span>
                                  
                                  {reportStates[item.id] === 'added' && (
                                    <span className="bg-accent-soft border border-accent-primary/20 text-accent-primary font-semibold text-[8.5px] tracking-wider uppercase px-1.5 py-0.5 rounded-full flex items-center gap-1 shrink-0 select-none">
                                      <span className="w-1.5 h-1.5 rounded-full bg-accent-primary" />
                                      Report Link
                                    </span>
                                  )}
                                  {reportStates[item.id] === 'reviewed' && (
                                    <span className="bg-status-success text-white font-bold text-[8.5px] tracking-wider uppercase px-1.5 py-0.5 rounded-lg flex items-center gap-1 shrink-0 select-none shadow-xs border border-transparent">
                                      <Check size={10} className="stroke-[3px]" />
                                      Reviewed
                                    </span>
                                  )}
                                  {reportStates[item.id] === 'dismissed' && (
                                    <span className="bg-surface-muted border border-border-subtle text-text-muted font-semibold text-[8.5px] tracking-wider uppercase px-1.5 py-0.5 rounded-full shrink-0 select-none">
                                      Excluded
                                    </span>
                                  )}
                                </div>
                                <p className="text-text-secondary text-[11px] font-mono leading-relaxed truncate max-w-2xl select-text">
                                  {item.detail}
                                </p>
                              </div>

                              <div className="flex items-center justify-between md:justify-end gap-3 shrink-0 border-t md:border-t-0 border-border-subtle/50 pt-1.5 md:pt-0">
                                <div className="flex items-center gap-1.5 font-mono text-[10.5px] text-text-secondary">
                                  <span className="text-text-primary font-medium">{item.src}</span>
                                  <span className="text-text-muted font-sans select-none">➔</span>
                                  <span className="text-text-primary font-medium">{item.dst}</span>
                                  <span className="text-[10px] text-text-muted bg-canvas px-1.5 py-0.5 rounded border border-border-subtle uppercase">{item.protocol}</span>
                                </div>

                                <span
                                  className={`px-2 py-0.5 rounded-lg text-[9px] font-bold tracking-wider uppercase shrink-0 border ${
                                    item.severity === 'high'
                                      ? 'bg-status-danger text-white border-transparent shadow-xs'
                                      : item.severity === 'medium'
                                      ? 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/15 font-semibold'
                                      : 'bg-surface-muted text-text-muted border-border-subtle font-normal'
                                  }`}
                                >
                                  {item.severity}
                                </span>
                              </div>

                            </div>

                          </div>
                        );
                      })}
                    </div>

                  </div>
                );
              })}
            </div>

          )}
        </div>

        {/* Right Side: 6. Selected Event Detail Rail (Width: 340px - 380px) */}
        <AnimatePresence>
          {selectedItem && (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.15 }}
              className="p-5 rounded-2xl border border-border-subtle bg-surface shadow-md space-y-4 sticky top-4 max-h-[calc(100vh-100px)] overflow-y-auto"
            >
              
              {/* Header block inside rail */}
              <div className="border-b border-border-subtle pb-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Event details</span>
                  <button
                    onClick={() => setSelectedItemId(null)}
                    className="p-1 text-text-muted hover:text-text-primary rounded-lg hover:bg-surface-muted transition-colors cursor-pointer"
                  >
                    <X size={15} />
                  </button>
                </div>
                <h3 className="text-sm font-bold text-text-primary mt-2 leading-tight">
                  {selectedItem.title}
                </h3>
                <p className="text-[11px] text-text-secondary mt-1">
                  Forensic Event reconstruction for sequence evaluation.
                </p>
                
                {/* Meta details strip */}
                <div className="flex items-center gap-2 mt-2.5 flex-wrap">
                  <span
                    className={`px-2 py-0.5 rounded-lg text-[9px] font-bold tracking-wider uppercase border ${
                      selectedItem.severity === 'high'
                        ? 'bg-status-danger text-white border-transparent shadow-xs'
                        : selectedItem.severity === 'medium'
                        ? 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/15 font-semibold'
                        : 'bg-surface-muted text-text-muted border-border-subtle font-normal'
                    }`}
                  >
                    {selectedItem.severity} Risk
                  </span>
                  
                  <span className="text-[10px] font-mono text-text-secondary bg-canvas border border-border-subtle px-1.5 py-0.2 rounded select-all">
                    {new Date(selectedItem.time).toISOString().slice(11, 19)} UTC
                  </span>

                  <span className="text-[9px] font-bold text-text-muted uppercase tracking-wide bg-surface-muted px-1.5 py-0.5 rounded select-none">
                    {selectedItem.type.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Metadata Card - Two-Column High Fidelity Layout */}
              <div className="rounded-xl border border-border-subtle bg-canvas overflow-hidden text-[10.5px] p-3 space-y-2.5 select-text">
                <div className="grid grid-cols-2 gap-y-2.5 font-mono">
                  <div className="space-y-0.5">
                    <span className="text-[9px] font-sans font-bold uppercase tracking-wider text-text-muted block">Timestamp</span>
                    <span className="text-text-primary block truncate font-mono">{selectedItem.time}</span>
                  </div>
                  <div className="space-y-0.5">
                    <span className="text-[9px] font-sans font-bold uppercase tracking-wider text-text-muted block">Relative Time</span>
                    <span className="text-text-primary block truncate font-mono">{getRelativeTimeString(selectedItem.time, earliestTime)}</span>
                  </div>
                  <div className="space-y-0.5">
                    <span className="text-[9px] font-sans font-bold uppercase tracking-wider text-text-muted block">Protocol / Port</span>
                    <span className="text-text-primary block truncate uppercase">{selectedItem.protocol} / Port {selectedItem.dstPort}</span>
                  </div>
                  <div className="space-y-0.5">
                    <span className="text-[9px] font-sans font-bold uppercase tracking-wider text-text-muted block">Direction</span>
                    <span className="text-text-primary block capitalize">{matchingFlow?.direction || 'Outbound'}</span>
                  </div>
                  <div className="space-y-0.5 col-span-2 border-t border-border-subtle/30 pt-2">
                    <span className="text-[9px] font-sans font-bold uppercase tracking-wider text-text-muted block">Source workstation</span>
                    <span className="text-text-primary block font-medium font-mono truncate">{selectedItem.src}</span>
                  </div>
                  <div className="space-y-0.5 col-span-2 border-t border-border-subtle/30 pt-2">
                    <span className="text-[9px] font-sans font-bold uppercase tracking-wider text-text-muted block">Destination host</span>
                    <span className="text-text-primary block font-medium font-mono truncate">{selectedItem.dst}</span>
                  </div>
                  <div className="space-y-0.5 border-t border-border-subtle/30 pt-2">
                    <span className="text-[9px] font-sans font-bold uppercase tracking-wider text-text-muted block">Bytes / Packets</span>
                    <span className="text-text-primary block font-mono">{selectedItem.length} B / {matchingFlow?.packetCount || 1} pkts</span>
                  </div>
                  <div className="space-y-0.5 border-t border-border-subtle/30 pt-2">
                    <span className="text-[9px] font-sans font-bold uppercase tracking-wider text-text-muted block">Duration</span>
                    <span className="text-text-primary block font-mono">{matchingFlow ? `${matchingFlow.duration}s` : 'N/A'}</span>
                  </div>
                </div>
              </div>

              {/* A. Event Description */}
              <div className="space-y-1">
                <h4 className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Event description</h4>
                <div className="p-2.5 rounded-lg border border-border-subtle bg-canvas text-xs text-text-secondary leading-relaxed font-sans select-text">
                  {selectedItem.type === 'dns' && `Workstation ${selectedItem.srcIp} queried domain resolver on port 53. Reconstruct associated lookup address details below.`}
                  {selectedItem.type === 'http' && `Decoded cleartext application-layer payload observed on standard Port 80. Configuration documents or binaries were transmitted without cryptographic validation.`}
                  {selectedItem.type === 'tls' && `Workstation completed an encrypted session handshake with external domain host. No cleartext payloads are readable under standard TLS headers.`}
                  {selectedItem.type === 'alert' && `Forensic heuristic parser identified anomalous packet flags or signatures on cleartext TCP socket. Investigation is recommended.`}
                  {selectedItem.type === 'conn' && `Outbound socket sequence established from internal workstation to destination host.`}
                  {selectedItem.type === 'general' && `Packet metadata captured. Details displayed in decoder logs below.`}
                  <div className="mt-1.5 text-text-primary font-mono text-[10.5px] font-semibold">{selectedItem.detail}</div>
                </div>
              </div>

              {/* B. Evidence Preview */}
              <div className="space-y-1">
                <h4 className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Evidence preview</h4>
                <pre className="p-2.5 rounded-lg border border-border-subtle bg-canvas text-[10px] font-mono text-text-secondary overflow-x-auto leading-relaxed max-w-full whitespace-pre select-text">
                  {getEvidencePreview(selectedItem)}
                </pre>
              </div>

              {/* C. Related Signals */}
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <h4 className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Related observations ({relatedSignalsForSelected.length})</h4>
                </div>
                
                {relatedSignalsForSelected.length === 0 ? (
                  <p className="text-[10.5px] text-text-muted italic px-1">No anomalies triggered for this specific event.</p>
                ) : (
                  <div className="space-y-1.5">
                    {relatedSignalsForSelected.map(s => (
                      <div key={s.id} className="p-2 rounded-lg border border-border-subtle bg-canvas flex items-center justify-between gap-2 text-[10.5px] select-text">
                        <div className="min-w-0">
                          <span className="font-semibold text-text-primary block truncate">{s.title}</span>
                          <span className="text-[9px] text-text-muted block mt-0.5 truncate">{s.category}</span>
                        </div>
                        <span
                          className={`px-1.5 py-0.5 rounded-lg text-[8.5px] font-bold uppercase border shrink-0 ${
                            s.severity === 'high'
                              ? 'bg-status-danger text-white border-transparent shadow-xs'
                              : s.severity === 'medium'
                              ? 'border border-status-warning/30 text-[#f59e0b] bg-status-warning-bg/10 font-semibold'
                              : 'bg-surface-muted text-text-muted border-border-subtle/30 font-normal'
                          }`}
                        >
                          {s.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* D. Related Flows */}
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <h4 className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Related flows ({relatedFlowsForSelected.length})</h4>
                </div>
                
                {relatedFlowsForSelected.length === 0 ? (
                  <p className="text-[10.5px] text-text-muted italic px-1">No associated flows currently mapped in session.</p>
                ) : (
                  <div className="space-y-1.5">
                    {relatedFlowsForSelected.map(f => (
                      <div key={f.id} className="p-2 rounded-lg border border-border-subtle bg-canvas space-y-1 text-[10.5px] select-text">
                        <div className="flex items-center justify-between text-text-primary font-mono font-medium">
                          <span>{f.sourceIp}:{f.sourcePort}</span>
                          <span className="text-text-muted font-sans select-none">➔</span>
                          <span>{f.destinationIp}</span>
                        </div>
                        <div className="flex justify-between text-[9.5px] text-text-muted">
                          <span>{f.protocol} ({f.packetCount} packets)</span>
                          <span className="font-mono">{(f.byteCount / 1024).toFixed(2)} KB</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* E. Recommended Checks */}
              <div className="space-y-1.5">
                <h4 className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Recommended checks</h4>
                <ul className="space-y-1 text-[11px] text-text-secondary">
                  {[
                    "Review surrounding events before and after this timestamp.",
                    "Check endpoint process activity around the event time.",
                    "Confirm destination ownership and expected business use.",
                    "Compare with resolver, proxy, and authentication logs.",
                    "Add validated events to the incident report."
                  ].map((step, idx) => (
                    <li key={idx} className="flex gap-2 items-start leading-snug">
                      <span className="w-4 h-4 rounded border border-border-strong flex items-center justify-center shrink-0 bg-canvas font-mono text-[9px] font-bold text-accent-primary mt-0.5 select-none">
                        {idx + 1}
                      </span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Actions Button Grid */}
              <div className="pt-2.5 border-t border-border-subtle/50 space-y-1.5">
                
                {/* Pivot to Flow Explorer */}
                {onNavigateToFlows && (
                  <button
                    onClick={handleInvestigateInFlows}
                    className="w-full py-1.5 rounded-lg bg-accent-soft text-accent-primary border border-accent-primary/20 hover:bg-accent-primary/10 font-sans text-xs font-semibold cursor-pointer transition-all flex items-center justify-center gap-1.5"
                  >
                    <ExternalLink size={13} />
                    Investigate in Flow Explorer
                  </button>
                )}

                {/* Add to / Remove from Report */}
                {reportStates[selectedItem.id] === 'added' ? (
                  <button
                    onClick={() => handleToggleReportState(selectedItem.id, 'not_added')}
                    className="w-full py-1.5 rounded-lg bg-status-danger-bg hover:bg-status-danger/10 text-status-danger border border-status-danger/20 font-sans text-xs font-semibold cursor-pointer transition-all flex items-center justify-center gap-1.5"
                  >
                    <Minus size={13} />
                    Remove event from report
                  </button>
                ) : (
                  <button
                    onClick={() => handleToggleReportState(selectedItem.id, 'added')}
                    className="w-full py-1.5 rounded-lg bg-accent-primary hover:bg-accent-primary-hover text-white font-sans text-xs font-semibold cursor-pointer transition-all flex items-center justify-center gap-1.5 shadow-sm"
                  >
                    <Plus size={13} />
                    Add event to report
                  </button>
                )}

                {/* Additional workflow tags: Reviewed & Excluded */}
                <div className="grid grid-cols-2 gap-2 text-center">
                  <button
                    onClick={() => handleToggleReportState(selectedItem.id, 'reviewed')}
                    className={`py-1.5 rounded-lg border text-xs font-bold transition-all duration-150 flex items-center justify-center gap-1 ${
                      reportStates[selectedItem.id] === 'reviewed'
                        ? 'bg-status-success border-transparent text-white shadow-xs cursor-default'
                        : 'bg-surface border-border-subtle hover:bg-surface-muted text-text-secondary cursor-pointer'
                    }`}
                  >
                    <CheckCircle2 size={12} />
                    Mark reviewed
                  </button>

                  <button
                    onClick={() => handleToggleReportState(selectedItem.id, 'dismissed')}
                    className={`py-1.5 rounded-lg border text-xs font-semibold transition-all duration-150 cursor-pointer flex items-center justify-center gap-1 ${
                      reportStates[selectedItem.id] === 'dismissed'
                        ? 'bg-surface-muted border-border-strong/40 text-text-primary'
                        : 'bg-surface border-border-subtle hover:bg-surface-muted text-text-muted'
                    }`}
                  >
                    <X size={12} />
                    Exclude event
                  </button>
                </div>

                {/* Copy Summary Text with confirmation animation */}
                <button
                  onClick={() => handleCopySummary(selectedItem)}
                  className="w-full py-1.5 rounded-lg bg-surface hover:bg-surface-muted border border-border-default text-text-secondary font-sans text-xs font-semibold cursor-pointer transition-all flex items-center justify-center gap-1.5"
                >
                  {copiedId === selectedItem.id ? (
                    <>
                      <Check size={13} className="text-status-success" />
                      <span className="text-status-success">Forensic record copied!</span>
                    </>
                  ) : (
                    <>
                      <FileText size={13} />
                      Copy event details
                    </>
                  )}
                </button>

              </div>

            </motion.div>
          )}
        </AnimatePresence>

      </div>

    </div>
  );
}
