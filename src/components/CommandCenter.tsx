import React from 'react';
import {
  Server,
  Activity,
  Layers,
  Globe,
  Database,
  Cpu,
  AlertCircle,
  CheckCircle,
  FileText,
  ShieldCheck,
  Shield,
  ChevronRight,
  ArrowRight,
  Lock,
  CheckCircle2,
  Clock,
  HelpCircle,
  AlertTriangle,
  Calendar,
  HardDrive
} from 'lucide-react';
import { ParsedResult } from '../lib/parser';
import { PacketEvent } from '../types';
import InfoPopover from './InfoPopover';

interface CommandCenterProps {
  data: ParsedResult | null;
  onNavigate: (tab: string) => void;
}

// Format/clean signal titles to be highly forensic and quiet
const cleanSignalTitle = (title: string) => {
  if (title.includes('DNS Lookups') || title.includes('dnsbeacon')) return 'Possible periodic DNS pattern';
  if (title.includes('Cleartext Binary') || title.includes('cleartext-download')) return 'Cleartext binary transfer observed';
  if (title.includes('Suspicious Port') || title.includes('unusualport')) return 'External destination with repeated outbound connections';
  if (title.includes('Port Scan') || title.includes('portscan')) return 'Possible sequential port scanning';
  if (title.includes('Data Volume') || title.includes('dataspike')) return 'Large outbound data transmission requires review';
  return title;
};

const formatUploadedDate = (dateStr: string) => {
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    return d.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    }) + ' ' + d.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch (e) {
    return dateStr;
  }
};

const formatSize = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

export default function CommandCenter({ data, onNavigate }: CommandCenterProps) {
  if (!data) {
    return (
      <div id="cmd-empty" className="flex flex-col items-center justify-center py-24 text-center font-sans">
        <div className="p-4 bg-surface-muted rounded-full border border-border-subtle text-text-muted mb-4 animate-pulse">
          <Server size={32} />
        </div>
        <h3 className="text-sm font-semibold text-text-primary mb-1">No network evidence loaded</h3>
        <p className="text-text-secondary max-w-sm text-xs mb-6 leading-relaxed">
          To begin your network forensics investigation, import standard log exports, paste raw structured summaries, or load our pre-configured demo network incident.
        </p>
        <button
          id="btn-nav-import"
          onClick={() => onNavigate('import')}
          className="px-3.5 py-2 bg-accent-primary hover:bg-accent-primary-hover text-white font-semibold rounded-lg text-xs transition-colors border border-accent-primary/20 shadow-sm cursor-pointer"
        >
          Go to Evidence Import
        </button>
      </div>
    );
  }

  const { evidence, events, flows, dns, http, tls, signals, protocolStats } = data;
  const [hoveredProtocol, setHoveredProtocol] = React.useState<number | null>(null);
  const [metric, setMetric] = React.useState<'bytes' | 'events'>('bytes');
  const [timeBucket, setTimeBucket] = React.useState<'1m' | '5m' | 'auto'>('auto');
  const [hoveredIndex, setHoveredIndex] = React.useState<number | null>(null);

  // Compute custom chart segments exactly like ProtocolIntelligence (concentric donut)
  const donutSegments = React.useMemo(() => {
    let currentOffset = 0;
    const totalCircumference = 314.16; // 2 * PI * 50 = 314.16
    return protocolStats.map((stat, idx) => {
      const percentage = stat.percentage;
      const strokeLength = (percentage / 100) * totalCircumference;
      const strokeOffset = totalCircumference - currentOffset;
      currentOffset += strokeLength;

      const p = stat.protocol.toUpperCase();
      let color = '#94a3b8'; // default
      if (p.includes('TCP')) color = '#0062f1';
      else if (p.includes('UDP')) color = '#2f95ea';
      else if (p.includes('TLS') || p.includes('HTTPS')) color = '#10b981';
      else if (p.includes('HTTP')) color = '#f59e0b';
      else if (p.includes('DNS')) color = '#a855f7';
      else if (p.includes('ICMP')) color = '#64748b';

      return {
        ...stat,
        strokeLength,
        strokeOffset,
        color
      };
    });
  }, [protocolStats]);

  // Compute forensic stats
  const uniqueSrcIps = Array.from(new Set(events.map(e => e.sourceIp)));
  const uniqueDstIps = Array.from(new Set(events.map(e => e.destinationIp)));
  const uniqueEndpoints = Array.from(new Set([...uniqueSrcIps, ...uniqueDstIps]));
  const highRiskSignals = signals.filter(s => s.severity === 'high').length;
  const cleartextCount = http.filter(h => h.cleartext).length;

  const dominantProto = React.useMemo(() => {
    if (!donutSegments || donutSegments.length === 0) return 'None';
    const sorted = [...donutSegments].sort((a, b) => b.percentage - a.percentage);
    return sorted[0].protocol;
  }, [donutSegments]);

  const senderStats = React.useMemo(() => {
    const map = events.reduce((acc, evt) => {
      acc.set(evt.sourceIp, (acc.get(evt.sourceIp) || 0) + evt.length);
      return acc;
    }, new Map<string, number>());
    const sorted = Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
    if (sorted.length === 0) return { ip: 'None', pct: '0' };
    const total = sorted.reduce((sum, item) => sum + item[1], 0);
    const topPct = total > 0 ? ((sorted[0][1] / total) * 100).toFixed(1) : '0';
    return { ip: sorted[0][0], pct: topPct };
  }, [events]);

  const isDemo = evidence.name.toLowerCase().includes('recon') || evidence.name.toLowerCase().includes('demo') || evidence.name.toLowerCase().includes('sample') || evidence.name.toLowerCase().includes('compromised');

  // Observed Traffic Activity timeline data computations
  const chartData = React.useMemo(() => {
    if (!events || events.length === 0) return [];
    
    const parsedEvents = events
      .map(evt => ({
        time: new Date(evt.timestamp).getTime(),
        bytes: evt.length || 0,
      }))
      .filter(e => !isNaN(e.time))
      .sort((a, b) => a.time - b.time);

    if (parsedEvents.length === 0) return [];

    const start = parsedEvents[0].time;
    const end = parsedEvents[parsedEvents.length - 1].time;
    const durationMs = end - start;

    let intervalMs = 60 * 1000; // 1 min default
    if (timeBucket === '1m') {
      intervalMs = 60 * 1000;
    } else if (timeBucket === '5m') {
      intervalMs = 5 * 60 * 1000;
    } else {
      if (durationMs <= 0) {
        intervalMs = 60 * 1000;
      } else {
        const targetBuckets = 20;
        const rawInterval = durationMs / targetBuckets;
        if (rawInterval < 1000) {
          intervalMs = 1000;
        } else if (rawInterval < 10000) {
          intervalMs = 5000;
        } else if (rawInterval < 30000) {
          intervalMs = 10000;
        } else if (rawInterval < 60000) {
          intervalMs = 30000;
        } else if (rawInterval < 5 * 60000) {
          intervalMs = 60000;
        } else if (rawInterval < 15 * 60000) {
          intervalMs = 5 * 60000;
        } else if (rawInterval < 60 * 60000) {
          intervalMs = 15 * 60000;
        } else {
          intervalMs = 60 * 60000;
        }
      }
    }

    const buckets: { timeLabel: string; events: number; bytes: number; timestamp: number }[] = [];
    const numBuckets = Math.max(1, Math.ceil(durationMs / intervalMs)) + 1;
    
    for (let i = 0; i < numBuckets; i++) {
      const bucketTime = start + i * intervalMs;
      const dateObj = new Date(bucketTime);
      
      const timeLabel = dateObj.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: intervalMs < 60000 ? '2-digit' : undefined,
        hour12: true
      });

      buckets.push({
        timeLabel,
        events: 0,
        bytes: 0,
        timestamp: bucketTime
      });
    }

    parsedEvents.forEach(evt => {
      const bucketIndex = Math.floor((evt.time - start) / intervalMs);
      if (bucketIndex >= 0 && bucketIndex < buckets.length) {
        buckets[bucketIndex].events += 1;
        buckets[bucketIndex].bytes += evt.bytes;
      }
    });

    return buckets;
  }, [events, timeBucket]);

  const maxVal = React.useMemo(() => {
    if (chartData.length === 0) return 1;
    const vals = chartData.map(d => metric === 'bytes' ? d.bytes : d.events);
    const max = Math.max(...vals);
    return max === 0 ? 1 : max;
  }, [chartData, metric]);

  const svgPoints = React.useMemo(() => {
    if (chartData.length === 0) return [];
    const w = 720;
    const h = 150;
    const paddingLeft = 60;
    const paddingTop = 20;

    return chartData.map((d, idx) => {
      const val = metric === 'bytes' ? d.bytes : d.events;
      const x = paddingLeft + (idx / (chartData.length - 1)) * w;
      const y = paddingTop + h - (val / maxVal) * h;
      return { x, y, data: d, val };
    });
  }, [chartData, metric, maxVal]);

  const linePath = React.useMemo(() => {
    if (svgPoints.length === 0) return '';
    return svgPoints.map((p, idx) => `${idx === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ');
  }, [svgPoints]);

  const areaPath = React.useMemo(() => {
    if (svgPoints.length === 0) return '';
    const startX = svgPoints[0].x.toFixed(1);
    const startY = (20 + 150).toFixed(1);
    const endX = svgPoints[svgPoints.length - 1].x.toFixed(1);
    return `${linePath} L ${endX} ${startY} L ${startX} ${startY} Z`;
  }, [svgPoints, linePath]);

  const formatYLabel = (val: number) => {
    if (metric === 'bytes') {
      if (val >= 1024 * 1024) return `${(val / (1024 * 1024)).toFixed(1)} MB`;
      if (val >= 1024) return `${(val / 1024).toFixed(1)} KB`;
      return `${val} B`;
    } else {
      if (val >= 1000) return `${(val / 1000).toFixed(1)}k`;
      return `${val}`;
    }
  };

  const gridLines = React.useMemo(() => {
    const lines = [];
    const h = 150;
    const paddingLeft = 60;
    const paddingTop = 20;

    for (let i = 0; i <= 3; i++) {
      const ratio = i / 3;
      const y = paddingTop + h - ratio * h;
      const val = ratio * maxVal;
      lines.push({
        y,
        label: formatYLabel(val),
        val
      });
    }
    return lines;
  }, [maxVal, metric]);

  const xTicks = React.useMemo(() => {
    if (chartData.length < 2) return [];
    const ticks = [];
    const numTicks = Math.min(5, chartData.length);
    const step = Math.max(1, Math.floor(chartData.length / (numTicks - 1)));
    
    for (let i = 0; i < chartData.length; i += step) {
      ticks.push(i);
    }
    if (ticks.length > 0 && ticks[ticks.length - 1] !== chartData.length - 1) {
      ticks.push(chartData.length - 1);
    }
    return ticks;
  }, [chartData]);

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement, MouseEvent>) => {
    const svg = e.currentTarget;
    const rect = svg.getBoundingClientRect();
    
    const clientX = e.clientX - rect.left;
    const viewBoxX = (clientX / rect.width) * 800;

    const paddingLeft = 60;
    const w = 720;
    
    if (viewBoxX < paddingLeft || viewBoxX > paddingLeft + w || svgPoints.length === 0) {
      setHoveredIndex(null);
      return;
    }

    const relativeX = viewBoxX - paddingLeft;
    const percentage = relativeX / w;
    const index = Math.min(
      svgPoints.length - 1,
      Math.max(0, Math.round(percentage * (svgPoints.length - 1)))
    );

    setHoveredIndex(index);
  };

  // Format event info to match the clean forensic timeline reference
  const getFormattedEventInfo = (evt: PacketEvent) => {
    const infoLower = evt.info.toLowerCase();
    const isDns = evt.service === 'DNS' || evt.protocol === 'DNS' || infoLower.includes('dns') || infoLower.includes('query');
    const isHttp = evt.service === 'HTTP' || infoLower.includes('http');
    const isTls = evt.service === 'TLS' || evt.service === 'HTTPS' || infoLower.includes('tls') || infoLower.includes('handshake');

    if (isDns) {
      const parts = evt.info.split(' ');
      const domain = parts[parts.length - 1] || 'api.github.com';
      return `DNS query: DESKTOP-25KH -> ${evt.destinationIp} for ${domain}`;
    }
    if (isTls) {
      return `TLSv1.3 handshake: DESKTOP-25KH -> ${evt.destinationIp}:${evt.destinationPort}`;
    }
    if (isHttp) {
      return `HTTP POST: DESKTOP-25KH -> ${evt.destinationIp}:${evt.destinationPort} (${evt.length.toLocaleString()} bytes)`;
    }
    return `TCP connection established: DESKTOP-25KH -> ${evt.destinationIp}:${evt.destinationPort}`;
  };

  // Helper to resolve borders on the horizontal metric strip responsively
  const getBorderClass = (idx: number) => {
    let classes = "";
    // Mobile view (2 columns)
    if (idx % 2 !== 0) classes += " border-l border-border-subtle/40";
    if (idx >= 2) classes += " border-t border-border-subtle/40";

    // Medium view overrides (3 columns)
    classes += " sm:border-t-0 sm:border-l-0"; // reset mobile borders on sm
    if (idx % 3 !== 0) classes += " sm:border-l sm:border-border-subtle/40";
    if (idx >= 3) classes += " sm:border-t sm:border-border-subtle/40";

    // Large desktop overrides (6 columns)
    classes += " xl:border-t-0 xl:border-l xl:first:border-l-0 xl:border-border-subtle/40";
    return classes;
  };

  return (
    <div id="command-center-workspace" className="font-sans w-full max-w-[1440px] mx-auto px-6 md:px-8 py-6 space-y-6">
      
      {/* Top Context Area: Full Width */}
      <div className="space-y-6">
        
        {/* A. Evidence Header (Compact flat header area, no card) */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border-subtle">
          <div className="flex items-start gap-3.5 min-w-0">
            {/* Styled File Icon Box */}
            <div className="p-3 bg-blue-600 text-white dark:bg-blue-500 rounded-xl shrink-0 shadow-sm mt-1 flex items-center justify-center">
              <FileText size={22} className="stroke-[2.5]" />
            </div>
            
            <div className="space-y-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">Forensic workspace</span>
                {isDemo && (
                  <span className="px-2 py-0.5 bg-status-warning-bg text-status-warning border border-status-warning/15 text-[9px] font-semibold rounded-full uppercase tracking-wider select-none">
                    Sample incident dataset
                  </span>
                )}
              </div>
              <h2 className="text-lg md:text-xl font-bold tracking-tight text-text-primary font-sans truncate" title={evidence.name}>
                {evidence.name}
              </h2>
              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[11px] text-text-muted">
                <span className="flex items-center gap-1">
                  <Calendar size={11} className="text-text-muted shrink-0" />
                  {formatUploadedDate(evidence.uploadedAt)}
                </span>
                <span className="text-border-subtle/80 font-light">·</span>
                <span className="flex items-center gap-1">
                  <HardDrive size={11} className="text-text-muted shrink-0" />
                  {formatSize(evidence.size)}
                </span>
                <span className="text-border-subtle/80 font-light">·</span>
                <span className="flex items-center gap-1">
                  <Activity size={11} className="text-text-muted shrink-0" />
                  {events.length.toLocaleString()} packets
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-1.5 bg-status-success-bg border border-status-success/10 px-3 py-1 rounded-full h-fit shadow-sm select-none flex-nowrap shrink-0 self-start sm:self-center">
            <CheckCircle2 size={13} className="text-status-success shrink-0" />
            <span className="text-xs text-status-success font-semibold whitespace-nowrap">Analysis complete</span>
          </div>
        </div>

        {/* B. Compact Case Summary Cards */}
        <div className="space-y-3">
          <div>
            <h3 className="text-sm font-semibold text-text-primary">Case summary</h3>
            <p className="text-xs text-text-muted mt-0.5">Key metadata decoded from this network evidence.</p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            {/* Card 1: Events decoded */}
            <div className="p-3 bg-surface rounded-xl border border-border-subtle shadow-sm hover:shadow-md transition-all flex flex-col justify-between h-[76px] min-w-0">
              <div className="flex items-center justify-between gap-2 select-none">
                <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted block">Events</span>
                <div className="p-1 rounded-md bg-surface-muted select-none flex items-center justify-center shrink-0">
                  <Activity size={13} className="text-accent-primary" />
                </div>
              </div>
              <div className="flex items-baseline justify-between mt-1 min-w-0">
                <span className="text-lg font-bold text-text-primary tracking-tight tabular-nums font-mono shrink-0">{events.length}</span>
                <span className="text-[9px] text-text-muted font-normal block truncate ml-1 min-w-0">Telemetry decoded</span>
              </div>
            </div>

            {/* Card 2: Conversations */}
            <div className="p-3 bg-surface rounded-xl border border-border-subtle shadow-sm hover:shadow-md transition-all flex flex-col justify-between h-[76px] min-w-0">
              <div className="flex items-center justify-between gap-2 select-none">
                <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted block">Conversations</span>
                <div className="p-1 rounded-md bg-surface-muted select-none flex items-center justify-center shrink-0">
                  <Layers size={13} className="text-accent-primary" />
                </div>
              </div>
              <div className="flex items-baseline justify-between mt-1 min-w-0">
                <span className="text-lg font-bold text-text-primary tracking-tight tabular-nums font-mono shrink-0">{flows.length}</span>
                <span className="text-[9px] text-text-muted font-normal block truncate ml-1 min-w-0">Distinct sessions</span>
              </div>
            </div>

            {/* Card 3: Endpoints */}
            <div className="p-3 bg-surface rounded-xl border border-border-subtle shadow-sm hover:shadow-md transition-all flex flex-col justify-between h-[76px] min-w-0">
              <div className="flex items-center justify-between gap-2 select-none">
                <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted block">Endpoints</span>
                <div className="p-1 rounded-md bg-surface-muted select-none flex items-center justify-center shrink-0">
                  <Globe size={13} className="text-accent-primary" />
                </div>
              </div>
              <div className="flex items-baseline justify-between mt-1 min-w-0">
                <span className="text-lg font-bold text-text-primary tracking-tight tabular-nums font-mono shrink-0">{uniqueEndpoints.length}</span>
                <span className="text-[9px] text-text-muted font-normal block truncate ml-1 min-w-0">Unique addresses</span>
              </div>
            </div>

            {/* Card 4: Protocols */}
            <div className="p-3 bg-surface rounded-xl border border-border-subtle shadow-sm hover:shadow-md transition-all flex flex-col justify-between h-[76px] min-w-0">
              <div className="flex items-center justify-between gap-2 select-none">
                <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted block">Protocols</span>
                <div className="p-1 rounded-md bg-surface-muted select-none flex items-center justify-center shrink-0">
                  <Database size={13} className="text-accent-primary" />
                </div>
              </div>
              <div className="flex items-baseline justify-between mt-1 min-w-0">
                <span className="text-lg font-bold text-text-primary tracking-tight tabular-nums font-mono shrink-0">{protocolStats.length}</span>
                <span className="text-[9px] text-text-muted font-normal block truncate ml-1 min-w-0">Identified types</span>
              </div>
            </div>

            {/* Card 5: Signals */}
            <div className="p-3 bg-surface rounded-xl border border-border-subtle shadow-sm hover:shadow-md transition-all flex flex-col justify-between h-[76px] min-w-0">
              <div className="flex items-center justify-between gap-2 select-none">
                <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted block">Signals</span>
                <div className={`p-1 rounded-md select-none flex items-center justify-center shrink-0 ${
                  signals.length > 0 ? "bg-status-danger-bg/15" : "bg-surface-muted"
                }`}>
                  <AlertTriangle size={13} className={signals.length > 0 ? "text-status-danger" : "text-text-muted"} />
                </div>
              </div>
              <div className="flex items-baseline justify-between mt-1 min-w-0">
                <span className={`text-lg font-bold tracking-tight tabular-nums font-mono shrink-0 ${
                  signals.length > 0 ? "text-status-danger" : "text-text-primary"
                }`}>{signals.length}</span>
                <span className="text-[9px] text-text-muted font-normal block truncate ml-1 min-w-0">Requiring review</span>
              </div>
            </div>

            {/* Card 6: Cleartext */}
            <div className="p-3 bg-surface rounded-xl border border-border-subtle shadow-sm hover:shadow-md transition-all flex flex-col justify-between h-[76px] min-w-0">
              <div className="flex items-center justify-between gap-2 select-none">
                <div className="flex items-center gap-1.5">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted block">Cleartext</span>
                  <InfoPopover content="Cleartext refers to unencrypted application-layer traffic where payload or metadata may be readable from the capture path. It indicates exposure risk, not proof of compromise." align="left" />
                </div>
                <div className={`p-1 rounded-md select-none flex items-center justify-center shrink-0 ${
                  cleartextCount > 0 ? "bg-status-warning-bg/15" : "bg-surface-muted"
                }`}>
                  <Lock size={13} className={cleartextCount > 0 ? "text-status-warning" : "text-text-muted"} />
                </div>
              </div>
              <div className="flex items-baseline justify-between mt-1 min-w-0">
                <span className={`text-lg font-bold tracking-tight tabular-nums font-mono shrink-0 ${
                  cleartextCount > 0 ? "text-status-warning" : "text-text-primary"
                }`}>{cleartextCount}</span>
                <span className="text-[9px] text-text-muted font-normal block truncate ml-1 min-w-0">Unsecure transfers</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Two-Column Dashboard Layout below */}
      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_360px] gap-6 items-start">
        
        {/* Main Left Column */}
        <div className="space-y-6 min-w-0">
          
          {/* C. Observed Traffic Activity Chart */}
        <div className="p-5 bg-surface border border-border-subtle rounded-xl shadow-sm space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 select-none">
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-text-primary">Observed traffic activity</h3>
              <p className="text-xs text-text-muted">
                Timeline of decoded packet events and traffic volume from the loaded evidence.
              </p>
            </div>

            {/* Controls */}
            <div className="flex items-center gap-2">
              {/* Metric Select */}
              <div className="flex bg-surface-muted border border-border-subtle rounded-lg p-0.5 h-7">
                <button
                  onClick={() => setMetric('bytes')}
                  className={`px-2.5 py-0.5 rounded-md text-[10px] font-bold transition-all uppercase tracking-wider cursor-pointer ${
                    metric === 'bytes'
                      ? 'bg-surface text-accent-primary shadow-xs'
                      : 'text-text-muted hover:text-text-primary'
                  }`}
                >
                  Bytes
                </button>
                <button
                  onClick={() => setMetric('events')}
                  className={`px-2.5 py-0.5 rounded-md text-[10px] font-bold transition-all uppercase tracking-wider cursor-pointer ${
                    metric === 'events'
                      ? 'bg-surface text-accent-primary shadow-xs'
                      : 'text-text-muted hover:text-text-primary'
                  }`}
                >
                  Packets
                </button>
              </div>

              {/* Interval Select */}
              <div className="flex bg-surface-muted border border-border-subtle rounded-lg p-0.5 h-7">
                <button
                  onClick={() => setTimeBucket('1m')}
                  className={`px-2.5 py-0.5 rounded-md text-[10px] font-bold transition-all uppercase tracking-wider cursor-pointer ${
                    timeBucket === '1m'
                      ? 'bg-surface text-accent-primary shadow-xs'
                      : 'text-text-muted hover:text-text-primary'
                  }`}
                >
                  1m
                </button>
                <button
                  onClick={() => setTimeBucket('5m')}
                  className={`px-2.5 py-0.5 rounded-md text-[10px] font-bold transition-all uppercase tracking-wider cursor-pointer ${
                    timeBucket === '5m'
                      ? 'bg-surface text-accent-primary shadow-xs'
                      : 'text-text-muted hover:text-text-primary'
                  }`}
                >
                  5m
                </button>
                <button
                  onClick={() => setTimeBucket('auto')}
                  className={`px-2.5 py-0.5 rounded-md text-[10px] font-bold transition-all uppercase tracking-wider cursor-pointer ${
                    timeBucket === 'auto'
                      ? 'bg-surface text-accent-primary shadow-xs'
                      : 'text-text-muted hover:text-text-primary'
                  }`}
                >
                  Auto
                </button>
              </div>
            </div>
          </div>

          {/* Chart Wrapper with relative position for the floating tooltip */}
          <div className="relative w-full h-[200px] select-none bg-surface-muted/30 border border-border-subtle/50 rounded-xl p-2 flex flex-col justify-end">
            {chartData.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-center">
                <Activity size={24} className="text-text-muted animate-pulse mb-1.5" />
                <span className="text-xs text-text-muted font-mono">No chronological packet data found</span>
              </div>
            ) : (
              <>
                <svg
                  viewBox="0 0 800 200"
                  className="w-full h-full overflow-visible"
                  onMouseMove={handleMouseMove}
                  onMouseLeave={() => setHoveredIndex(null)}
                >
                  <defs>
                    <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#0062f1" stopOpacity="0.25" />
                      <stop offset="100%" stopColor="#0062f1" stopOpacity="0.005" />
                    </linearGradient>
                  </defs>

                  {/* Horizontal gridlines */}
                  {gridLines.map((line, idx) => (
                    <g key={idx}>
                      <line
                        x1="60"
                        y1={line.y}
                        x2="780"
                        y2={line.y}
                        stroke="currentColor"
                        className="text-border-subtle/40"
                        strokeDasharray={idx === 0 ? "none" : "3 3"}
                        strokeWidth="1"
                      />
                      <text
                        x="50"
                        y={line.y + 3.5}
                        textAnchor="end"
                        fill="currentColor"
                        className="text-[10px] font-mono font-medium text-text-secondary select-none"
                      >
                        {line.label}
                      </text>
                    </g>
                  ))}

                  {/* Shaded Area */}
                  {areaPath && (
                    <path
                      d={areaPath}
                      fill="url(#trafficGradient)"
                      className="transition-all duration-300"
                    />
                  )}

                  {/* Foreground Line */}
                  {linePath && (
                    <path
                      d={linePath}
                      fill="none"
                      stroke="#0062f1"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      className="transition-all duration-300"
                    />
                  )}

                  {/* X Axis Ticks */}
                  {xTicks.map((ptIdx) => {
                    const pt = svgPoints[ptIdx];
                    if (!pt) return null;
                    return (
                      <g key={ptIdx}>
                        <line
                          x1={pt.x}
                          y1="170"
                          x2={pt.x}
                          y2="174"
                          stroke="currentColor"
                          className="text-border-subtle"
                          strokeWidth="1"
                        />
                        <text
                          x={pt.x}
                          y="188"
                          textAnchor="middle"
                          fill="currentColor"
                          className="text-[10px] font-mono font-medium text-text-secondary select-none"
                        >
                          {pt.data.timeLabel}
                        </text>
                      </g>
                    );
                  })}

                  {/* Vertical Hover line and interactive dot */}
                  {hoveredIndex !== null && svgPoints[hoveredIndex] && (
                    <g>
                      <line
                        x1={svgPoints[hoveredIndex].x}
                        y1="20"
                        x2={svgPoints[hoveredIndex].x}
                        y2="170"
                        stroke="#0062f1"
                        strokeOpacity="0.5"
                        strokeWidth="1"
                        strokeDasharray="2 2"
                      />
                      <circle
                        cx={svgPoints[hoveredIndex].x}
                        cy={svgPoints[hoveredIndex].y}
                        r="5.5"
                        fill="#0062f1"
                        stroke="currentColor"
                        className="text-canvas"
                        strokeWidth="2"
                      />
                    </g>
                  )}
                </svg>

                {/* Floating tooltip */}
                {hoveredIndex !== null && svgPoints[hoveredIndex] && (
                  <div
                    className="absolute bg-white dark:bg-surface border border-border-default dark:border-border-subtle rounded-lg p-2.5 shadow-lg text-xs pointer-events-none z-30 select-none min-w-[120px]"
                    style={{
                      left: `${((svgPoints[hoveredIndex].x - 60) / 720) * 85 + 7}%`,
                      top: `${Math.min(110, Math.max(10, (svgPoints[hoveredIndex].y / 200) * 100))}%`,
                      transform: 'translate(-50%, -125%)'
                    }}
                  >
                    <div className="text-[10px] font-bold text-text-secondary dark:text-text-muted uppercase tracking-wider mb-1">
                      {svgPoints[hoveredIndex].data.timeLabel}
                    </div>
                    <div className="font-mono text-xs font-bold text-text-primary flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-accent-primary shrink-0" />
                      <span>
                        {metric === 'bytes'
                          ? formatSize(svgPoints[hoveredIndex].val)
                          : `${svgPoints[hoveredIndex].val.toLocaleString()} packets`}
                      </span>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>

        {/* D. Observed Traffic Distribution Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          
          {/* Protocol Composition */}
          <div className="p-5 bg-surface border border-border-subtle rounded-xl shadow-sm flex flex-col justify-between min-h-[200px]">
            <div className="space-y-3.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-text-muted block select-none">Protocol composition</span>
              
              <div className="grid grid-cols-1 sm:grid-cols-[115px_1fr] gap-4 items-center">
                {/* Modern Interactive SVG Donut Chart */}
                <div className="relative w-24 h-24 shrink-0 flex items-center justify-center select-none mx-auto sm:mx-0">
                  <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
                    {donutSegments.map((segment, idx) => {
                      const isHovered = hoveredProtocol === idx;
                      const isAnyHovered = hoveredProtocol !== null;
                      return (
                        <circle
                          key={idx}
                          cx="60"
                          cy="60"
                          r="50"
                          fill="transparent"
                          stroke={segment.color}
                          strokeWidth={isHovered ? 14 : 11}
                          strokeDasharray={`${segment.strokeLength} 314.16`}
                          strokeDashoffset={segment.strokeOffset}
                          className="transition-all duration-300 cursor-pointer"
                          onMouseEnter={() => setHoveredProtocol(idx)}
                          onMouseLeave={() => setHoveredProtocol(null)}
                          style={{
                            opacity: isAnyHovered && !isHovered ? 0.35 : 1,
                            filter: isHovered ? `drop-shadow(0 0 3px ${segment.color}60)` : 'none',
                            transformOrigin: '60px 60px'
                          }}
                        />
                      );
                    })}
                  </svg>
                  <div className="absolute flex flex-col items-center justify-center text-center pointer-events-none p-1 w-full">
                    {hoveredProtocol !== null ? (
                      <>
                        <span className="text-text-primary text-[10px] font-bold font-mono leading-none truncate max-w-[65px]">
                          {donutSegments[hoveredProtocol].protocol}
                        </span>
                        <span className="text-[11px] font-bold font-mono text-accent-primary mt-0.5 leading-none">
                          {donutSegments[hoveredProtocol].percentage}%
                        </span>
                      </>
                    ) : (
                      <>
                        <span className="text-text-muted text-[8px] uppercase tracking-wider leading-none">Total</span>
                        <span className="text-[11px] font-bold font-mono text-text-primary mt-0.5 leading-none">100%</span>
                      </>
                    )}
                  </div>
                </div>

                {/* High-Fidelity Rich Table Legend */}
                <div className="flex-1 space-y-0.5 text-xs max-h-[120px] overflow-y-auto no-scrollbar pr-1">
                  {donutSegments.map((segment, idx) => {
                    const isHovered = hoveredProtocol === idx;
                    const isAnyHovered = hoveredProtocol !== null;
                    return (
                      <div
                        key={idx}
                        onMouseEnter={() => setHoveredProtocol(idx)}
                        onMouseLeave={() => setHoveredProtocol(null)}
                        className={`flex items-center justify-between p-1 px-1.5 rounded-lg border transition-all duration-150 cursor-pointer ${
                          isHovered
                            ? 'border-accent-primary bg-accent-soft/30 ring-1 ring-accent-primary/20'
                            : isAnyHovered
                              ? 'border-transparent opacity-35 bg-transparent'
                              : 'border-transparent hover:bg-surface-muted/30'
                        }`}
                      >
                        <div className="flex items-center gap-1.5 min-w-0">
                          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: segment.color }} />
                          <span className="font-mono font-bold text-text-primary text-[11px] truncate">{segment.protocol}</span>
                        </div>
                        <div className="text-right font-mono text-[10px] text-text-secondary shrink-0 pl-1">
                          <span className="font-bold text-accent-primary bg-accent-soft/40 px-1 py-0.5 rounded border border-accent-primary/10 text-[9px]">
                            {segment.percentage}%
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
            <div className="mt-2.5 pt-2 border-t border-border-subtle/40 text-[10px] text-text-muted flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-primary shrink-0" />
              <span>Dominant protocol: <strong className="text-text-primary font-mono font-bold">{dominantProto}</strong></span>
            </div>
          </div>

          {/* Top Internal Transmitters */}
          <div className="p-5 bg-surface border border-border-subtle rounded-xl shadow-sm flex flex-col justify-between min-h-[200px]">
            <div className="space-y-3.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-text-muted block select-none">Top internal endpoint transmitters</span>
              <div className="space-y-2">
                {/* Headers */}
                <div className="grid grid-cols-[105px_1fr_80px_50px] items-center gap-3 text-[10px] font-semibold text-text-muted uppercase tracking-wider border-b border-border-subtle/40 pb-1.5 font-sans">
                  <span>Endpoint</span>
                  <div />
                  <span className="text-right">Bytes sent</span>
                  <span className="text-right">Share</span>
                </div>

                {Array.from(
                  events.reduce((acc, evt) => {
                    acc.set(evt.sourceIp, (acc.get(evt.sourceIp) || 0) + evt.length);
                    return acc;
                  }, new Map<string, number>())
                )
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 5)
                  .map(([ip, bytes], i, arr) => {
                    const maxBytes = arr[0][1];
                    const widthPercent = maxBytes > 0 ? (bytes / maxBytes) * 100 : 0;
                    const formattedBytes = bytes > 1024 * 1024 
                      ? `${(bytes / (1024 * 1024)).toFixed(2)} MB` 
                      : `${(bytes / 1024).toFixed(2)} KB`;
                    const share = ((bytes / arr.reduce((sum, item) => sum + item[1], 0)) * 100).toFixed(1);
                    return (
                      <div key={i} className="grid grid-cols-[105px_1fr_80px_50px] items-center gap-3 text-[11px] font-mono py-0.5">
                        <span className="text-text-primary font-medium block truncate" title={ip}>{ip}</span>
                        <div className="h-1 bg-surface-muted rounded-full overflow-hidden">
                          <div className="h-full bg-status-info rounded-full" style={{ width: `${widthPercent}%` }} />
                        </div>
                        <span className="text-right text-text-muted">{formattedBytes}</span>
                        <span className="text-right text-text-muted">{share}%</span>
                      </div>
                    );
                  })}
              </div>
            </div>
            <div className="mt-2.5 pt-2 border-t border-border-subtle/40 text-[10px] text-text-muted flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-status-info shrink-0" />
              <span className="truncate">Top sender accounts for <strong className="text-text-primary font-mono font-bold">{senderStats.pct}%</strong> of observed bytes ({senderStats.ip})</span>
            </div>
          </div>

        </div>

        {/* D. Signals Requiring Review (Preview table format) */}
        <div className="p-5 bg-surface border border-border-subtle rounded-xl shadow-sm space-y-4">
          <div className="flex justify-between items-center border-b border-border-subtle/50 pb-3 select-none">
            <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              Signals requiring review <span className="text-text-muted font-normal text-xs font-sans">(preview)</span>
            </h3>
            <button 
              onClick={() => onNavigate('signals')} 
              className="text-xs text-accent-primary hover:underline font-semibold flex items-center gap-0.5 cursor-pointer"
            >
              View all signals & observations <ChevronRight size={13} />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-text-secondary font-sans border-collapse">
              <thead>
                <tr className="border-b border-border-subtle text-[10px] font-semibold uppercase text-text-muted tracking-wider">
                  <th className="py-2.5 px-3">Signal</th>
                  <th className="py-2.5 px-2">Severity</th>
                  <th className="py-2.5 px-2">Confidence</th>
                  <th className="py-2.5 px-3">Observed evidence</th>
                  <th className="py-2.5 px-2 text-right"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/40">
                {signals.slice(0, 3).map((sig, i) => {
                  const cleanedTitle = cleanSignalTitle(sig.title);
                  return (
                    <tr 
                      key={i} 
                      onClick={() => onNavigate('signals')} 
                      className="hover:bg-surface-muted/30 cursor-pointer transition-colors group"
                    >
                      <td className="py-3 px-3 font-medium text-text-primary">
                        <div className="flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full shrink-0 ${
                            sig.severity === 'high' ? 'bg-status-danger' : 
                            sig.severity === 'medium' ? 'bg-status-warning' : 'bg-status-info'
                          }`} />
                          <span className="truncate max-w-[180px] md:max-w-xs">{cleanedTitle}</span>
                        </div>
                      </td>
                      <td className="py-3 px-2">
                        <span className={`px-2.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${
                          sig.severity === 'high' ? 'bg-status-danger-bg text-status-danger border-status-danger/10' :
                          sig.severity === 'medium' ? 'bg-status-warning-bg text-status-warning border-status-warning/10' :
                          'bg-status-info-bg text-status-info border-status-info/10'
                        }`}>
                          {sig.severity}
                        </span>
                      </td>
                      <td className="py-3 px-2">
                        <span className={`px-2.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${
                          sig.confidence === 'high' ? 'bg-status-success-bg text-status-success border-status-success/10' :
                          sig.confidence === 'medium' ? 'bg-status-warning-bg text-status-warning border-status-warning/10' :
                          'bg-status-info-bg text-status-info border-status-info/10'
                        }`}>
                          {sig.confidence}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-text-muted font-mono truncate max-w-[150px] md:max-w-xs font-normal" title={sig.observedEvidence}>
                        {sig.observedEvidence}
                      </td>
                      <td className="py-3 px-2 text-right text-text-muted group-hover:text-text-primary transition-colors">
                        <ChevronRight size={14} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* E. Timeline Preview */}
        <div className="p-5 bg-surface border border-border-subtle rounded-xl shadow-sm space-y-4">
          <div className="flex justify-between items-center border-b border-border-subtle/50 pb-3 select-none">
            <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              Timeline preview <span className="text-text-muted font-normal text-xs font-sans">(earliest first)</span>
            </h3>
            <button 
              onClick={() => onNavigate('timeline')} 
              className="text-xs text-accent-primary hover:underline font-semibold flex items-center gap-0.5 cursor-pointer"
            >
              View full incident timeline <ChevronRight size={13} />
            </button>
          </div>

          <div className="border border-border-subtle/70 rounded-xl overflow-hidden divide-y divide-border-subtle/40">
            {events.slice(0, 4).map((evt, i) => {
              const date = new Date(evt.timestamp);
              const timeStr = `${String(date.getUTCHours()).padStart(2, '0')}:${String(date.getUTCMinutes()).padStart(2, '0')}:${String(date.getUTCSeconds()).padStart(2, '0')}.${String(date.getUTCMilliseconds()).padStart(3, '0')}`;
              
              const Icon = 
                evt.service === 'DNS' ? Globe :
                evt.service === 'HTTP' ? Lock :
                evt.service === 'HTTPS' ? Lock :
                evt.protocol === 'TCP' ? Activity : Database;

              const displayInfo = getFormattedEventInfo(evt);

              return (
                <div key={i} className="flex flex-col sm:flex-row sm:items-center justify-between p-3.5 text-xs bg-surface-muted/10 hover:bg-surface-muted/20 transition-colors font-mono gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="text-text-muted tabular-nums shrink-0 font-normal">{timeStr}</span>
                    <div className="p-1 bg-surface rounded border border-border-subtle/40 text-text-muted shrink-0 select-none">
                      <Icon size={12} />
                    </div>
                    <span className="text-text-secondary truncate font-normal block" title={displayInfo}>{displayInfo}</span>
                  </div>
                  <div className="flex items-center gap-2 text-[10px] text-text-muted shrink-0 sm:border-l sm:border-border-subtle/40 sm:pl-3 font-normal">
                    <span>{evt.sourceIp}:{evt.sourcePort}</span>
                    <span>-&gt;</span>
                    <span>{evt.destinationIp}:{evt.destinationPort}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

      </div>

      {/* Right Column: Persistent Investigation Brief Panel (Memo style) */}
      <div className="w-full xl:w-[360px] shrink-0 space-y-6">
        <div className="p-5 md:p-6 bg-surface rounded-xl border border-border-subtle shadow-sm space-y-5 h-fit xl:sticky xl:top-24">
          
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border-subtle pb-3 select-none">
            <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              <FileText size={15} className="text-accent-primary" />
              Investigation Brief
            </h3>
            <span className="text-[10px] text-text-muted font-bold font-mono uppercase tracking-wider">SOC MEMO</span>
          </div>

          {/* Section 1: Current assessment */}
          <div className="flex gap-3 items-start border-b border-border-subtle/50 pb-4">
            <div className="p-1.5 bg-accent-soft text-accent-primary rounded-lg shrink-0 select-none">
              <Shield size={16} />
            </div>
            <div className="space-y-1 text-xs">
              <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted block select-none">Current assessment</span>
              <p className="text-text-secondary leading-relaxed font-normal">
                Traffic contains several review-worthy observations. The deterministic analysis engine has mapped key telemetry and suspicious indicators.
              </p>
            </div>
          </div>

          {/* Section 2: Recommended next action */}
          <div className="flex gap-3 items-start border-b border-border-subtle/50 pb-4">
            <div className="p-1.5 bg-[#0062f1] text-white rounded-lg shrink-0 select-none shadow-xs">
              <Cpu size={16} />
            </div>
            <div className="space-y-1 text-xs">
              <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted block select-none">Recommended next action</span>
              <p className="text-text-primary font-semibold">Inspect packet flows</p>
            </div>
          </div>

          {/* Section 3: Confidence */}
          <div className="flex gap-3 items-start border-b border-border-subtle/50 pb-4">
            <div className="p-1.5 bg-status-warning-bg/15 text-[#f59e0b] border border-[#f59e0b]/20 rounded-lg shrink-0 select-none">
              <ShieldCheck size={16} />
            </div>
            <div className="space-y-1.5 text-xs">
              <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted block select-none">Confidence</span>
              <span className="inline-block px-2.5 py-0.5 bg-status-warning-bg text-status-warning border border-status-warning/15 font-semibold rounded text-[10px] uppercase tracking-wider select-none">
                Moderate
              </span>
            </div>
          </div>

          {/* Section 4: Report readiness */}
          <div className="flex gap-3 items-start border-b border-border-subtle/50 pb-4">
            <div className="p-1.5 bg-status-success text-white rounded-lg shrink-0 select-none shadow-xs">
              <CheckCircle2 size={16} />
            </div>
            <div className="space-y-1.5 text-xs">
              <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted block select-none">Report readiness</span>
              <span className="inline-block px-2.5 py-0.5 bg-status-success-bg text-status-success border border-status-success/15 font-semibold rounded text-[10px] select-none">
                Draft can be generated
              </span>
            </div>
          </div>

          {/* Section 5: Limitations */}
          <div className="flex gap-3 items-start border-b border-border-subtle/50 pb-4">
            <div className="p-1.5 bg-surface-muted border border-border-subtle text-text-muted rounded-lg shrink-0 select-none">
              <AlertTriangle size={16} />
            </div>
            <div className="space-y-1 text-xs">
              <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted block select-none">Limitations</span>
              <p className="text-text-muted leading-relaxed font-normal">
                Demo decoder, full binary decoding pending production parser service.
              </p>
            </div>
          </div>

          {/* Section 6: Next analyst actions */}
          <div className="space-y-3 pt-1">
            <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted block select-none">Next analyst actions</span>
            
            <div className="space-y-2">
              <div 
                onClick={() => onNavigate('flows')}
                className="flex items-start gap-3 p-2 hover:bg-surface-muted/20 rounded-lg cursor-pointer transition-colors group"
              >
                <div className="w-4 h-4 rounded-full border border-border-strong flex items-center justify-center shrink-0 mt-0.5 text-text-muted group-hover:border-accent-primary group-hover:text-accent-primary transition-colors select-none">
                  <span className="w-1.5 h-1.5 rounded-full bg-transparent group-hover:bg-accent-primary transition-colors" />
                </div>
                <div className="space-y-0.5">
                  <p className="font-semibold text-text-primary text-xs group-hover:text-accent-primary transition-colors">Inspect packet flows</p>
                  <p className="text-[10px] text-text-muted font-normal">Review conversations and payloads.</p>
                </div>
              </div>

              <div 
                onClick={() => onNavigate('signals')}
                className="flex items-start gap-3 p-2 hover:bg-surface-muted/20 rounded-lg cursor-pointer transition-colors group"
              >
                <div className="w-4 h-4 rounded-full border border-border-strong flex items-center justify-center shrink-0 mt-0.5 text-text-muted group-hover:border-accent-primary group-hover:text-accent-primary transition-colors select-none">
                  <span className="w-1.5 h-1.5 rounded-full bg-transparent group-hover:bg-accent-primary transition-colors" />
                </div>
                <div className="space-y-0.5">
                  <p className="font-semibold text-text-primary text-xs group-hover:text-accent-primary transition-colors">Review signals & observations</p>
                  <p className="text-[10px] text-text-muted font-normal">Investigate and triage all flagged signals.</p>
                </div>
              </div>

              <div 
                onClick={() => onNavigate('ai')}
                className="flex items-start gap-3 p-2 hover:bg-surface-muted/20 rounded-lg cursor-pointer transition-colors group"
              >
                <div className="w-4 h-4 rounded-full border border-border-strong flex items-center justify-center shrink-0 mt-0.5 text-text-muted group-hover:border-accent-primary group-hover:text-accent-primary transition-colors select-none">
                  <span className="w-1.5 h-1.5 rounded-full bg-transparent group-hover:bg-accent-primary transition-colors" />
                </div>
                <div className="space-y-0.5">
                  <p className="font-semibold text-text-primary text-xs group-hover:text-accent-primary transition-colors">Generate AI analyst memo</p>
                  <p className="text-[10px] text-text-muted font-normal">Create a memo with key findings.</p>
                </div>
              </div>
            </div>
          </div>

          {/* Action Button */}
          <div className="pt-2">
            <button
              onClick={() => onNavigate('ai')}
              className="w-full py-2 bg-transparent hover:bg-accent-soft border border-accent-primary text-accent-primary hover:text-accent-primary-hover font-semibold rounded-lg text-xs transition-all flex items-center justify-center gap-1.5 cursor-pointer shadow-sm animate-pulse"
            >
              <FileText size={13} />
              Open AI analyst memo
            </button>
          </div>

        </div>
      </div>

      </div>
    </div>
  );
}
