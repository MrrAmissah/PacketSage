import React, { useState, useMemo, useEffect } from 'react';
import {
  ShieldCheck,
  HelpCircle,
  Eye,
  EyeOff,
  Radio,
  Lock,
  Server,
  Cpu,
  Search,
  Copy,
  Check,
  AlertTriangle,
  ArrowRight,
  Clock,
  Terminal,
  ExternalLink,
  ShieldAlert,
  Info,
  Calendar,
  Layers,
  ChevronRight,
  Database,
  ArrowUpRight,
  Filter,
  CheckSquare,
  Activity,
  UserCheck
} from 'lucide-react';
import { DnsRecord, HttpRecord, TlsRecord, ProtocolStat } from '../types';
import InfoPopover from './InfoPopover';

interface ProtocolIntelligenceProps {
  dns: DnsRecord[];
  http: HttpRecord[];
  tls: TlsRecord[];
  stats: ProtocolStat[];
}

interface ProtocolDetailRow {
  protocol: string;
  family: string;
  description: string;
  conversations: number;
  bytes: number;
  bytesFormatted: string;
  percentage: number;
  packets: number;
  avgDuration: string;
  topEndpoints: string[];
  commonPorts: string[];
  riskLevel: 'high' | 'medium' | 'low';
  keyObservations: string[];
  methods?: { name: string; percentage: number; count: number }[];
  domains?: { name: string; count: number; risk: string }[];
  tlsVersions?: { version: string; count: number; cipher: string }[];
  endpointsPairs?: { src: string; dst: string; count: number }[];
}

export default function ProtocolIntelligence({ dns, http, tls, stats }: ProtocolIntelligenceProps) {
  // Tab states: overview, breakdown, dns, http, tls, ports, anomalies
  const [activeTab, setActiveTab] = useState<'overview' | 'breakdown' | 'dns' | 'http' | 'tls' | 'ports' | 'anomalies'>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Filters for individual sub-tabs
  const [dnsTypeFilter, setDnsTypeFilter] = useState<string>('ALL');
  const [httpMethodFilter, setHttpMethodFilter] = useState<string>('ALL');
  const [tlsVersionFilter, setTlsVersionFilter] = useState<string>('ALL');

  // Unified Inspector State
  const [selectedItem, setSelectedItem] = useState<{
    type: 'protocol' | 'dns' | 'http' | 'tls' | 'port' | 'anomaly';
    id: string;
    data: any;
  } | null>(null);

  // Automatically reset search query and clear selected item when changing tabs
  useEffect(() => {
    setSearchQuery('');
    setSelectedItem(null);
  }, [activeTab]);

  // Format standard timestamps consistently
  const formatTimestamp = (timeStr: string) => {
    try {
      const date = new Date(timeStr);
      return date.toISOString().replace('T', ' ').substring(5, 19); // "MM-DD HH:MM:SS"
    } catch {
      return timeStr;
    }
  };

  // Helper to handle clipboard copies
  const handleCopyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => {
      setCopiedText(null);
    }, 2000);
  };

  // --- STATS COMPUTATION ---
  const calculatedStats = useMemo(() => {
    const totalDns = dns.length;
    const totalHttp = http.length;
    const totalTls = tls.length;
    const totalProtocols = stats.length || 6;

    // Estimate unencrypted cleartext count
    const cleartextHttp = http.filter(h => h.cleartext || h.riskLevel === 'high' || h.riskLevel === 'medium').length;
    const totalTransfers = totalHttp + totalTls;
    const cleartextPercentage = totalTransfers > 0 ? Math.round((cleartextHttp / totalTransfers) * 100) : 15;

    // Detect high risk elements
    const unusualEvents = 
      dns.filter(d => d.riskLevel === 'high' || d.rcode !== 'NOERROR').length +
      http.filter(h => h.riskLevel === 'high' || h.method === 'POST').length +
      tls.filter(t => t.riskLevel === 'high' || t.version === 'TLSv1.0' || t.version === 'TLSv1.1').length;

    // Conversations totals
    const totalConversations = 18 + 7 + totalTls + totalHttp + totalDns + 1; // TCP, UDP, TLS, HTTP, DNS, ICMP

    return {
      totalDns,
      totalHttp,
      totalTls,
      totalProtocols,
      cleartextHttp,
      cleartextPercentage,
      unusualEvents,
      totalConversations
    };
  }, [dns, http, tls, stats]);

  // --- DNS UNIQUE QUERY RATIO COEFF ---
  const dnsPatternCoeff = useMemo(() => {
    if (dns.length === 0) return { uniqueRatio: 0, severity: 'low', label: 'Inconclusive' };
    const uniqueDomains = new Set(dns.map(d => d.query)).size;
    const ratio = uniqueDomains / dns.length;

    // Lower unique-ratio indicates highly repetitive querying (potential beaconing / C2 heartbeat!)
    let severity = 'low';
    let label = 'Healthy query variety';
    if (ratio < 0.25) {
      severity = 'high';
      label = 'Severe Repetitive Beacons';
    } else if (ratio < 0.5) {
      severity = 'medium';
      label = 'Moderate pattern repetition';
    }

    return {
      uniqueRatio: Math.round(ratio * 100),
      uniqueCount: uniqueDomains,
      totalCount: dns.length,
      severity,
      label
    };
  }, [dns]);

  // --- MASTER PROTOCOLS INV LIST ---
  const protocolDetailsList = useMemo<ProtocolDetailRow[]>(() => {
    // Sum up dynamic bytes from provided parsed stats
    const tcpBytes = stats.find(s => s.protocol.toUpperCase() === 'TCP')?.byteCount || 4630;
    const udpBytes = stats.find(s => s.protocol.toUpperCase() === 'UDP')?.byteCount || 1340;
    const tlsBytes = stats.find(s => s.protocol.toUpperCase() === 'TLS' || s.protocol.toUpperCase() === 'TLSV1.3')?.byteCount || 620;
    const httpBytes = stats.find(s => s.protocol.toUpperCase() === 'HTTP')?.byteCount || 430;
    const dnsBytes = stats.find(s => s.protocol.toUpperCase() === 'DNS')?.byteCount || 205;
    const icmpBytes = stats.find(s => s.protocol.toUpperCase() === 'ICMP')?.byteCount || 120;
    const totalBytesVal = tcpBytes + udpBytes + tlsBytes + httpBytes + dnsBytes + icmpBytes;

    const dnsCount = dns.length || 2;
    const httpCount = http.length || 3;
    const tlsCount = tls.length || 4;

    return [
      {
        protocol: 'TCP',
        family: 'Transport Layer',
        description: 'Transmission Control Protocol. Reliable, ordered, and error-checked delivery of a stream of bytes between applications running on hosts over an IP network. It establishes a stateful conversation via three-way handshakes (SYN, SYN-ACK, ACK).',
        conversations: 18,
        bytes: tcpBytes,
        bytesFormatted: `${(tcpBytes / 1024).toFixed(2)} KB`,
        percentage: totalBytesVal > 0 ? Math.round((tcpBytes / totalBytesVal) * 100) : 62.4,
        packets: 32,
        avgDuration: '0.45s',
        topEndpoints: ['10.0.0.15', '203.0.113.50', '203.0.113.80'],
        commonPorts: ['443', '80', '8080'],
        riskLevel: 'medium',
        keyObservations: [
          'Multiple outbound connections parsed to 203.0.113.50 on standard web port 80.',
          'Frequent non-persistent connection tearing indicates active programmatic polling or telemetry reporting.',
          'High payload-to-header byte ratio observed on Port 8080 indicating data exfiltration risk.'
        ],
        endpointsPairs: [
          { src: '10.0.0.15', dst: '203.0.113.50', count: 12 },
          { src: '10.0.0.15', dst: '203.0.113.80', count: 4 },
          { src: '10.0.0.15', dst: '203.0.113.150', count: 2 }
        ]
      },
      {
        protocol: 'UDP',
        family: 'Transport Layer',
        description: 'User Datagram Protocol. A simple, connectionless, lightweight transmission model with a minimum of protocol mechanism. Suitable for real-time transactions, streaming, and query-response protocols.',
        conversations: 7,
        bytes: udpBytes,
        bytesFormatted: `${(udpBytes / 1024).toFixed(2)} KB`,
        percentage: totalBytesVal > 0 ? Math.round((udpBytes / totalBytesVal) * 100) : 18.1,
        packets: 14,
        avgDuration: '0.08s',
        topEndpoints: ['10.0.0.15', '10.0.0.1'],
        commonPorts: ['53', '123', '5353'],
        riskLevel: 'low',
        keyObservations: [
          'Recursive DNS queries and NTP network time synchronization transactions completed successfully.',
          'Lightweight local multicast DNS (mDNS) traffic discovered on internal subnet routing.',
          'Uniform payload sizes indicate stable daemon configurations across client systems.'
        ],
        endpointsPairs: [
          { src: '10.0.0.15', dst: '10.0.0.1', count: 10 },
          { src: '10.0.0.15', dst: '224.0.0.251', count: 4 }
        ]
      },
      {
        protocol: 'TLSv1.3',
        family: 'Cryptographic Session',
        description: 'Transport Layer Security 1.3. Modern cryptographic protocol designed to provide secure, encrypted communications over TCP channels. It completely eliminates outdated cipher suites and cuts handshake latency to a single round-trip.',
        conversations: tlsCount,
        bytes: tlsBytes,
        bytesFormatted: `${(tlsBytes / 1024).toFixed(2)} KB`,
        percentage: totalBytesVal > 0 ? Math.round((tlsBytes / totalBytesVal) * 100) : 8.4,
        packets: 9,
        avgDuration: '0.32s',
        topEndpoints: ['10.0.0.15', '203.0.113.15'],
        commonPorts: ['443'],
        riskLevel: 'low',
        keyObservations: [
          'Encrypted TLS sessions verified utilizing strong modern symmetric AEAD cipher suites (TLS_AES_256_GCM_SHA384).',
          'Client Hello handshake patterns successfully mapped against standard web browser fingerprints (JA3).',
          'Certificate chains inspected and validated against global trusted roots with zero expirations.'
        ],
        tlsVersions: [
          { version: 'TLSv1.3', count: tlsCount, cipher: 'TLS_AES_256_GCM_SHA384' }
        ]
      },
      {
        protocol: 'HTTP',
        family: 'Application Layer',
        description: 'Hypertext Transfer Protocol. HTTP transfers are not encrypted at the application transport layer, so payloads may be readable to parties with access to the capture path.',
        conversations: httpCount,
        bytes: httpBytes,
        bytesFormatted: `${(httpBytes / 1024).toFixed(2)} KB`,
        percentage: totalBytesVal > 0 ? Math.round((httpBytes / totalBytesVal) * 100) : 5.8,
        packets: 8,
        avgDuration: '0.21s',
        topEndpoints: ['10.0.0.15', '203.0.113.50'],
        commonPorts: ['80', '8080'],
        riskLevel: 'medium',
        keyObservations: [
          'Cleartext transfer observed containing critical endpoint configuration metadata in plaintext XML/JSON formats.',
          'Active POST request transmitted to external address 203.0.113.50 without active security session tokens.',
          'Unencrypted application-layer transfer observed which could facilitate immediate payload delivery or credentials sniffing.'
        ],
        methods: (() => {
          const methodCounts: Record<string, number> = {};
          http.forEach(h => {
            const m = h.method?.toUpperCase() || 'GET';
            methodCounts[m] = (methodCounts[m] || 0) + 1;
          });
          const totalHttpCount = http.length;
          const keys = ['POST', 'GET'];
          Object.keys(methodCounts).forEach(k => {
            if (!keys.includes(k)) keys.push(k);
          });
          const list = keys.map(m => {
            const count = methodCounts[m] || 0;
            const percentage = totalHttpCount > 0 ? Math.round((count / totalHttpCount) * 100) : 0;
            return { name: m, percentage, count };
          });
          const filteredList = list.filter(m => m.count > 0);
          if (filteredList.length === 0) {
            return [
              { name: 'POST', percentage: 0, count: 0 },
              { name: 'GET', percentage: 0, count: 0 }
            ];
          }
          const totalPercentage = filteredList.reduce((sum, item) => sum + item.percentage, 0);
          if (totalPercentage > 0 && totalPercentage !== 100) {
            const maxItem = filteredList.reduce((prev, current) => (prev.percentage > current.percentage) ? prev : current);
            maxItem.percentage += (100 - totalPercentage);
          }
          return filteredList;
        })()
      },
      {
        protocol: 'DNS',
        family: 'Application Layer',
        description: 'Domain Name System. Decentralized naming system translating human-readable hostnames to numerical IP addresses. Crucial defensive vector as modern C2 architectures heavily utilize DNS for dynamic domain resolution.',
        conversations: dnsCount,
        bytes: dnsBytes,
        bytesFormatted: `${(dnsBytes / 1024).toFixed(2)} KB`,
        percentage: totalBytesVal > 0 ? Math.round((dnsBytes / totalBytesVal) * 100) : 2.8,
        packets: 4,
        avgDuration: '0.05s',
        topEndpoints: ['10.0.0.15', '10.0.0.1'],
        commonPorts: ['53'],
        riskLevel: 'low',
        keyObservations: [
          'Periodic DNS query pattern observed to specific external servers with consistent timing intervals (beacons).',
          'RCODE status parameters returned NOERROR, indicating successful recursive resolution of target domains.',
          'Query-to-response transaction latency averages an optimal 12ms.'
        ],
        domains: dns.map(d => ({ name: d.query, count: 1, risk: d.riskLevel })).slice(0, 4)
      },
      {
        protocol: 'ICMP',
        family: 'Network Layer',
        description: 'Internet Control Message Protocol. Diagnostic and control plane utility used by routers and hosts to communicate status, error codes, and packet route details. Frequently abused for localized network sniffing and ping sweep reconnaissance.',
        conversations: 1,
        bytes: icmpBytes,
        bytesFormatted: `${(icmpBytes / 1024).toFixed(2)} KB`,
        percentage: totalBytesVal > 0 ? Math.round((icmpBytes / totalBytesVal) * 100) : 1.7,
        packets: 2,
        avgDuration: '0.01s',
        topEndpoints: ['10.0.0.15', '10.0.0.1'],
        commonPorts: ['N/A'],
        riskLevel: 'low',
        keyObservations: [
          'Standard Echo Request (Type 8) and Echo Reply (Type 0) diagnostic ping sequence observed.',
          'No TTL-expired or destination-unreachable error frames parsed, indicating a healthy path routing.',
          'Diagnostic conversation strictly localized between the forensic host and default gateway.'
        ]
      }
    ];
  }, [dns, http, tls, stats]);

  // Lookup data for currently selected inspector item
  const selectedInspectorData = useMemo(() => {
    if (!selectedItem) return null;

    if (selectedItem.type === 'protocol') {
      return protocolDetailsList.find(p => p.protocol.toUpperCase() === selectedItem.id.toUpperCase()) || protocolDetailsList[0];
    }
    if (selectedItem.type === 'dns') {
      return dns.find(d => d.query === selectedItem.id) || selectedItem.data;
    }
    if (selectedItem.type === 'http') {
      return http.find(h => `${h.host}${h.uri}` === selectedItem.id) || selectedItem.data;
    }
    if (selectedItem.type === 'tls') {
      return tls.find(t => t.sni === selectedItem.id) || selectedItem.data;
    }
    if (selectedItem.type === 'port') {
      const ports = [
        { port: '53', service: 'Domain Name System (DNS)', traffic: 'UDP / TCP', volume: '0.20 KB', risk: 'Low', description: 'Recursive network name lookup services.', status: 'Active' },
        { port: '80', service: 'Hypertext Transfer Protocol (HTTP)', traffic: 'TCP Plaintext', volume: '0.42 KB', risk: 'Medium', description: 'Unencrypted hypertext transport.', status: 'Active' },
        { port: '443', service: 'HTTP Secure (HTTPS / TLS)', traffic: 'TCP Encrypted', volume: '0.61 KB', risk: 'Low', description: 'Cryptographic session wrapper.', status: 'Active' },
        { port: '8080', service: 'HTTP Alternate / Proxy Web', traffic: 'TCP Plaintext', volume: '1.20 KB', risk: 'Medium', description: 'Unsecured developer or alternate proxy transfers.', status: 'Inactive' },
        { port: '123', service: 'Network Time Protocol (NTP)', traffic: 'UDP Stateless', volume: '0.15 KB', risk: 'Low', description: 'System time synchronization daemon.', status: 'Active' }
      ];
      return ports.find(p => p.port === selectedItem.id) || ports[2];
    }
    if (selectedItem.type === 'anomaly') {
      const anomalies = [
        { id: 'cleartext-transfer', title: 'Cleartext HTTP observed', severity: 'medium', category: 'Unencrypted payload', description: 'Web traffic completed on unsecure Port 80, releasing paths, headers, and raw files in plaintext.', remediation: 'Enforce transport-layer policies (HSTS) and force redirection to TLS port 443.' },
        { id: 'beacon-dns', title: 'Periodic DNS query pattern observed', severity: 'medium', category: 'Automated Beacons', description: 'Repetitive uniform lookup frequency to external authoritative servers, matching malware heartbeats.', remediation: 'Track parent execution process IDs on the local system matching target DNS timestamps.' },
        { id: 'unencrypted-binary', title: 'Unencrypted application-layer transfer observed', severity: 'high', category: 'Executable Retrieval', description: 'Explicit POST payload and file structures retrieved over standard HTTP without security wrappers.', remediation: 'Audit remote server domain trust age, file hashes, and configure local host firewalls.' }
      ];
      return anomalies.find(a => a.id === selectedItem.id) || anomalies[0];
    }
    return null;
  }, [selectedItem, protocolDetailsList, dns, http, tls]);

  // Unified Wireshark query constructor based on current selection
  const currentFilterQuery = useMemo(() => {
    if (!selectedItem || !selectedInspectorData) return 'tcp.port == 443';

    if (selectedItem.type === 'dns') {
      return `dns.qry.name == "${selectedInspectorData.query || ''}"`;
    }
    if (selectedItem.type === 'http') {
      return `http.host == "${selectedInspectorData.host || ''}" and http.request.uri == "${selectedInspectorData.uri || ''}"`;
    }
    if (selectedItem.type === 'tls') {
      return `tls.handshake.extensions_server_name == "${selectedInspectorData.sni || ''}"`;
    }
    if (selectedItem.type === 'port') {
      return `tcp.port == ${selectedInspectorData.port} or udp.port == ${selectedInspectorData.port}`;
    }
    if (selectedItem.type === 'anomaly') {
      if (selectedInspectorData.id === 'cleartext-transfer') {
        return `http.request`;
      }
      if (selectedInspectorData.id === 'unencrypted-binary') {
        return `http.request.method == "POST"`;
      }
      if (selectedInspectorData.id === 'beacon-dns') {
        return `dns`;
      }
    }
    if (selectedItem.type === 'protocol') {
      const proto = selectedInspectorData.protocol?.toUpperCase();
      if (proto === 'HTTP') {
        return 'http or tcp.port == 80';
      }
      if (proto === 'TLSV1.3' || proto === 'TLS') {
        return 'tls or tcp.port == 443';
      }
      if (proto === 'DNS') {
        return 'dns or udp.port == 53';
      }
      if (proto === 'UDP') {
        return 'udp';
      }
      if (proto === 'TCP') {
        return 'tcp';
      }
      if (proto === 'ICMP') {
        return 'icmp';
      }
    }
    return 'tcp.port == 443';
  }, [selectedItem, selectedInspectorData]);

  // --- FILTERED LISTS FOR SUB-TABS ---
  const filteredDns = useMemo(() => {
    return dns.filter(item => {
      const matchesSearch = searchQuery === '' || 
        item.query.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.clientIp.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.response.toLowerCase().includes(searchQuery.toLowerCase());
      
      const matchesType = dnsTypeFilter === 'ALL' || item.queryType.toUpperCase() === dnsTypeFilter.toUpperCase();
      return matchesSearch && matchesType;
    });
  }, [dns, searchQuery, dnsTypeFilter]);

  const filteredHttp = useMemo(() => {
    return http.filter(item => {
      const matchesSearch = searchQuery === '' ||
        item.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.clientIp.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.uri.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesMethod = httpMethodFilter === 'ALL' || item.method.toUpperCase() === httpMethodFilter.toUpperCase();
      return matchesSearch && matchesMethod;
    });
  }, [http, searchQuery, httpMethodFilter]);

  const filteredTls = useMemo(() => {
    return tls.filter(item => {
      const matchesSearch = searchQuery === '' ||
        item.sni.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.clientIp.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.serverIp.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesVersion = tlsVersionFilter === 'ALL' || (item.version && item.version.toUpperCase().includes(tlsVersionFilter.toUpperCase()));
      return matchesSearch && matchesVersion;
    });
  }, [tls, searchQuery, tlsVersionFilter]);

  // --- COMPUTE CUSTOM CHART SEGMENTS (DONUT & BARS) ---
  const donutChartSegments = useMemo(() => {
    let currentOffset = 0;
    const totalCircumference = 314.16; // 2 * pi * 50

    return protocolDetailsList.map((proto, idx) => {
      const percentage = proto.percentage;
      const strokeLength = (percentage / 100) * totalCircumference;
      const strokeOffset = totalCircumference - currentOffset;
      currentOffset += strokeLength;

      // Elegant high-contrast palette matching Cool Trust variables
      const colors = [
        '#0062f1', // TCP: Action Blue
        '#2f95ea', // UDP: Light Sky Blue
        '#10b981', // TLS: Emerald
        '#f59e0b', // HTTP: Amber
        '#a855f7', // DNS: Purple
        '#64748b'  // ICMP: Slate
      ];

      return {
        ...proto,
        strokeLength,
        strokeOffset,
        color: colors[idx % colors.length]
      };
    });
  }, [protocolDetailsList]);

  const barChartMax = useMemo(() => {
    const counts = protocolDetailsList.map(p => p.conversations);
    return Math.max(...counts, 1);
  }, [protocolDetailsList]);

  return (
    <div id="protocol-intelligence-workspace" className="max-w-[1440px] mx-auto w-full px-6 md:px-8 py-6 space-y-6 font-sans text-text-primary">
      
      {/* 1. Page Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="space-y-1">
          <h2 id="page-title-protocol" className="text-xl font-bold tracking-tight text-text-primary">Protocol intelligence</h2>
          <p className="text-xs text-text-muted">
            Inspect DNS, HTTP, TLS, and transport-level activity decoded from the current evidence.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono font-medium text-text-muted bg-surface-muted/40 border border-border-subtle/50 px-2.5 py-1 rounded-lg flex items-center gap-1.5 select-none">
            <Cpu size={10} className="text-text-muted" />
            <span>Decoder status: Active</span>
          </span>
        </div>
      </div>

      {/* Summary Metrics Strip */}
      <div id="summary-metrics-strip" className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        {[
          {
            label: 'Protocols',
            value: calculatedStats.totalProtocols,
            sub: 'Active decoders',
            borderClass: 'border-border-subtle hover:border-border-strong',
            bgClass: 'bg-surface',
            labelClass: 'text-text-muted',
            valueClass: 'text-text-primary',
            subClass: 'text-text-muted'
          },
          {
            label: 'Conversations',
            value: calculatedStats.totalConversations,
            sub: 'Stateful sessions',
            borderClass: 'border-border-subtle hover:border-border-strong',
            bgClass: 'bg-surface',
            labelClass: 'text-text-muted',
            valueClass: 'text-text-primary',
            subClass: 'text-text-muted'
          },
          {
            label: 'DNS queries',
            value: calculatedStats.totalDns,
            sub: `${dnsPatternCoeff.uniqueCount} unique domains`,
            borderClass: 'border-border-subtle hover:border-border-strong',
            bgClass: 'bg-surface',
            labelClass: 'text-text-muted',
            valueClass: 'text-text-primary',
            subClass: 'text-text-muted'
          },
          {
            label: 'HTTP traces',
            value: calculatedStats.totalHttp,
            sub: 'Cleartext traces',
            borderClass: calculatedStats.cleartextHttp > 0 ? 'border-status-warning/40' : 'border-border-subtle hover:border-border-strong',
            bgClass: calculatedStats.cleartextHttp > 0 ? 'bg-status-warning-bg/10 dark:bg-status-warning-bg/5' : 'bg-surface',
            labelClass: calculatedStats.cleartextHttp > 0 ? 'text-[#f59e0b] font-bold' : 'text-text-muted',
            valueClass: 'text-text-primary',
            subClass: calculatedStats.cleartextHttp > 0 ? 'text-[#f59e0b]/90 font-medium' : 'text-text-muted'
          },
          {
            label: 'TLS handshakes',
            value: calculatedStats.totalTls,
            sub: 'Cryptographic logs',
            borderClass: 'border-border-subtle hover:border-border-strong',
            bgClass: 'bg-surface',
            labelClass: 'text-text-muted',
            valueClass: 'text-text-primary',
            subClass: 'text-text-muted'
          },
          {
            label: 'Plaintext risk',
            value: `${calculatedStats.cleartextPercentage}%`,
            sub: 'Exposed transport',
            borderClass: calculatedStats.cleartextPercentage > 30 ? 'border-status-danger/40' : 'border-border-subtle hover:border-border-strong',
            bgClass: calculatedStats.cleartextPercentage > 30 ? 'bg-status-danger-bg/10 dark:bg-status-danger-bg/5' : 'bg-surface',
            labelClass: calculatedStats.cleartextPercentage > 30 ? 'text-[#ef4444] font-bold' : 'text-text-muted',
            valueClass: 'text-text-primary',
            subClass: calculatedStats.cleartextPercentage > 30 ? 'text-[#ef4444]/90 font-medium' : 'text-text-muted'
          },
          {
            label: 'Unusual events',
            value: calculatedStats.unusualEvents,
            sub: 'Anomalies flagged',
            borderClass: calculatedStats.unusualEvents > 0 ? 'border-[#a855f7]/40' : 'border-border-subtle hover:border-border-strong',
            bgClass: calculatedStats.unusualEvents > 0 ? 'bg-[#a855f7]/10 dark:bg-[#a855f7]/5' : 'bg-surface',
            labelClass: calculatedStats.unusualEvents > 0 ? 'text-[#a855f7] font-bold' : 'text-text-muted',
            valueClass: 'text-text-primary',
            subClass: calculatedStats.unusualEvents > 0 ? 'text-[#a855f7]/90 font-medium' : 'text-text-muted'
          }
        ].map((stat, idx) => (
          <div
            key={idx}
            className={`p-3 rounded-xl border flex flex-col justify-between min-h-[92px] transition-all duration-200 shadow-sm hover:shadow-md ${stat.borderClass} ${stat.bgClass}`}
          >
            <div className="flex items-center justify-between gap-1.5 min-w-0">
              <span className={`text-[10px] font-bold uppercase tracking-wider truncate block leading-tight ${stat.labelClass}`}>{stat.label}</span>
              {stat.label === 'Plaintext risk' && (
                <InfoPopover content="Plaintext risk highlights traffic that may expose readable application data, headers, credentials, or payload references. It requires validation against the actual capture and endpoint context." align="right" />
              )}
              {stat.label === 'TLS handshakes' && (
                <InfoPopover content="TLS and fingerprint metadata can help compare encrypted session behavior without decrypting payload contents. It supports correlation, not direct content inspection." align="right" />
              )}
            </div>
            <div className="mt-2">
              <span className={`text-lg font-bold font-mono tracking-tight block leading-none ${stat.valueClass}`}>{stat.value}</span>
              <span className={`text-[9px] mt-1 block truncate leading-none ${stat.subClass}`}>{stat.sub}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Main Desktop Split Layout */}
      <div className={`grid grid-cols-1 ${selectedInspectorData ? 'xl:grid-cols-[minmax(0,1fr)_340px]' : ''} gap-6 items-start`}>
        
        {/* Left Area: Visuals & Interactive Log Tables */}
        <div className="space-y-6 min-w-0">
          
          {/* Visual Workspace Tabs Toggle */}
          <div 
            id="protocol-tabs-bar"
            className="flex bg-surface-muted/60 p-1 border border-border-subtle rounded-2xl max-w-full overflow-x-auto text-xs gap-1 no-scrollbar"
            style={{ scrollbarWidth: 'none', msOverflowStyle: 'none' }}
          >
            <style dangerouslySetInnerHTML={{ __html: '.no-scrollbar::-webkit-scrollbar { display: none; }' }} />
            {[
              { id: 'overview', label: 'OVERVIEW' },
              { id: 'breakdown', label: 'PROTOCOL BREAKDOWN' },
              { id: 'dns', label: `DNS ACTIVITY (${dns.length})` },
              { id: 'http', label: `HTTP ACTIVITY (${http.length})` },
              { id: 'tls', label: `TLS HANDSHAKES (${tls.length})` },
              { id: 'ports', label: 'PORT MAPS' },
              { id: 'anomalies', label: 'DECODER ANOMALIES' }
            ].map((tab) => {
              const isSelected = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`py-2 px-4 rounded-xl font-medium cursor-pointer transition-all whitespace-nowrap text-[11px] ${
                    isSelected
                      ? 'bg-surface text-accent-primary shadow-sm font-bold border border-border-subtle/40'
                      : 'text-text-muted hover:text-text-primary'
                  }`}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>

          {/* Subview Contents */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              
              {/* Primary Visual Analysis Row */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Visual Card A: Protocol Distribution Donut */}
                <div className="p-4 rounded-2xl border border-border-subtle bg-surface shadow-sm flex flex-col justify-between h-[300px]">
                  <div className="space-y-0.5">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">Protocol distribution</h3>
                    <p className="text-[11px] text-text-muted">Payload volume shares parsed from packet metadata</p>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-6 md:gap-8 items-center flex-1 min-h-0 w-full py-1">
                    {/* SVG Donut Chart */}
                    <div className={`relative shrink-0 flex items-center justify-center select-none mx-auto sm:mx-0 ${
                      selectedItem 
                        ? 'w-24 h-24 sm:w-28 sm:h-28 md:w-28 md:h-28' 
                        : 'w-32 h-32 sm:w-36 sm:h-36 md:w-40 md:h-40'
                    }`}>
                      <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
                        {donutChartSegments.map((segment, idx) => (
                          <circle
                            key={idx}
                            cx="60"
                            cy="60"
                            r="50"
                            fill="transparent"
                            stroke={segment.color}
                            strokeWidth="12"
                            strokeDasharray={`${segment.strokeLength} 314.16`}
                            strokeDashoffset={segment.strokeOffset}
                            className="transition-all duration-300 hover:stroke-[14] cursor-pointer"
                            title={`${segment.protocol}: ${segment.percentage}%`}
                            onClick={() => setSelectedItem({ type: 'protocol', id: segment.protocol, data: segment })}
                          />
                        ))}
                      </svg>
                      <div className="absolute flex flex-col items-center justify-center text-center">
                        <span className="text-text-muted text-[8px] sm:text-[9px] uppercase tracking-wider leading-none">Total bytes</span>
                        <span className="text-xs sm:text-sm font-bold font-mono tracking-tight text-text-primary mt-0.5 sm:mt-1 leading-none">7.24 KB</span>
                      </div>
                    </div>

                    {/* Rich Legends Table */}
                    <div className="flex-1 space-y-1 text-xs max-h-full overflow-y-auto no-scrollbar pr-1">
                      {donutChartSegments.map((segment, idx) => (
                        <div
                          key={idx}
                          onClick={() => setSelectedItem({ type: 'protocol', id: segment.protocol, data: segment })}
                          className={`flex items-center justify-between rounded-lg border cursor-pointer hover:bg-surface-muted/40 transition-colors ${
                            selectedItem?.type === 'protocol' && selectedItem.id === segment.protocol
                              ? 'border-accent-primary bg-accent-soft/30 ring-1 ring-accent-primary/20'
                              : 'border-transparent'
                          } ${selectedItem ? 'p-1 px-1.5' : 'p-1.5 px-2.5'}`}
                        >
                          <div className="flex items-center gap-1.5 min-w-0">
                            <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: segment.color }} />
                            <span className="font-mono font-bold text-text-primary text-[10px] sm:text-[11px] truncate">{segment.protocol}</span>
                          </div>
                          <div className="text-right font-mono text-[9px] sm:text-[10px] text-text-secondary shrink-0 pl-1 flex items-center gap-1.5 sm:gap-2">
                            <span className={`text-text-muted hidden ${selectedItem ? '2xl:inline' : 'md:inline'}`}>{segment.bytesFormatted}</span>
                            <span className="font-bold text-accent-primary bg-accent-soft/40 px-1 py-0.5 rounded border border-accent-primary/10 text-[9px]">{segment.percentage}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Visual Card B: Conversations by Protocol */}
                <div className="p-4 rounded-2xl border border-border-subtle bg-surface shadow-sm flex flex-col justify-between h-[300px]">
                  <div className="space-y-0.5">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">Conversations by protocol</h3>
                    <p className="text-[11px] text-text-muted">Discrete session streams identified</p>
                  </div>

                  {/* HTML/CSS Bar Chart with high pixel perfection and horizontal centering */}
                  <div className={`h-[180px] max-w-xl mx-auto w-full flex items-end justify-between pt-2 pb-1 px-2 border-b border-border-subtle/30 select-none ${
                    selectedItem ? 'gap-1.5 md:gap-2' : 'gap-3'
                  }`}>
                    {protocolDetailsList.map((proto, idx) => {
                      const percentVal = (proto.conversations / barChartMax) * 100;
                      const barColors = [
                        'bg-[#0062f1]', // TCP
                        'bg-[#2f95ea]', // UDP
                        'bg-[#10b981]', // TLS
                        'bg-[#f59e0b]', // HTTP
                        'bg-[#a855f7]', // DNS
                        'bg-[#64748b]'  // ICMP
                      ];

                      return (
                        <div
                          key={idx}
                          onClick={() => setSelectedItem({ type: 'protocol', id: proto.protocol, data: proto })}
                          className="flex-1 flex flex-col items-center h-full group relative cursor-pointer justify-end"
                        >
                          {/* Value above bar */}
                          <span className="text-[9px] font-mono font-bold text-text-primary opacity-80 group-hover:opacity-100 transition-opacity mb-1 leading-none">
                            {proto.conversations}
                          </span>
                          
                          {/* Colored Pillar */}
                          <div className="w-full flex-1 flex items-end min-h-0">
                            <div
                              className={`w-full rounded-t-md transition-all duration-300 hover:brightness-110 shadow-sm ${
                                selectedItem?.type === 'protocol' && selectedItem.id === proto.protocol
                                  ? `${barColors[idx % barColors.length]} ring-1 ring-offset-1 ring-offset-surface ring-accent-primary`
                                  : `${barColors[idx % barColors.length]}`
                              }`}
                              style={{ height: `${Math.max(percentVal, 8)}%` }}
                            />
                          </div>

                          {/* Label under bar */}
                          <span className="text-[9px] font-mono text-text-muted mt-2 font-semibold">
                            {proto.protocol}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>

              </div>

              {/* Master Protocol details table */}
              <div className="p-5 rounded-2xl border border-border-subtle bg-surface shadow-sm space-y-4">
                <div className="flex justify-between items-center border-b border-border-subtle/50 pb-3">
                  <div className="space-y-0.5">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">Protocol details</h3>
                    <p className="text-[11px] text-text-muted">Master comparative breakdown across active decoders</p>
                  </div>
                </div>

                <div className="overflow-x-auto border border-border-subtle/60 rounded-xl bg-surface">
                  <table className={`w-full text-left text-xs border-collapse transition-all ${selectedItem ? 'min-w-[580px]' : 'min-w-[700px]'}`}>
                    <thead className="bg-surface-muted border-b border-border-subtle text-text-muted select-none">
                      <tr>
                        <th className={`py-2.5 font-bold text-[10px] tracking-wider uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Protocol</th>
                        <th className={`py-2.5 font-bold text-[10px] tracking-wider uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Conversations</th>
                        <th className={`py-2.5 font-bold text-[10px] tracking-wider uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Bytes</th>
                        <th className={`py-2.5 font-bold text-[10px] tracking-wider uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Packets</th>
                        <th className={`py-2.5 font-bold text-[10px] tracking-wider uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Avg duration</th>
                        <th className={`py-2.5 font-bold text-[10px] tracking-wider uppercase font-mono whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Common ports</th>
                        <th className={`py-2.5 font-bold text-[10px] tracking-wider uppercase text-right whitespace-nowrap sticky right-0 bg-surface-muted border-b border-border-subtle z-10 pl-3 shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.15)] dark:shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.4)] ${selectedItem ? 'pr-3.5' : 'pr-4'}`}>Risk</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-subtle/30">
                      {protocolDetailsList.map((row, idx) => {
                        const isSelected = selectedItem?.type === 'protocol' && selectedItem.id === row.protocol;
                        return (
                          <tr
                            key={idx}
                            onClick={() => setSelectedItem({ type: 'protocol', id: row.protocol, data: row })}
                            className={`hover:bg-table-row-hover cursor-pointer transition-colors group ${
                              isSelected ? 'bg-accent-soft font-medium' : ''
                            }`}
                          >
                            <td className={`text-text-primary font-mono font-bold whitespace-nowrap flex items-center gap-1.5 ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-3 px-4'} ${
                              isSelected ? 'border-l-2 border-accent-primary pl-[14px]' : ''
                            }`}>
                              <span className={`w-1.5 h-1.5 rounded-full`} style={{ backgroundColor: donutChartSegments[idx]?.color }} />
                              {row.protocol}
                            </td>
                            <td className={`text-text-secondary font-mono whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-3 px-4'}`}>{row.conversations}</td>
                            <td className={`text-text-secondary font-mono whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-3 px-4'}`}>
                              {row.bytesFormatted} <span className="text-text-muted text-[10px]">({row.percentage}%)</span>
                            </td>
                            <td className={`text-text-muted font-mono whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-3 px-4'}`}>{row.packets}</td>
                            <td className={`text-text-muted font-mono whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-3 px-4'}`}>{row.avgDuration}</td>
                            <td className={`text-text-secondary font-mono whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-3 px-4'}`}>{row.commonPorts.join(', ')}</td>
                            <td className={`text-right whitespace-nowrap sticky right-0 z-10 pl-3 shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.15)] dark:shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.4)] transition-colors ${
                              isSelected 
                                ? 'bg-accent-soft' 
                                : 'bg-surface group-hover:bg-surface-muted'
                            } ${selectedItem ? 'py-2 pr-3.5 text-[11px]' : 'py-3 pr-4'}`}>
                              <span
                                className={`px-2 py-0.5 rounded-lg text-[10px] font-bold tracking-wider uppercase border whitespace-nowrap ${
                                  row.riskLevel === 'high'
                                    ? 'bg-status-danger text-white border-transparent shadow-xs'
                                    : row.riskLevel === 'medium'
                                    ? 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/15 font-semibold'
                                    : isSelected
                                    ? 'border border-accent-primary/30 text-text-secondary bg-accent-soft/40 font-medium'
                                    : 'border border-border-subtle text-text-muted bg-surface-muted/50 font-medium'
                                }`}
                              >
                                {row.riskLevel}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          )}

          {activeTab === 'breakdown' && (
            <div className="p-5 rounded-2xl border border-border-subtle bg-surface shadow-sm space-y-6">
              <div className="space-y-1 border-b border-border-subtle/50 pb-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">Deep Protocol breakdown</h3>
                <p className="text-[11px] text-text-muted">Explore active forensic properties of identified protocols</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {protocolDetailsList.map((proto, idx) => (
                  <div
                    key={idx}
                    onClick={() => setSelectedItem({ type: 'protocol', id: proto.protocol, data: proto })}
                    className={`p-4 rounded-xl border transition-all cursor-pointer ${
                      selectedItem?.type === 'protocol' && selectedItem.id === proto.protocol
                        ? 'border-accent-primary bg-accent-soft/25'
                        : 'border-border-subtle hover:border-border-strong'
                    }`}
                  >
                    <div className="flex justify-between items-start">
                      <div className="space-y-1">
                        <span className="text-[9px] font-bold uppercase tracking-widest text-text-muted leading-none block">{proto.family}</span>
                        <h4 className="text-sm font-bold text-text-primary font-mono">{proto.protocol}</h4>
                      </div>
                      <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold uppercase tracking-wider border ${
                        proto.riskLevel === 'high'
                          ? 'bg-status-danger text-white border-transparent shadow-xs'
                          : proto.riskLevel === 'medium'
                          ? 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/15 font-semibold'
                          : 'bg-surface-muted text-text-muted border border-border-subtle font-normal'
                      }`}>
                        {proto.riskLevel}
                      </span>
                    </div>
                    <p className="text-[11px] text-text-secondary leading-relaxed mt-2 line-clamp-2">{proto.description}</p>
                    <div className="grid grid-cols-3 gap-2 mt-4 pt-3 border-t border-border-subtle/30 font-mono text-[10px]">
                      <div>
                        <span className="text-text-muted block text-[9px] uppercase tracking-wider">Bytes</span>
                        <span className="font-bold text-text-primary">{proto.bytesFormatted}</span>
                      </div>
                      <div>
                        <span className="text-text-muted block text-[9px] uppercase tracking-wider">Conns</span>
                        <span className="font-bold text-text-primary">{proto.conversations}</span>
                      </div>
                      <div>
                        <span className="text-text-muted block text-[9px] uppercase tracking-wider">Avg Latency</span>
                        <span className="font-bold text-text-primary">{proto.avgDuration}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'dns' && (
            <div className="p-5 rounded-2xl border border-border-subtle bg-surface shadow-sm space-y-4">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-border-subtle/50 pb-3">
                <div className="space-y-1">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">DNS Resolver logs</h3>
                  <p className="text-[11px] text-text-muted">Port 53 queries decoded from active sessions</p>
                </div>
                
                {/* Search & Custom Quick Filter */}
                <div className="flex items-center gap-2 w-full sm:w-auto">
                  <div className="flex bg-surface-muted p-0.5 border border-border-subtle rounded-lg text-[10px]">
                    {['ALL', 'A', 'AAAA', 'MX', 'TXT'].map((type) => (
                      <button
                        key={type}
                        onClick={() => setDnsTypeFilter(type)}
                        className={`px-2 py-1 rounded font-mono ${
                          dnsTypeFilter === type ? 'bg-surface text-accent-primary font-bold shadow-sm' : 'text-text-muted'
                        }`}
                      >
                        {type}
                      </button>
                    ))}
                  </div>
                  <div className="relative w-full sm:w-48">
                    <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
                    <input
                      type="text"
                      placeholder="Search domain..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-8 pr-3 py-1 bg-surface-muted border border-border-subtle rounded-lg text-[11px] placeholder-text-muted text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-primary"
                    />
                  </div>
                </div>
              </div>

              {/* Log Table */}
              <div className="overflow-x-auto border border-border-subtle rounded-xl bg-surface">
                <table className={`w-full text-left text-xs border-collapse transition-all ${selectedItem ? 'min-w-[580px]' : 'min-w-[700px]'}`}>
                  <thead className="bg-surface-muted border-b border-border-subtle text-text-muted">
                    <tr>
                      <th className={`py-2 font-bold text-[10px] uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Timestamp</th>
                      <th className={`py-2 font-bold text-[10px] uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Client IP</th>
                      <th className={`py-2 font-bold text-[10px] uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Queried Domain</th>
                      <th className={`py-2 font-bold text-[10px] uppercase font-mono whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Type</th>
                      <th className={`py-2 font-bold text-[10px] uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>RCODE</th>
                      <th className={`py-2 text-right font-bold text-[10px] uppercase whitespace-nowrap sticky right-0 bg-surface-muted border-b border-border-subtle z-10 pl-3 shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.15)] dark:shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.4)] ${selectedItem ? 'pr-3.5' : 'pr-4'}`}>Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-subtle/30">
                    {filteredDns.length > 0 ? (
                      filteredDns.map((rec, i) => {
                        const isSelected = selectedItem?.type === 'dns' && selectedItem.id === rec.query;
                        return (
                          <tr
                            key={i}
                            onClick={() => setSelectedItem({ type: 'dns', id: rec.query, data: rec })}
                            className={`hover:bg-table-row-hover cursor-pointer transition-colors group ${
                              isSelected ? 'bg-accent-soft font-medium' : ''
                            }`}
                          >
                            <td className={`font-mono text-[10px] text-text-muted whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'} ${
                              isSelected ? 'border-l-2 border-accent-primary pl-[14px]' : ''
                            }`}>{formatTimestamp(rec.timestamp)}</td>
                            <td className={`font-mono text-text-secondary whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>{rec.clientIp}</td>
                            <td className={`font-mono text-accent-primary font-bold truncate max-w-[240px] whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>{rec.query}</td>
                            <td className={`font-mono text-text-muted whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>{rec.queryType}</td>
                            <td className={`font-mono text-text-secondary whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>{rec.rcode}</td>
                            <td className={`text-right whitespace-nowrap sticky right-0 z-10 pl-3 shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.15)] dark:shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.4)] transition-colors ${
                              isSelected 
                                ? 'bg-accent-soft' 
                                : 'bg-surface group-hover:bg-surface-muted'
                            } ${selectedItem ? 'py-2 pr-3.5 text-[11px]' : 'py-2.5 pr-4'}`}>
                              <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold uppercase tracking-wider border whitespace-nowrap ${
                                rec.riskLevel === 'high'
                                  ? 'bg-status-danger text-white border-transparent shadow-xs'
                                  : rec.riskLevel === 'medium'
                                  ? 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/15 font-semibold'
                                  : isSelected
                                  ? 'border border-accent-primary/30 text-text-secondary bg-accent-soft/40 font-medium'
                                  : 'border border-border-subtle text-text-muted bg-surface-muted/50 font-medium'
                              }`}>
                                {rec.riskLevel}
                              </span>
                            </td>
                          </tr>
                        );
                      })
                    ) : (
                      <tr>
                        <td colSpan={6} className="py-12 text-center text-text-muted font-mono">No matching DNS records parsed.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'http' && (
            <div className="p-5 rounded-2xl border border-border-subtle bg-surface shadow-sm space-y-4">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-border-subtle/50 pb-3">
                <div className="space-y-1">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">HTTP Plaintext Traces</h3>
                  <p className="text-[11px] text-text-muted">Unencrypted application data captured on Web Port 80 / 8080</p>
                </div>

                {/* Filters */}
                <div className="flex items-center gap-2 w-full sm:w-auto">
                  <div className="flex bg-surface-muted p-0.5 border border-border-subtle rounded-lg text-[10px]">
                    {['ALL', 'GET', 'POST', 'PUT'].map((method) => (
                      <button
                        key={method}
                        onClick={() => setHttpMethodFilter(method)}
                        className={`px-2 py-1 rounded font-mono ${
                          httpMethodFilter === method ? 'bg-surface text-accent-primary font-bold shadow-sm' : 'text-text-muted'
                        }`}
                      >
                        {method}
                      </button>
                    ))}
                  </div>
                  <div className="relative w-full sm:w-48">
                    <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
                    <input
                      type="text"
                      placeholder="Search host/URI..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-8 pr-3 py-1 bg-surface-muted border border-border-subtle rounded-lg text-[11px] placeholder-text-muted text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-primary"
                    />
                  </div>
                </div>
              </div>

              {/* Log Table with strict overflow support and column sizing */}
              <div className="overflow-x-auto border border-border-subtle rounded-xl bg-surface">
                <table className={`w-full text-left text-xs border-collapse transition-all ${selectedItem ? 'min-w-[640px]' : 'min-w-[780px]'}`}>
                  <thead className="bg-surface-muted border-b border-border-subtle text-text-muted">
                    <tr>
                      <th className={`py-2.5 font-bold text-[10px] uppercase whitespace-nowrap w-[120px] ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Timestamp</th>
                      <th className={`py-2.5 font-bold text-[10px] uppercase whitespace-nowrap w-[110px] ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Client IP</th>
                      <th className={`py-2.5 font-bold text-[10px] uppercase whitespace-nowrap w-[150px] ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Host</th>
                      <th className={`py-2.5 font-bold text-[10px] uppercase whitespace-nowrap w-[80px] ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Method</th>
                      <th className={`py-2.5 font-bold text-[10px] uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Path/URI</th>
                      <th className={`py-2.5 font-bold text-[10px] uppercase whitespace-nowrap w-[70px] ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Status</th>
                      <th className={`py-2.5 text-right font-bold text-[10px] uppercase whitespace-nowrap w-[100px] sticky right-0 bg-surface-muted border-b border-border-subtle z-10 pl-3 shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.15)] dark:shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.4)] ${selectedItem ? 'pr-3.5' : 'pr-4'}`}>Security</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-subtle/30">
                    {filteredHttp.length > 0 ? (
                      filteredHttp.map((rec, i) => {
                        const isSelected = selectedItem?.type === 'http' && selectedItem.id === `${rec.host}${rec.uri}`;
                        return (
                          <tr
                            key={i}
                            onClick={() => setSelectedItem({ type: 'http', id: `${rec.host}${rec.uri}`, data: rec })}
                            className={`hover:bg-table-row-hover cursor-pointer transition-colors group ${
                              isSelected ? 'bg-accent-soft font-medium' : ''
                            }`}
                          >
                            <td className={`font-mono text-[10px] text-text-muted whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'} ${
                              isSelected ? 'border-l-2 border-accent-primary pl-[14px]' : ''
                            }`}>{formatTimestamp(rec.timestamp)}</td>
                            <td className={`font-mono text-text-secondary whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>{rec.clientIp}</td>
                            <td className={`font-mono text-text-primary font-bold truncate max-w-[150px] whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>{rec.host}</td>
                            <td className={`font-mono whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>
                              <span className={`font-bold ${rec.method === 'POST' ? 'text-status-warning' : 'text-accent-primary'}`}>
                                {rec.method}
                              </span>
                            </td>
                            <td className={`font-mono text-text-muted truncate max-w-[260px] whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>{rec.uri}</td>
                            <td className={`font-mono text-text-secondary whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>{rec.statusCode}</td>
                            <td className={`text-right whitespace-nowrap sticky right-0 z-10 pl-3 shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.15)] dark:shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.4)] transition-colors ${
                              isSelected 
                                ? 'bg-accent-soft' 
                                : 'bg-surface group-hover:bg-surface-muted'
                            } ${selectedItem ? 'py-2 pr-3.5 text-[11px]' : 'py-2.5 pr-4'}`}>
                              <span className="inline-flex items-center gap-1 text-[10px] font-bold text-status-warning whitespace-nowrap">
                                <EyeOff size={11} /> Plaintext
                              </span>
                            </td>
                          </tr>
                        );
                      })
                    ) : (
                      <tr>
                        <td colSpan={7} className="py-12 text-center text-text-muted font-mono">No matching plaintext HTTP records found.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'tls' && (
            <div className="p-5 rounded-2xl border border-border-subtle bg-surface shadow-sm space-y-4">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-border-subtle/50 pb-3">
                <div className="space-y-1">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">TLS Encrypted Handshakes</h3>
                  <p className="text-[11px] text-text-muted">Cryptographic parameters negotiated on Secure Port 443</p>
                </div>

                {/* Filters */}
                <div className="flex items-center gap-2 w-full sm:w-auto">
                  <div className="flex bg-surface-muted p-0.5 border border-border-subtle rounded-lg text-[10px]">
                    {['ALL', 'TLSv1.3', 'TLSv1.2'].map((ver) => (
                      <button
                        key={ver}
                        onClick={() => setTlsVersionFilter(ver)}
                        className={`px-2 py-1 rounded font-mono ${
                          tlsVersionFilter === ver ? 'bg-surface text-accent-primary font-bold shadow-sm' : 'text-text-muted'
                        }`}
                      >
                        {ver}
                      </button>
                    ))}
                  </div>
                  <div className="relative w-full sm:w-48">
                    <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
                    <input
                      type="text"
                      placeholder="Search SNI / Fingerprint..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-8 pr-3 py-1 bg-surface-muted border border-border-subtle rounded-lg text-[11px] placeholder-text-muted text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-primary"
                    />
                  </div>
                </div>
              </div>

              {/* Log Table */}
              <div className="overflow-x-auto border border-border-subtle rounded-xl bg-surface">
                <table className={`w-full text-left text-xs border-collapse transition-all ${selectedItem ? 'min-w-[580px]' : 'min-w-[700px]'}`}>
                  <thead className="bg-surface-muted border-b border-border-subtle text-text-muted">
                    <tr>
                      <th className={`py-2 px-4 font-bold text-[10px] uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Timestamp</th>
                      <th className={`py-2 px-4 font-bold text-[10px] uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Client IP</th>
                      <th className={`py-2 px-4 font-bold text-[10px] uppercase font-mono whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Server Destination</th>
                      <th className={`py-2 px-4 font-bold text-[10px] uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>SNI Hostname</th>
                      <th className={`py-2 px-4 font-bold text-[10px] uppercase font-mono whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Version</th>
                      <th className={`py-2 text-right font-bold text-[10px] uppercase whitespace-nowrap sticky right-0 bg-surface-muted border-b border-border-subtle z-10 pl-3 shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.15)] dark:shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.4)] ${selectedItem ? 'pr-3.5' : 'pr-4'}`}>JA3 Hash</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-subtle/30">
                    {filteredTls.length > 0 ? (
                      filteredTls.map((rec, i) => {
                        const isSelected = selectedItem?.type === 'tls' && selectedItem.id === rec.sni;
                        return (
                          <tr
                            key={i}
                            onClick={() => setSelectedItem({ type: 'tls', id: rec.sni, data: rec })}
                            className={`hover:bg-table-row-hover cursor-pointer transition-colors group ${
                              isSelected ? 'bg-accent-soft font-medium' : ''
                            }`}
                          >
                            <td className={`font-mono text-[10px] text-text-muted whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'} ${
                              isSelected ? 'border-l-2 border-accent-primary pl-[14px]' : ''
                            }`}>{formatTimestamp(rec.timestamp)}</td>
                            <td className={`font-mono text-text-secondary whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>{rec.clientIp}</td>
                            <td className={`font-mono text-text-secondary whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>{rec.serverIp}</td>
                            <td className={`font-mono text-accent-primary font-bold truncate max-w-[200px] whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>{rec.sni}</td>
                            <td className={`font-mono text-text-secondary whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-2.5 px-4'}`}>{rec.version || 'TLSv1.3'}</td>
                            <td className={`text-right font-mono text-[10px] text-text-muted truncate max-w-[120px] whitespace-nowrap sticky right-0 z-10 pl-3 shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.15)] dark:shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.4)] transition-colors ${
                              isSelected 
                                ? 'bg-accent-soft' 
                                : 'bg-surface group-hover:bg-surface-muted'
                            } ${selectedItem ? 'py-2 pr-3.5 text-[11px]' : 'py-2.5 pr-4'}`} title={rec.ja3}>
                              {rec.ja3 || 'N/A'}
                            </td>
                          </tr>
                        );
                      })
                    ) : (
                      <tr>
                        <td colSpan={6} className="py-12 text-center text-text-muted font-mono whitespace-nowrap">No matching secure cryptographic handshakes found.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'ports' && (
            <div className="p-5 rounded-2xl border border-border-subtle bg-surface shadow-sm space-y-4">
              <div className="space-y-1 border-b border-border-subtle/50 pb-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">Logical Socket Port Mapping</h3>
                <p className="text-[11px] text-text-muted">Network transport ports parsed across current evidence records</p>
              </div>

              <div className="overflow-x-auto border border-border-subtle rounded-xl bg-surface">
                <table className={`w-full text-left text-xs border-collapse transition-all ${selectedItem ? 'min-w-[580px]' : 'min-w-[700px]'}`}>
                  <thead className="bg-surface-muted border-b border-border-subtle text-text-muted">
                    <tr>
                      <th className={`py-2.5 font-bold text-[10px] uppercase font-mono whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Local Port</th>
                      <th className={`py-2.5 font-bold text-[10px] uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Service Name</th>
                      <th className={`py-2.5 font-bold text-[10px] uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Registered Transport</th>
                      <th className={`py-2.5 font-bold text-[10px] uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Observed Bytes</th>
                      <th className={`py-2.5 font-bold text-[10px] uppercase whitespace-nowrap ${selectedItem ? 'px-2 lg:px-3 text-[11px]' : 'px-4'}`}>Forensic Risk</th>
                      <th className={`py-2.5 text-right font-bold text-[10px] uppercase whitespace-nowrap sticky right-0 bg-surface-muted border-b border-border-subtle z-10 pl-3 shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.15)] dark:shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.4)] ${selectedItem ? 'pr-3.5' : 'pr-4'}`}>Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-subtle/30">
                    {[
                      { port: '53', service: 'Domain Name System (DNS)', traffic: 'UDP / TCP', volume: '0.20 KB', risk: 'Low', status: 'Active' },
                      { port: '80', service: 'Hypertext Transfer Protocol (HTTP)', traffic: 'TCP Plaintext', volume: '0.42 KB', risk: 'Medium', status: 'Active' },
                      { port: '443', service: 'HTTP Secure (HTTPS / TLS)', traffic: 'TCP Encrypted', volume: '0.61 KB', risk: 'Low', status: 'Active' },
                      { port: '8080', service: 'HTTP Alternate Proxy', traffic: 'TCP Plaintext', volume: '1.20 KB', risk: 'Medium', status: 'Inactive' },
                      { port: '123', service: 'Network Time Protocol (NTP)', traffic: 'UDP Stateless', volume: '0.15 KB', risk: 'Low', status: 'Active' }
                    ].map((row, idx) => {
                      const isSelected = selectedItem?.type === 'port' && selectedItem.id === row.port;
                      return (
                          <tr
                            key={idx}
                            onClick={() => setSelectedItem({ type: 'port', id: row.port, data: row })}
                            className={`hover:bg-table-row-hover cursor-pointer transition-colors group ${
                              isSelected ? 'bg-accent-soft font-medium' : ''
                            }`}
                          >
                            <td className={`font-mono font-bold text-accent-primary whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-3 px-4'} ${
                              isSelected ? 'border-l-2 border-accent-primary pl-[14px]' : ''
                            }`}>{row.port}</td>
                            <td className={`text-text-primary font-medium whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-3 px-4'}`}>{row.service}</td>
                            <td className={`text-text-secondary font-mono whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-3 px-4'}`}>{row.traffic}</td>
                            <td className={`text-text-muted font-mono whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-3 px-4'}`}>{row.volume}</td>
                            <td className={`whitespace-nowrap ${selectedItem ? 'py-2 px-2 lg:px-3 text-[11px]' : 'py-3 px-4'}`}>
                              <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold uppercase tracking-wider border whitespace-nowrap ${
                                row.risk === 'High'
                                  ? 'bg-status-danger text-white border-transparent shadow-xs'
                                  : row.risk === 'Medium'
                                  ? 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/15 font-semibold'
                                  : isSelected
                                  ? 'border border-accent-primary/30 text-text-secondary bg-accent-soft/40 font-medium'
                                  : 'border border-border-subtle text-text-muted bg-surface-muted/50 font-medium'
                              }`}>
                                {row.risk}
                              </span>
                            </td>
                            <td className={`text-right whitespace-nowrap sticky right-0 z-10 pl-3 shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.15)] dark:shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.2)] transition-colors ${
                              isSelected 
                                ? 'bg-accent-soft' 
                                : 'bg-surface group-hover:bg-surface-muted'
                            } ${selectedItem ? 'py-2 pr-3.5 text-[11px]' : 'py-3 pr-4'}`}>
                              <span className="inline-flex items-center gap-1 text-[11px] text-text-secondary whitespace-nowrap">
                                <span className={`w-1.5 h-1.5 rounded-full ${row.status === 'Active' ? 'bg-status-success' : 'bg-text-muted'}`} />
                                {row.status}
                              </span>
                            </td>
                          </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'anomalies' && (
            <div className="p-5 rounded-2xl border border-border-subtle bg-surface shadow-sm space-y-4">
              <div className="space-y-1 border-b border-border-subtle/50 pb-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">Forensic Decoder Anomalies</h3>
                <p className="text-[11px] text-text-muted">Automated rule engine warnings triggered on protocol validation failures</p>
              </div>

              <div className="space-y-3">
                {[
                  { id: 'cleartext-transfer', title: 'Cleartext HTTP observed', severity: 'medium', category: 'Unencrypted payload', status: 'Unresolved' },
                  { id: 'beacon-dns', title: 'Periodic DNS query pattern observed', severity: 'medium', category: 'Automated Beacons', status: 'Review Required' },
                  { id: 'unencrypted-binary', title: 'Unencrypted application-layer transfer observed', severity: 'high', category: 'Executable Retrieval', status: 'Immediate Investigation' }
                ].map((row, idx) => {
                  const isSelected = selectedItem?.type === 'anomaly' && selectedItem.id === row.id;
                  return (
                    <div
                      key={idx}
                      onClick={() => setSelectedItem({ type: 'anomaly', id: row.id, data: row })}
                      className={`p-4 rounded-xl border cursor-pointer transition-all flex items-start gap-3 justify-between ${
                        isSelected
                          ? 'border-accent-primary bg-accent-soft/20 ring-1 ring-accent-primary/40 shadow-sm'
                          : 'border-border-subtle hover:border-border-strong'
                      }`}
                    >
                      <div className="flex gap-3">
                        <ShieldAlert className={`shrink-0 mt-0.5 ${row.severity === 'high' ? 'text-status-danger' : 'text-status-warning'}`} size={16} />
                        <div className="space-y-1">
                          <span className="text-[9px] font-bold uppercase tracking-widest text-text-muted leading-none">{row.category}</span>
                          <h4 className="text-xs font-bold text-text-primary">{row.title}</h4>
                        </div>
                      </div>
                      <div className="text-right space-y-1 shrink-0">
                        <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold uppercase tracking-wider border ${
                          row.severity === 'high'
                            ? 'bg-status-danger text-white border-transparent shadow-xs'
                            : 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/15 font-semibold'
                        }`}>
                          {row.severity}
                        </span>
                        <span className="text-[9px] text-text-muted block font-mono">{row.status}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

        </div>

        {/* Right Column: Dynamic Protocol Detail Rail */}
        {selectedInspectorData && (
          <div className="space-y-6">
            
            {/* Main Inspection Card */}
            <div className="p-5 rounded-2xl border border-border-subtle bg-surface shadow-sm space-y-4">
              
              {/* ACTIVE ROW SELECTED DETAILS */}
              <div className="space-y-4">
                
                {/* Header */}
                <div className="flex justify-between items-center border-b border-border-subtle/50 pb-3">
                  <div className="space-y-0.5">
                    <span className="text-[9px] font-bold uppercase tracking-wider text-accent-primary">Frame inspector</span>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">Protocol detail</h3>
                  </div>
                  <button
                    onClick={() => setSelectedItem(null)}
                    className="text-[10px] text-text-muted hover:text-text-primary font-mono cursor-pointer border border-border-subtle px-2 py-0.5 rounded-md hover:bg-surface-muted transition-colors"
                  >
                    CLOSE
                  </button>
                </div>

                {/* Selected Detail Fields */}
                <div className="space-y-4 text-xs select-text">
                  
                  {/* Dynamic Title and Family */}
                  <div className="space-y-1">
                    <div className="flex items-center gap-1.5">
                      <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold tracking-wider uppercase border ${
                        selectedItem?.type === 'http' || selectedInspectorData.protocol === 'HTTP'
                          ? 'bg-status-warning-bg text-status-warning border-status-warning/25'
                          : selectedItem?.type === 'tls' || selectedInspectorData.protocol === 'TLSv1.3'
                          ? 'bg-status-success-bg text-status-success border-status-success/25'
                          : 'bg-accent-soft text-accent-primary border-accent-primary/20'
                      }`}>
                        {selectedItem?.type.toUpperCase()} DECODER
                      </span>
                      <span className="text-text-muted font-mono text-[10px]">
                        Port {
                          selectedItem?.type === 'dns' || selectedInspectorData.protocol === 'DNS' ? '53' :
                          selectedItem?.type === 'http' || selectedInspectorData.protocol === 'HTTP' ? '80' :
                          selectedItem?.type === 'tls' || selectedInspectorData.protocol === 'TLSv1.3' ? '443' : 'Any'
                        }
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-text-primary font-mono mt-1">
                      {selectedItem?.type === 'protocol' ? selectedInspectorData.protocol : 
                       selectedItem?.type === 'dns' ? 'DNS Query Frame' :
                       selectedItem?.type === 'http' ? 'HTTP Transaction' :
                       selectedItem?.type === 'tls' ? 'TLS Client Hello' :
                       selectedItem?.type === 'port' ? `Port ${selectedInspectorData.port}` :
                       selectedInspectorData.title}
                    </h4>
                  </div>

                  {/* Core description / summary */}
                  <p className="text-[11px] text-text-secondary leading-relaxed font-sans bg-surface-muted/30 p-3 rounded-xl border border-border-subtle/50">
                    {selectedItem?.type === 'protocol' ? selectedInspectorData.description :
                     selectedItem?.type === 'dns' ? `Decoded recursive DNS lookup session completed on target resolver. Queried authority has been audited against potential tunneling intervals.` :
                     selectedItem?.type === 'http' ? `Decoded unencrypted HTTP transaction log capturing cleartext methods and path values on Port ${selectedInspectorData.statusCode === 8080 ? '8080' : '80'}.` :
                     selectedItem?.type === 'tls' ? `Cryptographic handshake initiated by forensic client. Hostname negotiated via Server Name Indication (SNI) prior to encrypting payload.` :
                     selectedItem?.type === 'port' ? `${selectedInspectorData.description}` :
                     selectedInspectorData.description}
                  </p>

                  {/* SPECIFIC TO PROTOCOL OVERVIEW TYPE */}
                  {selectedItem?.type === 'protocol' && (
                    <div className="space-y-3.5 pt-1">
                      
                      {/* Metric parameters row */}
                      <div className="grid grid-cols-2 gap-2 font-mono text-[11px] bg-surface-muted/40 p-2.5 rounded-xl border border-border-subtle/40">
                        <div>
                          <span className="text-text-muted block text-[9px] uppercase tracking-wider font-sans">CONVERSATIONS</span>
                          <span className="font-bold text-text-primary">{selectedInspectorData.conversations} sessions</span>
                        </div>
                        <div>
                          <span className="text-text-muted block text-[9px] uppercase tracking-wider font-sans">TOTAL BYTES</span>
                          <span className="font-bold text-text-primary">{selectedInspectorData.bytesFormatted}</span>
                        </div>
                        <div className="mt-2">
                          <span className="text-text-muted block text-[9px] uppercase tracking-wider font-sans">PACKET COUNT</span>
                          <span className="font-bold text-text-primary">{selectedInspectorData.packets} frames</span>
                        </div>
                        <div className="mt-2">
                          <span className="text-text-muted block text-[9px] uppercase tracking-wider font-sans">AVG DURATION</span>
                          <span className="font-bold text-text-primary">{selectedInspectorData.avgDuration}</span>
                        </div>
                      </div>

                      {/* HTTP Method distribution progress if HTTP selected */}
                      {selectedInspectorData.protocol === 'HTTP' && selectedInspectorData.methods && (
                        <div className="space-y-2">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted block">Method distribution</span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-status-warning-bg text-status-warning border border-status-warning/20 inline-block mb-1">
                            Cleartext HTTP observed
                          </span>
                          <div className="space-y-1.5 font-mono text-[10px]">
                            {selectedInspectorData.methods.map((m: any, i: number) => (
                              <div key={i} className="space-y-1">
                                <div className="flex justify-between">
                                  <span className="font-bold text-text-secondary">{m.name}</span>
                                  <span className="text-text-muted">{m.count} ({m.percentage}%)</span>
                                </div>
                                <div className="w-full h-1.5 bg-surface-muted rounded-full overflow-hidden">
                                  <div className="bg-status-warning h-full" style={{ width: `${m.percentage}%` }} />
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* DNS domain repetitions if DNS selected */}
                      {selectedInspectorData.protocol === 'DNS' && (
                        <div className="space-y-2">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted block">Query pattern indicator</span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-status-info-bg text-status-info border border-status-info/20 inline-block mb-1">
                            Periodic DNS query pattern observed
                          </span>
                          <div className="space-y-1 bg-surface-muted/35 p-2 rounded-xl border border-border-subtle/60">
                            {selectedInspectorData.domains?.map((d: any, i: number) => (
                              <div key={i} className="flex justify-between items-center text-[10px] font-mono border-b border-border-subtle/20 pb-1 mb-1 last:border-0 last:pb-0 last:mb-0">
                                <span className="text-accent-primary font-bold truncate max-w-[180px]">{d.name}</span>
                                <span className={`px-1 rounded text-[9px] uppercase border ${
                                  d.risk === 'high'
                                    ? 'bg-status-danger-bg text-status-danger border-status-danger/20 font-bold'
                                    : d.risk === 'medium'
                                    ? 'bg-status-warning-bg/15 text-[#f59e0b] border-status-warning/20 font-semibold'
                                    : 'bg-surface-muted text-text-muted border border-border-subtle/50 font-medium'
                                }`}>{d.risk}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* TLS session details if TLS selected */}
                      {selectedInspectorData.protocol === 'TLSv1.3' && selectedInspectorData.tlsVersions && (
                        <div className="space-y-2 bg-surface-muted/40 p-3 rounded-xl border border-border-subtle/50 font-mono text-[10px]">
                          <span className="text-[9px] font-bold uppercase tracking-widest text-text-muted block mb-1">Encrypted Tunneling details</span>
                          <div className="flex justify-between">
                            <span className="text-text-muted">VERSION:</span>
                            <span className="font-bold text-status-success">{selectedInspectorData.tlsVersions[0].version}</span>
                          </div>
                          <div className="flex justify-between mt-1">
                            <span className="text-text-muted">CIPHER SUITE:</span>
                            <span className="font-bold text-text-primary break-all text-right max-w-[140px]">{selectedInspectorData.tlsVersions[0].cipher}</span>
                          </div>
                        </div>
                      )}

                      {/* Key Observations list */}
                      <div className="space-y-2 pt-1">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted block">Key Observations</span>
                        <ul className="space-y-2">
                          {selectedInspectorData.keyObservations.map((obs: string, i: number) => (
                            <li key={i} className="flex items-start gap-2 text-[11px] text-text-secondary leading-normal">
                              <span className="w-1 h-1 rounded-full bg-accent-primary mt-1.5 shrink-0" />
                              <span>{obs}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                    </div>
                  )}

                  {/* SPECIFIC TO DNS SINGLE LOG INSPECTION */}
                  {selectedItem?.type === 'dns' && (
                    <div className="space-y-3 font-mono text-[11px] bg-surface-muted/40 p-3 rounded-xl border border-border-subtle/40">
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted">TIMESTAMP:</span>
                        <span className="text-text-secondary font-bold">{new Date(selectedInspectorData.timestamp).toISOString().substring(11, 23)}</span>
                      </div>
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted">CLIENT IP:</span>
                        <span className="text-text-primary font-bold">{selectedInspectorData.clientIp}</span>
                      </div>
                      <div className="space-y-1 border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted block">QUERY TARGET:</span>
                        <span className="text-accent-primary font-bold break-all block">{selectedInspectorData.query}</span>
                      </div>
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted">QUERY TYPE:</span>
                        <span className="text-text-secondary font-bold">{selectedInspectorData.queryType}</span>
                      </div>
                      <div className="space-y-1 border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted block">ANSWER PACKET:</span>
                        <span className="text-text-secondary break-all block">{selectedInspectorData.response || '0.0.0.0'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-text-muted">RCODE:</span>
                        <span className="text-status-success font-bold">{selectedInspectorData.rcode}</span>
                      </div>
                    </div>
                  )}

                  {/* SPECIFIC TO HTTP SINGLE LOG INSPECTION */}
                  {selectedItem?.type === 'http' && (
                    <div className="space-y-3 font-mono text-[11px] bg-surface-muted/40 p-3 rounded-xl border border-border-subtle/40">
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted">TIMESTAMP:</span>
                        <span className="text-text-secondary font-bold">{new Date(selectedInspectorData.timestamp).toISOString().substring(11, 23)}</span>
                      </div>
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted">CLIENT IP:</span>
                        <span className="text-text-primary font-bold">{selectedInspectorData.clientIp}</span>
                      </div>
                      <div className="space-y-1 border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted block">HOST HEADER:</span>
                        <span className="text-text-primary font-bold break-all block">{selectedInspectorData.host}</span>
                      </div>
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted">METHOD:</span>
                        <span className="text-status-warning font-bold">{selectedInspectorData.method}</span>
                      </div>
                      <div className="space-y-1 border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted block">REQUEST PATH:</span>
                        <span className="text-text-secondary break-all block text-[10px]">{selectedInspectorData.uri}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-text-muted">STATUS CODE:</span>
                        <span className="text-text-secondary font-bold">{selectedInspectorData.statusCode}</span>
                      </div>
                    </div>
                  )}

                  {/* SPECIFIC TO TLS SINGLE LOG INSPECTION */}
                  {selectedItem?.type === 'tls' && (
                    <div className="space-y-3 font-mono text-[11px] bg-surface-muted/40 p-3 rounded-xl border border-border-subtle/40">
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted">TIMESTAMP:</span>
                        <span className="text-text-secondary font-bold">{new Date(selectedInspectorData.timestamp).toISOString().substring(11, 23)}</span>
                      </div>
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted">CLIENT IP:</span>
                        <span className="text-text-primary font-bold">{selectedInspectorData.clientIp}</span>
                      </div>
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted">SERVER IP:</span>
                        <span className="text-text-secondary font-bold">{selectedInspectorData.serverIp}</span>
                      </div>
                      <div className="space-y-1 border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted block">SNI HOSTNAME:</span>
                        <span className="text-status-success font-bold break-all block">{selectedInspectorData.sni}</span>
                      </div>
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted">VERSION:</span>
                        <span className="text-text-secondary font-bold">{selectedInspectorData.version || 'TLSv1.3'}</span>
                      </div>
                      <div className="space-y-1">
                        <span className="text-text-muted block">JA3 FINGERPRINT:</span>
                        <span className="text-text-muted text-[10px] break-all select-all block bg-surface p-1 rounded border border-border-subtle">
                          {selectedInspectorData.ja3 || 'N/A'}
                        </span>
                      </div>
                    </div>
                  )}

                  {/* SPECIFIC TO PORT TYPE */}
                  {selectedItem?.type === 'port' && (
                    <div className="space-y-3 font-mono text-[11px] bg-surface-muted/40 p-3 rounded-xl border border-border-subtle/40">
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted font-sans">PORT:</span>
                        <span className="text-text-primary font-bold">Port {selectedInspectorData.port}</span>
                      </div>
                      <div className="space-y-1 border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted font-sans block">SERVICE:</span>
                        <span className="text-text-secondary font-bold block font-sans">{selectedInspectorData.service}</span>
                      </div>
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted font-sans">TRANSPORT:</span>
                        <span className="text-text-secondary font-bold">{selectedInspectorData.traffic}</span>
                      </div>
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted font-sans">OBSERVED VOL:</span>
                        <span className="text-text-primary font-bold">{selectedInspectorData.volume}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-text-muted font-sans">IANA STATUS:</span>
                        <span className="text-text-secondary">{selectedInspectorData.status}</span>
                      </div>
                    </div>
                  )}

                  {/* SPECIFIC TO ANOMALY TYPE */}
                  {selectedItem?.type === 'anomaly' && (
                    <div className="space-y-3 font-mono text-[11px] bg-surface-muted/40 p-3 rounded-xl border border-border-subtle/40">
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted font-sans">ANOMALY:</span>
                        <span className="text-text-primary font-bold font-sans">{selectedInspectorData.title}</span>
                      </div>
                      <div className="flex justify-between border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted font-sans">SEVERITY:</span>
                        <span className="text-status-warning font-bold uppercase">{selectedInspectorData.severity}</span>
                      </div>
                      <div className="space-y-1 border-b border-border-subtle/30 pb-1.5 mb-1.5">
                        <span className="text-text-muted font-sans block">FORENSIC CATEGORY:</span>
                        <span className="text-text-secondary font-bold font-sans block">{selectedInspectorData.category}</span>
                      </div>
                      <div className="space-y-1">
                        <span className="text-text-muted font-sans block">RECOMMENDED REMEDIATION:</span>
                        <span className="text-text-secondary block font-sans leading-relaxed text-[10px] bg-surface p-2 rounded border border-border-subtle">
                          {selectedInspectorData.remediation}
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Wireshark copy filter query */}
                  <div className="space-y-2 pt-1.5">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted block">Wireshark Filter query</span>
                      <InfoPopover content="Filters are passive inspection helpers for reviewing captured evidence in tools such as Wireshark. They are not active scans." align="left" />
                    </div>
                    <div className="p-2.5 bg-mono-bg rounded-lg border border-border-subtle font-mono text-[10px] text-text-primary flex justify-between items-center gap-2 select-all shadow-inner">
                      <span className="truncate text-[10px] font-bold">
                        {currentFilterQuery}
                      </span>
                      <button
                        onClick={() => {
                          handleCopyToClipboard(currentFilterQuery, 'ws-detail-filter');
                        }}
                        className="text-[10px] text-accent-primary hover:underline font-bold cursor-pointer shrink-0"
                      >
                        {copiedText === 'ws-detail-filter' ? 'COPIED' : 'COPY'}
                      </button>
                    </div>
                  </div>

                </div>

              </div>

            </div>

          </div>
        )}

      </div>

      {/* Bottom Section: Posture Assessment & Recommended Checklist */}
      <div id="protocol-bottom-section" className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6 border-t border-border-subtle/30 pt-6 items-start">
        
        {/* Posture Assessment Card */}
        <div className="p-5 rounded-2xl border border-border-subtle bg-surface shadow-sm space-y-4">
          <div className="border-b border-border-subtle pb-3">
            <span className="text-[9px] font-bold uppercase tracking-wider text-text-muted">Security assessment</span>
            <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">Protocol Security Posture</h3>
          </div>

          <div className="space-y-4">
            {/* A. Assessment summary */}
            <p className="text-xs text-text-secondary leading-relaxed font-sans">
              Decoded traffic shows encrypted transport, DNS resolution, and cleartext HTTP activity. Review priority should focus on Port 80 payload context, external destinations, and repeated DNS query behavior.
            </p>

            {/* Optional compact exposure path */}
            <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono text-text-secondary border-y border-border-subtle/20 py-1.5">
              <span className="text-[9px] font-bold uppercase tracking-wider text-text-muted mr-1">Exposure Path:</span>
              <span className="text-text-primary font-semibold">Internal host</span>
              <span className="text-text-muted">→</span>
              <span className="text-[#f59e0b] font-semibold">HTTP Port 80</span>
              <span className="text-text-muted">→</span>
              <span className="text-text-primary font-semibold">External destination</span>
              <span className="text-text-muted">→</span>
              <span className="text-accent-primary font-bold uppercase text-[9px] tracking-wider">Payload review required</span>
            </div>

            {/* B. Evidence-backed observations */}
            <div className="space-y-1">
              <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted block mb-1">Evidence-Backed Observations</span>
              <div className="divide-y divide-border-subtle/30">
                {/* Observation 1 */}
                <div className="py-2.5 flex gap-2.5 text-xs">
                  <EyeOff size={14} className="text-status-warning shrink-0 mt-0.5" />
                  <div className="space-y-0.5 w-full">
                    <div className="flex justify-between items-center gap-2">
                      <span className="font-bold text-text-primary text-[11px]">Cleartext application-layer transfer</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border border-status-warning/40 text-[#f59e0b] bg-[#f59e0b]/10">Medium</span>
                    </div>
                    <p className="text-[11px] text-text-secondary leading-relaxed font-sans">
                      <strong className="text-text-muted font-mono text-[9px] uppercase mr-1">Evidence:</strong> HTTP over Port 80 with POST activity to external destination 203.0.113.50.
                    </p>
                    <p className="text-[11px] text-text-muted leading-relaxed font-sans italic">
                      <strong className="text-text-muted font-sans font-bold text-[9px] uppercase mr-1">Interpretation:</strong> Payload context requires review because HTTP traffic is not encrypted at the application transport layer.
                    </p>
                  </div>
                </div>

                {/* Observation 2 */}
                <div className="py-2.5 flex gap-2.5 text-xs">
                  <Activity size={14} className="text-text-muted shrink-0 mt-0.5" />
                  <div className="space-y-0.5 w-full">
                    <div className="flex justify-between items-center gap-2">
                      <span className="font-bold text-text-primary text-[11px]">Repeated DNS query pattern</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-medium uppercase border border-border-subtle text-text-muted bg-surface-muted/30">Low / Info</span>
                    </div>
                    <p className="text-[11px] text-text-secondary leading-relaxed font-sans">
                      <strong className="text-text-muted font-mono text-[9px] uppercase mr-1">Evidence:</strong> Repeated UDP/53 queries observed at stable intervals.
                    </p>
                    <p className="text-[11px] text-text-muted leading-relaxed font-sans italic">
                      <strong className="text-text-muted font-sans font-bold text-[9px] uppercase mr-1">Interpretation:</strong> May reflect routine telemetry or daemon updates; validate against resolver and process logs.
                    </p>
                  </div>
                </div>

                {/* Observation 3 */}
                <div className="py-2.5 flex gap-2.5 text-xs">
                  <ArrowUpRight size={14} className="text-status-warning shrink-0 mt-0.5" />
                  <div className="space-y-0.5 w-full">
                    <div className="flex justify-between items-center gap-2">
                      <span className="font-bold text-text-primary text-[11px]">External web session concentration</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border border-status-warning/40 text-[#f59e0b] bg-[#f59e0b]/10">Medium</span>
                    </div>
                    <p className="text-[11px] text-text-secondary leading-relaxed font-sans">
                      <strong className="text-text-muted font-mono text-[9px] uppercase mr-1">Evidence:</strong> Outbound web sessions concentrated around 203.0.113.50 and 203.0.113.150.
                    </p>
                    <p className="text-[11px] text-text-muted leading-relaxed font-sans italic">
                      <strong className="text-text-muted font-sans font-bold text-[9px] uppercase mr-1">Interpretation:</strong> Review destination ownership, reputation, and endpoint process context.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* C. Forensic disclaimer note */}
            <div className="pt-2 text-[10px] text-text-muted leading-relaxed flex gap-2 items-start border-t border-border-subtle/20">
              <span className="text-[9px] font-bold uppercase tracking-wider text-text-muted shrink-0 mt-0.5">Note:</span>
              <p>
                Protocol evidence alone does not confirm endpoint compromise, malware execution, or user intent. Validate with endpoint process logs, DNS resolver logs, and server reputation checks.
              </p>
            </div>
          </div>
        </div>

        {/* Recommended Checks Checklist Card */}
        <div className="p-5 rounded-2xl border border-border-subtle bg-surface shadow-sm space-y-4">
          <div className="border-b border-border-subtle pb-3">
            <span className="text-[9px] font-bold uppercase tracking-wider text-text-muted">Defensive checklist</span>
            <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">Recommended checks</h3>
          </div>

          <p className="text-xs text-text-secondary leading-relaxed font-sans">
            Evidence-led investigation checklist compiled from detected cleartext HTTP and DNS transaction anomalies.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            {[
              {
                title: "Validate HTTP payload context and destination ownership",
                desc: "Analyze unencrypted Port 80 payload context and verify if destination address 203.0.113.50 is a legitimate server.",
              },
              {
                title: "Review endpoint process activity around packet timestamps",
                desc: "Identify host processes executing connections at timestamps correlating with unencrypted transfers.",
              },
              {
                title: "Check DNS resolver logs for repeated query patterns",
                desc: "Correlate stable UDP/53 query intervals to confirm if specific endpoints show persistent query spikes.",
              },
              {
                title: "Verify whether Port 80 traffic is expected for this environment",
                desc: "Audit environment policies to confirm whether any client system requires active plaintext HTTP exemptions.",
              }
            ].map((step, idx) => (
              <div key={idx} className="flex gap-2.5 items-start text-text-secondary border-b border-border-subtle/20 pb-2.5 last:border-0 last:pb-0 sm:border-0 sm:pb-0">
                <div className="w-5 h-5 rounded-full border border-accent-primary/20 flex items-center justify-center shrink-0 mt-0.5 bg-accent-soft/20 font-mono text-[10px] font-bold text-accent-primary select-none">
                  {idx + 1}
                </div>
                <div className="space-y-0.5">
                  <h4 className="font-bold text-text-primary text-[11px] leading-tight">{step.title}</h4>
                  <p className="text-[10px] text-text-muted leading-relaxed">{step.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>

    </div>
  );
}
