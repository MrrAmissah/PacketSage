import React, { useState, useEffect, useMemo } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Search, 
  SlidersHorizontal, 
  ChevronDown, 
  ChevronLeft, 
  ChevronRight, 
  X, 
  Check, 
  AlertCircle, 
  Clipboard, 
  Info,
  ExternalLink,
  Ban,
  LoaderCircle,
  RotateCcw,
  Sparkles,
} from 'lucide-react';
import {
  DnsRecord,
  FlowSummary,
  HttpRecord,
  InvestigationAssessment,
  InvestigationEvidencePacket,
  PacketEvent,
  SignalReviewStatus,
  SuspiciousSignal,
  TlsRecord,
} from '../types';
import InfoPopover from './InfoPopover';
import InvestigationAssessmentPanel from './InvestigationAssessment';
import {
  buildInvestigationEvidencePacket,
  evidenceIds,
  validateInvestigationAssessment,
} from '../lib/investigation';
import { selectPresentedSignals } from '../lib/signalPresentation';
import { resolveRelatedFlows } from '../lib/relatedFlows';

interface SuspiciousSignalsProps {
  signals: SuspiciousSignal[];
  flows: FlowSummary[];
  events: PacketEvent[];
  dns: DnsRecord[];
  http: HttpRecord[];
  tls: TlsRecord[];
  signalStatusOverrides?: Record<string, SignalReviewStatus>;
  onNavigateToFlows: (flows: FlowSummary[]) => void;
  onUpdateSignalStatus?: (id: string, status: SignalReviewStatus, linkedIds?: string[]) => void;
}

// Rich high-fidelity signals matching the reference image layout and metadata
interface EnrichedSignal extends SuspiciousSignal {
  subtitle: string;
  confidenceScore: number;
  observedSnippet: string;
  relatedFlowsCount: number;
  firstSeenTime: string;
  status: SignalReviewStatus;
  metrics?: { label: string; value: string }[];
  flowsList?: { id?: string; src: string; dst: string; proto: string }[];
}

const EMPTY_SIGNAL_STATUS_OVERRIDES: Record<string, SignalReviewStatus> = {};

const PCAP_DEMO_SIGNALS: EnrichedSignal[] = [
  {
    id: 'sig-dns-beacon',
    title: 'Possible periodic DNS pattern',
    subtitle: 'Consistent 60s DNS queries',
    severity: 'high',
    confidence: 'high',
    confidenceScore: 72,
    category: 'Beacon-like DNS pattern',
    observedSnippet: 'd4c1f2a1.example.com',
    observedEvidence: 'Host 10.0.0.15 sent DNS queries to d4c1f2a1.example.com every ~60 seconds over a 10 minute window.',
    interpretation: 'This pattern is consistent with periodic beaconing behavior commonly used by some command and control (C2) frameworks to maintain egress persistence.',
    whatItDoesNotProve: 'Does not confirm active endpoint host compromise. The target domain resolution could be a legitimate background updater, cloud service heartbeat, or CDN sync.',
    recommendedDefensiveCheck: 'Investigate the domain owner reputation and dynamic creation details. Review DNS query logs on workstation 10.0.0.15 and correlate with outbound socket connections.',
    relatedFlowsCount: 5,
    firstSeenTime: '2024-05-21 10:12:18',
    status: 'Needs review',
    metrics: [
      { label: 'Query type', value: 'A' },
      { label: 'Total queries', value: '10' },
      { label: 'Avg interval', value: '59.8s (σ 1.2s)' },
      { label: 'First seen', value: '2024-05-21 10:12:18' },
      { label: 'Last seen', value: '2024-05-21 10:22:18' }
    ],
    flowsList: [
      { src: '10.0.0.15:52000', dst: '10.0.0.1:53', proto: 'UDP' },
      { src: '10.0.0.15:52001', dst: '10.0.0.1:53', proto: 'UDP' },
      { src: '10.0.0.15:52002', dst: '10.0.0.1:53', proto: 'UDP' },
      { src: '10.0.0.15:52003', dst: '10.0.0.1:53', proto: 'UDP' },
      { src: '10.0.0.15:52004', dst: '10.0.0.1:53', proto: 'UDP' }
    ]
  },
  {
    id: 'sig-cleartext-binary',
    title: 'Cleartext binary transfer observed',
    subtitle: 'Large file transfer over HTTP',
    severity: 'medium',
    confidence: 'medium',
    confidenceScore: 65,
    category: 'Cleartext transfer',
    observedSnippet: '203.0.113.50',
    observedEvidence: 'Unencrypted Application-layer records observed in telemetry. Host 10.0.0.15 downloaded agent.bin in cleartext over HTTP (Host: 203.0.113.50).',
    interpretation: 'Downloading executables or binary updates over unencrypted HTTP exposes systems to passive eavesdropping, spoofing, and man-in-the-middle injection.',
    whatItDoesNotProve: 'Does not guarantee the downloaded binary contains active malicious payload code or was executed. Could be an legacy in-house IT development build.',
    recommendedDefensiveCheck: 'Audit workstation software deployment policies. Check local EDR logs on host 10.0.0.15 for file execution events and match target hash on threat database.',
    relatedFlowsCount: 2,
    firstSeenTime: '2024-05-21 10:14:22',
    status: 'Needs review',
    metrics: [
      { label: 'File name', value: 'agent.bin' },
      { label: 'File size', value: '2.4 MB' },
      { label: 'Method', value: 'GET' },
      { label: 'Port', value: '80 (HTTP)' },
      { label: 'Source', value: '203.0.113.50' }
    ],
    flowsList: [
      { src: '10.0.0.15:49158', dst: '203.0.113.50:80', proto: 'TCP' },
      { src: '10.0.0.15:49159', dst: '203.0.113.50:80', proto: 'TCP' }
    ]
  },
  {
    id: 'sig-repeated-connections',
    title: 'Repeated outbound connections',
    subtitle: 'Multiple connections to same IP',
    severity: 'medium',
    confidence: 'medium',
    confidenceScore: 61,
    category: 'Repeated outbound activity',
    observedSnippet: '203.0.113.80:4444',
    observedEvidence: 'Telemetry recorded 10 successive short-duration outbound TCP connections from 10.0.0.15 to external IP 203.0.113.80 on port 4444.',
    interpretation: 'A quick sequence of short-duration TCP connections to a single external host often points to heartbeats, staging discovery, or keep-alive sockets.',
    whatItDoesNotProve: 'Does not guarantee active C2 channel communication or theft. It may be triggered by standard software polling scripts, CDN resource requests, or local API loops.',
    recommendedDefensiveCheck: 'Query external domain registry details. Review the payload headers for authorization tokens or persistent shell identifiers.',
    relatedFlowsCount: 10,
    firstSeenTime: '2024-05-21 10:11:03',
    status: 'Needs review',
    metrics: [
      { label: 'Total connections', value: '10 sessions' },
      { label: 'Target IP', value: '203.0.113.80' },
      { label: 'Dest Port', value: '4444' },
      { label: 'Handshake status', value: 'ESTABLISHED (completed)' }
    ],
    flowsList: [
      { src: '10.0.0.15:53000', dst: '203.0.113.80:4444', proto: 'TCP' },
      { src: '10.0.0.15:53001', dst: '203.0.113.80:4444', proto: 'TCP' },
      { src: '10.0.0.15:53002', dst: '203.0.113.80:4444', proto: 'TCP' }
    ]
  },
  {
    id: 'sig-unusual-host-traffic',
    title: 'Unusual source host activity',
    subtitle: 'Host generated high volume',
    severity: 'low',
    confidence: 'medium',
    confidenceScore: 48,
    category: 'Anomaly',
    observedSnippet: '10.0.0.15 generated 78% of total outbound traffic',
    observedEvidence: 'Workstation 10.0.0.15 transferred 12.5 MB of data out of the internal network, representing 78% of the packet capture volume.',
    interpretation: 'Asymmetric high-volume outbound data transfer from a single user workstation is an anomaly that suggests manual uploads, database transfers, or potential archiving.',
    whatItDoesNotProve: 'Does not prove malicious exfiltration. Standard user actions like syncing corporate OneDrive accounts, publishing developer artifacts, or video streaming cause similar patterns.',
    recommendedDefensiveCheck: 'Inspect the list of active user directories accessed by user workstation on local file servers. Compare historical average daily egress baseline.',
    relatedFlowsCount: 18,
    firstSeenTime: '2024-05-21 10:08:01',
    status: 'Needs review',
    metrics: [
      { label: 'Outbound bytes', value: '12.5 MB' },
      { label: 'Traffic proportion', value: '78.4% of total' },
      { label: 'Primary service', value: 'TCP/HTTPS' }
    ],
    flowsList: [
      { src: '10.0.0.15:51301', dst: '203.0.113.150:443', proto: 'TCP' },
      { src: '10.0.0.15:51302', dst: '203.0.113.150:443', proto: 'TCP' }
    ]
  },
  {
    id: 'sig-tls-sni-rare',
    title: 'TLS SNI to rare external domain',
    subtitle: 'Uncommon domain in TLS SNI',
    severity: 'low',
    confidence: 'low',
    confidenceScore: 42,
    category: 'Reconnaissance',
    observedSnippet: 'update-checker[.]net',
    observedEvidence: 'TLS client handshake SNI extension targeted the domain update-checker.net which has no recognized enterprise background.',
    interpretation: 'Attackers frequently utilize newly-registered or generic-looking domains with free certificates to host configuration endpoints or stage minor tasks.',
    whatItDoesNotProve: 'Does not confirm malicious staging. Benign developers or third-party open source projects may use similarly named checking servers.',
    recommendedDefensiveCheck: 'Block resolving queries to this domain on the local DNS server. Inspect domain registration age and active nameserver profiles.',
    relatedFlowsCount: 1,
    firstSeenTime: '2024-05-21 10:09:47',
    status: 'Needs review',
    metrics: [
      { label: 'Server name indication', value: 'update-checker.net' },
      { label: 'Cert issuer', value: 'Let\'s Encrypt' },
      { label: 'Version', value: 'TLSv1.3' }
    ],
    flowsList: [
      { src: '10.0.0.15:52310', dst: '198.51.100.42:443', proto: 'TCP' }
    ]
  },
  {
    id: 'sig-protocol-mismatch',
    title: 'Protocol mismatch',
    subtitle: 'Unexpected protocol on port',
    severity: 'medium',
    confidence: 'medium',
    confidenceScore: 60,
    category: 'Protocol anomaly',
    observedSnippet: 'HTTP traffic on port 8080',
    observedEvidence: 'Unencrypted HTTP payload streams decoded over port 8080, which is typically associated with proxy services or administrative panels.',
    interpretation: 'Transmitting sensitive plain application sequences over high ports violates cryptographic isolation policies and facilitates lateral credential sniffing.',
    whatItDoesNotProve: 'Does not prove active exploitation. Often represents an internal developer testing setup or legacy system configuration omission.',
    recommendedDefensiveCheck: 'Enforce transport security (HTTPS/TLS) on port 8080. Restrict high port access on internal server subnets via access control lists.',
    relatedFlowsCount: 1,
    firstSeenTime: '2024-05-21 10:13:12',
    status: 'Added to report',
    metrics: [
      { label: 'Port', value: '8080' },
      { label: 'Inferred protocol', value: 'HTTP Cleartext' },
      { label: 'Host header', value: 'gateway.external.test' },
      { label: 'Target file', value: '/configuration.xml' }
    ],
    flowsList: [
      { src: '10.0.0.15:49182', dst: '10.0.0.18:8080', proto: 'TCP' }
    ]
  },
  {
    id: 'sig-credential-exposure',
    title: 'Potential credential exposure',
    subtitle: 'Basic auth over HTTP',
    severity: 'high',
    confidence: 'high',
    confidenceScore: 75,
    category: 'Credential exposure risk',
    observedSnippet: 'Authorization: Basic YWRtaW46ZGFzZDMvdmM=',
    observedEvidence: 'A cleartext Basic authentication header containing base64 credentials was intercepted in the unencrypted stream to 10.0.0.18:8080.',
    interpretation: 'Basic authentication is encoded, not encrypted. Anyone in the transmission pathway can easily decode this header to capture plain administrator passwords.',
    whatItDoesNotProve: 'Does not guarantee the exposed credentials have been successfully leveraged to compromise other services outside the target host.',
    recommendedDefensiveCheck: 'Immediately rotate the password for user account \'admin\' on host 10.0.0.18. Mandate standard encrypted LDAP or SSO parameters for authentication.',
    relatedFlowsCount: 1,
    firstSeenTime: '2024-05-21 10:14:22',
    status: 'Needs review',
    metrics: [
      { label: 'Auth scheme', value: 'Basic (Base64)' },
      { label: 'Decoded user', value: 'admin' },
      { label: 'Target IP', value: '10.0.0.18' },
      { label: 'Port', value: '8080' }
    ],
    flowsList: [
      { src: '10.0.0.15:49182', dst: '10.0.0.18:8080', proto: 'TCP' }
    ]
  },
  {
    id: 'sig-large-dns-response',
    title: 'Large DNS response',
    subtitle: 'DNS response > 1KB',
    severity: 'low',
    confidence: 'low',
    confidenceScore: 40,
    category: 'Cleartext transfer',
    observedSnippet: 'DNS response size 2.3 KB from 203.0.113.53',
    observedEvidence: 'Oversized DNS response packet measuring 2.3 KB was transmitted by external IP 203.0.113.53.',
    interpretation: 'Oversized DNS payloads (particularly TXT records) are frequently used to tunnel stage-1 payloads, stage keys, or transmit exfiltrated database chunks.',
    whatItDoesNotProve: 'Does not prove active tunneling. Modern services (like cloud CDNs or DNSSEC keys) frequently return large TXT metadata records legitimately.',
    recommendedDefensiveCheck: 'Verify the raw payload contents of the DNS response. Inspect corporate firewalls for strict UDP packet length thresholds.',
    relatedFlowsCount: 1,
    firstSeenTime: '2024-05-21 10:10:55',
    status: 'Dismissed',
    metrics: [
      { label: 'Packet size', value: '2.3 KB' },
      { label: 'Record type', value: 'TXT' },
      { label: 'Source Server', value: '203.0.113.53' }
    ],
    flowsList: [
      { src: '10.0.0.15:52020', dst: '203.0.113.53:53', proto: 'UDP' }
    ]
  },
  {
    id: 'sig-icmp-sweep',
    title: 'ICMP sweep detected',
    subtitle: 'Multiple ICMP requests',
    severity: 'info',
    confidence: 'low',
    confidenceScore: 35,
    category: 'Discovery',
    observedSnippet: 'ICMP echo requests to 10.0.0.0/24',
    observedEvidence: 'Host 10.0.0.15 generated successive ICMP echo requests targeting the entire 10.0.0.0/24 local subnet.',
    interpretation: 'Ping scans are classic host-discovery protocols. Adversaries execute sweeps to build a list of alive hosts before initiating lateral staging.',
    whatItDoesNotProve: 'Does not prove malicious hacking. Internal network mapping utilities or system inventory agents periodically execute similar ping loops.',
    recommendedDefensiveCheck: 'Query workstation logs to see what application process triggered the ICMP requests. Limit internal subnet pings across key gateways.',
    relatedFlowsCount: 1,
    firstSeenTime: '2024-05-21 10:07:33',
    status: 'Dismissed',
    metrics: [
      { label: 'Subnet target', value: '10.0.0.0/24' },
      { label: 'Requests count', value: '128' },
      { label: 'Source workstation', value: '10.0.0.15' }
    ],
    flowsList: [
      { src: '10.0.0.15:0', dst: '10.0.0.0/24:0', proto: 'ICMP' }
    ]
  },
  {
    id: 'sig-failed-connections',
    title: 'Failed connection attempts',
    subtitle: 'Multiple resets from destination',
    severity: 'low',
    confidence: 'low',
    confidenceScore: 38,
    category: 'Anomaly',
    observedSnippet: 'TCP RST packets from 203.0.113.80',
    observedEvidence: 'Workstation 10.0.0.15 received instant TCP Reset (RST) flags from destination host 203.0.113.80 across several socket requests.',
    interpretation: 'Frequent outbound connection resets suggest that either the remote port is closed, or a mid-way firewall is actively dropping the requests.',
    whatItDoesNotProve: 'Does not prove command control success or malicious intent. Often triggered by client applications trying to reach unavailable cloud features.',
    recommendedDefensiveCheck: 'Cross-reference destination IP on threat databases. Verify if target IP matches known malicious callback profiles.',
    relatedFlowsCount: 3,
    firstSeenTime: '2024-05-21 10:15:01',
    status: 'Needs review',
    metrics: [
      { label: 'TCP Flags', value: 'RST-ACK' },
      { label: 'Attempt count', value: '3 times' },
      { label: 'Target IP', value: '203.0.113.80' },
      { label: 'Target Port', value: '443' }
    ],
    flowsList: [
      { src: '10.0.0.15:49811', dst: '203.0.113.80:443', proto: 'TCP' },
      { src: '10.0.0.15:49812', dst: '203.0.113.80:443', proto: 'TCP' },
      { src: '10.0.0.15:49813', dst: '203.0.113.80:443', proto: 'TCP' }
    ]
  }
];

const normalizeSignalText = (value = '') => value.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

const DEMO_SIGNAL_MATCHERS: Record<string, (signal: SuspiciousSignal) => boolean> = {
  'sig-dns-beacon': (signal) => {
    const id = signal.id.toLowerCase();
    const text = normalizeSignalText(`${signal.title} ${signal.category} ${signal.observedEvidence}`);
    return id.includes('sig-dnsbeacon') || (text.includes('dns') && (text.includes('periodic') || text.includes('timing')));
  },
  'sig-cleartext-binary': (signal) => {
    const id = signal.id.toLowerCase();
    const text = normalizeSignalText(`${signal.title} ${signal.category} ${signal.observedEvidence}`);
    return id.includes('sig-cleartext-download') || (text.includes('cleartext') && (text.includes('binary') || text.includes('download')));
  },
  'sig-repeated-connections': (signal) => {
    const id = signal.id.toLowerCase();
    const text = normalizeSignalText(`${signal.title} ${signal.category} ${signal.observedEvidence}`);
    const isRepeatedConnectionPattern = (
      id.includes('sig-repeated-connections') ||
      text.includes('repeated') ||
      text.includes('multiple') ||
      text.includes('successive') ||
      text.includes('short duration')
    ) && (text.includes('outbound') || text.includes('connection') || text.includes('socket'));

    // Unusual-port parser signals are owned by the protocol-mismatch card below.
    return !id.includes('sig-unusualport') && isRepeatedConnectionPattern;
  },
  'sig-unusual-host-traffic': (signal) => {
    const id = signal.id.toLowerCase();
    const text = normalizeSignalText(`${signal.title} ${signal.category} ${signal.observedEvidence}`);
    return id.includes('sig-dataspike') || text.includes('data volume') || text.includes('outbound data');
  },
  'sig-protocol-mismatch': (signal) => {
    const id = signal.id.toLowerCase();
    const text = normalizeSignalText(`${signal.title} ${signal.category} ${signal.observedEvidence}`);
    return id.includes('sig-unusualport') || text.includes('suspicious port') || text.includes('unusual port');
  },
  'sig-failed-connections': (signal) => {
    const text = normalizeSignalText(`${signal.title} ${signal.category} ${signal.observedEvidence}`);
    return text.includes('failed') || text.includes('reset') || text.includes('rst');
  },
};

const getLinkedSignalIds = (displaySignal: SuspiciousSignal, sourceSignals: SuspiciousSignal[]) => {
  const exact = sourceSignals.filter(signal => signal.id === displaySignal.id).map(signal => signal.id);
  if (exact.length > 0) return exact;

  const matcher = DEMO_SIGNAL_MATCHERS[displaySignal.id];
  if (matcher) {
    return sourceSignals.filter(matcher).map(signal => signal.id);
  }

  const displayTitle = normalizeSignalText(displaySignal.title);
  const displayEvidence = normalizeSignalText(displaySignal.observedEvidence).slice(0, 80);
  return sourceSignals
    .filter(signal => {
      const sourceTitle = normalizeSignalText(signal.title);
      const sourceEvidence = normalizeSignalText(signal.observedEvidence);
      return sourceTitle === displayTitle || (!!displayEvidence && sourceEvidence.includes(displayEvidence));
    })
    .map(signal => signal.id);
};

const getPersistedStatus = (
  displaySignal: SuspiciousSignal,
  sourceSignals: SuspiciousSignal[],
  overrides: Record<string, SignalReviewStatus>
): SignalReviewStatus | undefined => {
  const linkedIds = [displaySignal.id, ...getLinkedSignalIds(displaySignal, sourceSignals)];
  for (const signalId of linkedIds) {
    const overrideStatus = overrides[signalId];
    if (overrideStatus) return overrideStatus;
    const sourceStatus = sourceSignals.find(signal => signal.id === signalId)?.status;
    if (sourceStatus) return sourceStatus;
  }
  return displaySignal.status;
};

const redactSensitive = (text: string): string => {
  if (!text) return text;
  let redacted = text;
  
  // Replace case-insensitive patterns of username/user, password/passwd, token, cookie
  // 1. Authorization: Basic base64 -> redacted username/password
  redacted = redacted.replace(/(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+/gi, 'Authorization: Basic username=[redacted], password=[redacted]');

  // 2. Query param or body patterns like username=abc, password=123, token=xyz, cookie=cookieval
  // Handle key=value or key:value
  redacted = redacted.replace(/(username|user)\s*([=:])\s*[^\s&;,]+/gi, 'username=[redacted]');
  redacted = redacted.replace(/(password|passwd|pwd)\s*([=:])\s*[^\s&;,]+/gi, 'password=[redacted]');
  redacted = redacted.replace(/(token|auth_token|access_token)\s*([=:])\s*[^\s&;,]+/gi, 'token=[redacted]');
  redacted = redacted.replace(/(cookie|sessionid|session)\s*([=:])\s*[^\s&;,]+/gi, 'cookie=[redacted]');

  // 3. JSON property patterns: "username": "abc", "password": "123", "token": "xyz", "cookie": "cookieval"
  redacted = redacted.replace(/(["']?username["']?\s*[:=]\s*["']?)[^"'\s&;,]+(["']?)/gi, 'username=[redacted]');
  redacted = redacted.replace(/(["']?(?:password|passwd|pwd)["']?\s*[:=]\s*["']?)[^"'\s&;,]+(["']?)/gi, 'password=[redacted]');
  redacted = redacted.replace(/(["']?(?:token|auth_token|access_token)["']?\s*[:=]\s*["']?)[^"'\s&;,]+(["']?)/gi, 'token=[redacted]');
  redacted = redacted.replace(/(["']?(?:cookie|sessionid|session)["']?\s*[:=]\s*["']?)[^"'\s&;,]+(["']?)/gi, 'cookie=[redacted]');
  
  return redacted;
};

const FINDING_SUMMARIES: Record<string, string> = {
  'sig-dns-beacon': 'Repeated DNS queries were observed at a regular interval for the same domain. This may indicate automated network behavior and should be reviewed alongside related flows and host telemetry.',
  'sig-cleartext-binary': 'An unencrypted file download of a binary executable was detected over cleartext HTTP. Transmission of executable files without TLS encryption poses injection risks.',
  'sig-repeated-connections': 'A sequence of multiple rapid outbound connection attempts was established with a single external IP address. This indicates active outbound communication streams needing validation.',
  'sig-unusual-host-traffic': 'Workstation telemetry indicates an asymmetric spike in outbound data transfer, far exceeding normal historical baseline volumes for this endpoint.',
  'sig-tls-sni-rare': 'A client TLS handshake was observed targeting an unrecognized external domain. Rare SNI identifiers warrant reputation checking and resolver log review.',
  'sig-protocol-mismatch': 'Application-layer telemetry decoded unencrypted cleartext HTTP traffic on a high port typically reserved for secure administration or proxies.',
  'sig-credential-exposure': 'Plain text credentials encoded via Base64 were transmitted in a cleartext HTTP request header, exposing administrative credentials to local network segments.',
  'sig-large-dns-response': 'An abnormally large DNS response payload was received by the client. Oversized DNS records should be evaluated for potential payload tunneling or data staging.',
  'sig-icmp-sweep': 'Host workstation was observed broadcasting successive ICMP echo requests targeting the entire local subnet range, consistent with asset discovery.',
  'sig-failed-connections': 'Workstation outbound traffic to an external IP was met with immediate reset flags. This indicates either destination-side port closure or active firewall filtering.'
};

const ANALYST_INTERPRETATIONS: Record<string, string> = {
  'sig-dns-beacon': 'This pattern is consistent with periodic DNS activity and may reflect automated communication. It should be reviewed with resolver logs, surrounding flows, and endpoint telemetry before any conclusion is drawn.',
  'sig-cleartext-binary': 'The unencrypted transmission of binary resources poses cleartext transfer risks. This payload should be cross-referenced with local system deployment logs and verified as a legitimate program update before establishing intent.',
  'sig-repeated-connections': 'Repeated quick TCP connections can indicate normal software heartbeats, service checks, or minor API requests. The communication pattern should be assessed alongside workstation software inventories.',
  'sig-unusual-host-traffic': 'Anomalous outbound traffic volume from a single host should be validated against active user workflows, cloud backup schedules, or development exports to confirm authorization.',
  'sig-tls-sni-rare': 'The use of rare or newly-registered domains in SNI handshakes is common in dynamic environments. It should be checked against current vendor specifications and endpoint browser histories.',
  'sig-protocol-mismatch': 'Running unencrypted cleartext HTTP over alternative ports violates standard encrypted transit baselines. This should be verified as a legacy system configuration or developer setup.',
  'sig-credential-exposure': 'Unencrypted transmission of administrative authentication headers exposes credentials to local routing segments. Credentials should be rotated and transit channels upgraded to TLS.',
  'sig-large-dns-response': 'Oversized DNS payloads can result from legitimate DNSSEC signatures, rich metadata records, or CDNs. Resolver logs should be correlated to verify the decoded structure of the records.',
  'sig-icmp-sweep': 'Sequential ICMP requests across a local subnet are commonly generated by inventory scanners, network mapping utilities, or corporate monitoring tools.',
  'sig-failed-connections': 'Outbound resets are indicative of destination port unavailability or routing policy blocks. The destination should be audited against current business partner profiles.'
};

const WHAT_IT_DOES_NOT_PROVE: Record<string, string> = {
  'sig-dns-beacon': 'This observation does not confirm endpoint compromise, malicious intent, or data theft on its own. Similar patterns can also result from legitimate update services, scheduled communications, or resolver behavior.',
  'sig-cleartext-binary': 'This does not confirm active file execution or compromised status. The file download may be a benign, legacy utility or an automated administrative tool update.',
  'sig-repeated-connections': 'Multiple connection sessions do not prove malicious exfiltration or tunneling activity. Legacy telemetry updates and local daemon syncs generate identical patterns.',
  'sig-unusual-host-traffic': 'High traffic volume is not proof of unauthorized data exfiltration. Large developer uploads, continuous media streaming, or cloud drives are common legitimate causes.',
  'sig-tls-sni-rare': 'Accessing unrecognized SNI domains is not proof of hosting unauthorized assets. Legitimate cloud microservices often leverage obscure auto-generated hostnames.',
  'sig-protocol-mismatch': 'Using HTTP on high ports does not prove malicious routing or proxy bypass. Internal diagnostics tools often serve legacy administrative configurations over non-standard ports.',
  'sig-credential-exposure': 'Credential transit exposure does not verify active network exploitation. It indicates a transmission vulnerability that should be mitigated immediately.',
  'sig-large-dns-response': 'Oversized DNS responses do not confirm active payload delivery or tunnel establishment. These payloads commonly transport valid CDN configurations and key exchanges.',
  'sig-icmp-sweep': 'Subnet pinging does not indicate lateral host infiltration. Corporate inventory audits and routine configuration probes generate regular ICMP sweep traffic.',
  'sig-failed-connections': 'TCP connection failures do not verify callback command channels or remote active listening. They are typical outcomes of transient route timeouts or port closures.'
};

const DEFENSIVE_CHECKS: Record<string, string[]> = {
  'sig-dns-beacon': [
    'Confirm whether the destination/domain is expected.',
    'Review DNS query logs for surrounding activity.',
    'Compare with endpoint process or scheduled task telemetry.',
    'Inspect adjacent flows for repeated timing patterns.',
    'Add validated findings to the report.'
  ],
  'sig-cleartext-binary': [
    'Retrieve the target binary hash and query reputation databases.',
    'Review host file system creation and execution logs.',
    'Audit local software installation policy compliance.',
    'Check if the host can be transitioned to secure HTTPS mirrors.',
    'Add validated findings to the report.'
  ],
  'sig-repeated-connections': [
    'Validate the IP owner and destination hosting environment.',
    'Audit outbound TCP ports active on the local workstation.',
    'Inspect local browser extensions or daemon processes.',
    'Correlate timestamps with concurrent user interactions.',
    'Add validated findings to the report.'
  ],
  'sig-unusual-host-traffic': [
    'Verify active processes on host 10.0.0.15 during the spike.',
    'Match transferred bytes with standard database exports or backups.',
    'Check if any unauthorized synchronization clients are installed.',
    'Confirm if the user has a registered justification for large transfer.',
    'Add validated findings to the report.'
  ],
  'sig-tls-sni-rare': [
    'Query the domain registration date and WHOIS registry.',
    'Check other hosts in the network for identical SNI strings.',
    'Verify certificate chain trust against local root authorities.',
    'Correlate DNS request history preceding the TLS handshake.',
    'Add validated findings to the report.'
  ],
  'sig-protocol-mismatch': [
    'Confirm the owner and service running on port 8080.',
    'Audit the host configuration files to enforce SSL/TLS.',
    'Review adjacent high port listening sockets on the subnet.',
    'Trace web requests to check for sensitive header exposure.',
    'Add validated findings to the report.'
  ],
  'sig-credential-exposure': [
    'Immediately expire and rotate administrative passwords.',
    'Implement TLS/HTTPS transit policies to replace plain text HTTP.',
    'Review audit logs for successful logins from external IPs.',
    'Enforce MFA policies across administrative consoles.',
    'Add validated findings to the report.'
  ],
  'sig-large-dns-response': [
    'Inspect resolver logs for TXT or records content extraction.',
    'Review host routing table for active tunneling interfaces.',
    'Monitor subsequent socket traffic from the same IP endpoint.',
    'Enforce maximum UDP packet size policies on local resolvers.',
    'Add validated findings to the report.'
  ],
  'sig-icmp-sweep': [
    'Check local workstation task history for active scanner utilities.',
    'Validate if the scan matches the schedule of authorized internal IT audits.',
    'Review host ARP tables for newly discovered active neighbors.',
    'Implement router policies to restrict wide-range internal pings.',
    'Add validated findings to the report.'
  ],
  'sig-failed-connections': [
    'Compare remote IP address reputation on known abuse databases.',
    'Verify if the reset was triggered by an internal edge firewall policy.',
    'Cross-reference port status on remote host with similar network targets.',
    'Trace subsequent outbound traffic for secondary callback avenues.',
    'Add validated findings to the report.'
  ]
};

const sanitizeText = (text: string): string => {
  if (!text) return text;
  let clean = text;
  
  // Replace C2/Exfiltration or similar variations
  clean = clean.replace(/\bCommand\s+and\s+Control\s*\/\s*Exfiltration\b/gi, 'Repeated Outbound & Transfer Anomaly');
  clean = clean.replace(/\bC2\s*\/\s*Exfiltration\b/gi, 'Repeated Outbound & Transfer Anomaly');
  clean = clean.replace(/\bCommand\s+and\s+Control\b/gi, 'Beacon-like DNS pattern');
  clean = clean.replace(/\bC2\b/g, 'Beacon-like DNS pattern');
  clean = clean.replace(/\bExfiltration\b/gi, 'Cleartext Transfer');
  clean = clean.replace(/\bInitial\s+Access\b/gi, 'Discovery Anomaly');
  clean = clean.replace(/\bReconnaissance\b/gi, 'Discovery Anomaly');
  
  return clean;
};

const sanitizeSignal = <T extends SuspiciousSignal>(sig: T): T => {
  return {
    ...sig,
    title: sanitizeText(sig.title),
    category: sanitizeText(sig.category),
    observedEvidence: sanitizeText(sig.observedEvidence),
    interpretation: sanitizeText(sig.interpretation),
    whatItDoesNotProve: sanitizeText(sig.whatItDoesNotProve),
    recommendedDefensiveCheck: sanitizeText(sig.recommendedDefensiveCheck),
  };
};

export default function SuspiciousSignals({
  signals,
  flows,
  events,
  dns,
  http,
  tls,
  signalStatusOverrides = EMPTY_SIGNAL_STATUS_OVERRIDES,
  onNavigateToFlows,
  onUpdateSignalStatus
}: SuspiciousSignalsProps) {
  // Rich local state derived only from parser/rule-engine signals.
  const [enrichedSignals, setEnrichedSignals] = useState<EnrichedSignal[]>([]);
  const [selectedSignal, setSelectedSignal] = useState<EnrichedSignal | null>(null);
  const [investigationState, setInvestigationState] = useState<{
    signalId: string;
    status: 'analysing' | 'success' | 'failure';
    packet: InvestigationEvidencePacket;
    assessment?: InvestigationAssessment;
    error?: string;
  } | null>(null);

  const investigationPacket = useMemo(() => {
    if (!selectedSignal) return null;
    try {
      return buildInvestigationEvidencePacket(selectedSignal, { flows, events, dns, http, tls });
    } catch {
      return null;
    }
  }, [selectedSignal, flows, events, dns, http, tls]);
  const activeInvestigation = investigationState?.signalId === selectedSignal?.id ? investigationState : null;

  // Filters State
  const [activeTab, setActiveTab] = useState<'ALL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [isFilterPanelOpen, setIsFilterPanelOpen] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Load and enrich signals
  useEffect(() => {
    if (signals.length === 0) {
      setEnrichedSignals([]);
      setSelectedSignal(null);
      return;
    }

    const confidenceScores: Record<string, number> = { high: 75, medium: 60, low: 45, info: 30 };
    const mapped = selectPresentedSignals(signals).map(sig => {
      const cleanedSig = sanitizeSignal(sig);
      const relatedFlows = resolveRelatedFlows(sig.relatedFlowIds, flows);
      const firstSeen = relatedFlows.map(flow => flow.firstSeen).sort()[0] || '';
      return {
        ...cleanedSig,
        subtitle: cleanedSig.observedEvidence ? `${cleanedSig.observedEvidence.substring(0, 50)}...` : 'Deterministic observation',
        confidenceScore: confidenceScores[cleanedSig.confidence] || 50,
        observedSnippet: cleanedSig.observedEvidence ? cleanedSig.observedEvidence.substring(0, 30) : 'No evidence summary supplied',
        relatedFlowsCount: relatedFlows.length,
        flowsList: relatedFlows.map(flow => ({
          id: flow.id,
          src: `${flow.sourceIp}:${flow.sourcePort}`,
          dst: `${flow.destinationIp}:${flow.destinationPort}`,
          proto: flow.protocol,
        })),
        firstSeenTime: firstSeen ? firstSeen.replace('T', ' ').slice(0, 19) : 'Not provided',
        status: signalStatusOverrides[sig.id] || sig.status || 'Needs review'
      };
    });
    setEnrichedSignals(mapped);
    setSelectedSignal(prev => mapped.find(signal => signal.id === prev?.id) || mapped[0]);
  }, [signals, flows, signalStatusOverrides]);

  // Keep selection synchronized when items change
  const handleSelectSignal = (sig: EnrichedSignal) => {
    setSelectedSignal(sig);
  };

  // Status modifier functions (Simulating real integration/workflow status persistence)
  const handleUpdateStatus = (id: string, newStatus: SignalReviewStatus) => {
    const activeSignal = enrichedSignals.find(signal => signal.id === id) || selectedSignal;
    const linkedIds = activeSignal ? getLinkedSignalIds(activeSignal, signals) : [];
    const idsToUpdate = new Set([id, ...linkedIds]);

    const updated = enrichedSignals.map(s => {
      if (idsToUpdate.has(s.id)) {
        return { ...s, status: newStatus };
      }
      return s;
    });
    setEnrichedSignals(updated);
    
    // Update selected signal if it matches
    setSelectedSignal(prev => prev && idsToUpdate.has(prev.id) ? { ...prev, status: newStatus } : prev);

    // Call parent to sync state globally so navigation transitions do not wipe data
    if (onUpdateSignalStatus) {
      onUpdateSignalStatus(id, newStatus, linkedIds);
    }
  };

  // Navigate to Related Flows in the main App explorer
  const handleViewRelatedFlows = (sig: EnrichedSignal) => {
    const relatedFlows = resolveRelatedFlows(sig.relatedFlowIds, flows);
    if (relatedFlows.length > 0) onNavigateToFlows(relatedFlows);
  };

  const handleInvestigate = async () => {
    if (!selectedSignal || !investigationPacket) return;
    const signalId = selectedSignal.id;
    setInvestigationState({ signalId, status: 'analysing', packet: investigationPacket });
    try {
      const response = await fetch('/api/investigate', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ evidence: investigationPacket }),
      });
      let body: unknown;
      try {
        body = await response.json();
      } catch {
        body = null;
      }
      if (!response.ok) {
        const safeMessage = body && typeof body === 'object' && typeof (body as { error?: unknown }).error === 'string'
          ? (body as { error: string }).error.slice(0, 300)
          : 'AI-assisted investigation could not be completed. Try again.';
        throw new Error(safeMessage);
      }
      const validated = validateInvestigationAssessment(body, evidenceIds(investigationPacket));
      setInvestigationState({ signalId, status: 'success', packet: investigationPacket, assessment: validated });
    } catch (error) {
      const message = error instanceof Error && error.message
        ? error.message
        : 'AI-assisted investigation could not be completed. Try again.';
      setInvestigationState({ signalId, status: 'failure', packet: investigationPacket, error: message });
    }
  };

  // Filter computation
  const filteredSignals = enrichedSignals.filter(sig => {
    // Tab category filter
    const matchTab = 
      activeTab === 'ALL' || 
      (activeTab === 'HIGH' && sig.severity === 'high') ||
      (activeTab === 'MEDIUM' && sig.severity === 'medium') ||
      (activeTab === 'LOW' && sig.severity === 'low') ||
      (activeTab === 'INFO' && sig.severity === 'info');

    // Search term matching
    const matchesSearch = 
      sig.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      sig.category.toLowerCase().includes(searchTerm.toLowerCase()) ||
      sig.observedSnippet.toLowerCase().includes(searchTerm.toLowerCase()) ||
      sig.observedEvidence.toLowerCase().includes(searchTerm.toLowerCase());

    // Panel filters
    const matchesCategory = categoryFilter === 'ALL' || sig.category.toLowerCase() === categoryFilter.toLowerCase();
    const matchesStatus = statusFilter === 'ALL' || sig.status.toLowerCase() === statusFilter.toLowerCase();

    return matchTab && matchesSearch && matchesCategory && matchesStatus;
  });

  // Pagination bounds
  const totalFindings = filteredSignals.length;
  const startIndex = (currentPage - 1) * pageSize;
  const paginatedSignals = filteredSignals.slice(startIndex, startIndex + pageSize);

  const categories = Array.from(new Set(enrichedSignals.map(s => s.category)));

  // Status styles for Badge Rendering
  const getStatusBadgeStyle = (status: string) => {
    switch (status) {
      case 'Needs review':
        return 'text-status-info bg-status-info-bg/15 border border-status-info/30 rounded-lg font-semibold';
      case 'Added to report':
        return 'bg-status-success text-white border-transparent shadow-xs font-bold rounded-lg';
      case 'Dismissed':
        return 'text-text-muted bg-surface-muted border border-border-subtle rounded-lg hover:bg-surface-muted/80 font-semibold';
      default:
        return 'text-text-muted bg-surface-muted border border-border-subtle rounded-lg';
    }
  };

  const getSeverityBadgeStyle = (sev: string) => {
    switch (sev) {
      case 'high':
        return 'bg-status-danger text-white border-transparent shadow-xs font-bold rounded-lg';
      case 'medium':
        return 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/15 font-bold rounded-lg';
      case 'low':
        return 'bg-surface-muted border border-border-subtle text-text-muted font-semibold rounded-lg';
      case 'info':
        return 'bg-surface-muted border border-border-subtle text-text-muted/80 font-medium rounded-lg';
      default:
        return 'bg-surface-muted border border-border-subtle text-text-muted/80 font-medium rounded-lg';
    }
  };

  const getSeverityIndicator = (sev: string) => {
    switch (sev) {
      case 'high':
        return 'bg-status-danger';
      case 'medium':
        return 'bg-status-warning';
      case 'low':
        return 'bg-text-muted';
      case 'info':
        return 'bg-status-info';
      default:
        return 'bg-text-muted';
    }
  };

  return (
    <div className="space-y-5 font-sans">
      
      {/* Page Header */}
      <div className="pb-3 border-b border-border-subtle">
        <h1 className="text-xl font-bold tracking-tight text-text-primary">Signals & observations</h1>
        <p className="text-xs text-text-muted mt-0.5">
          Review detections from deterministic analysis and custom rules. Validate findings and add important items to your report.
        </p>
      </div>

      {/* Control Row with Tabs, Search, Filters and Export */}
      <div className="flex flex-col gap-3">
        <div className="flex flex-col lg:flex-row gap-3 items-stretch lg:items-center justify-between">
          
          {/* Tabs matching exact mockup structure */}
          <div className="flex bg-surface-muted p-1 rounded-xl border border-border-subtle w-fit max-w-full overflow-x-auto gap-0.5">
            {[
              { id: 'ALL', label: 'All findings', count: enrichedSignals.length },
              { id: 'HIGH', label: 'High', count: enrichedSignals.filter(s => s.severity === 'high').length, color: 'text-status-danger font-medium' },
              { id: 'MEDIUM', label: 'Medium', count: enrichedSignals.filter(s => s.severity === 'medium').length, color: 'text-status-warning font-medium' },
              { id: 'LOW', label: 'Low', count: enrichedSignals.filter(s => s.severity === 'low').length, color: 'text-text-muted' },
              { id: 'INFO', label: 'Informational', count: enrichedSignals.filter(s => s.severity === 'info').length, color: 'text-status-info font-medium' }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id as any);
                  setCurrentPage(1);
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-all flex items-center gap-1.5 whitespace-nowrap ${
                  activeTab === tab.id 
                    ? 'bg-surface text-text-primary border border-border-subtle shadow-sm' 
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                <span className={tab.id !== 'ALL' && activeTab !== tab.id ? tab.color : ''}>{tab.label}</span>
                <span className={`px-1.5 py-0.2 text-[10px] rounded-full font-mono font-bold ${
                  activeTab === tab.id ? 'bg-accent-primary text-text-inverse' : 'bg-surface-muted border border-border-subtle text-text-muted'
                }`}>
                  {tab.count}
                </span>
              </button>
            ))}
          </div>

          {/* Action Row: Search, Filters, Export */}
          <div className="flex items-center gap-2">
            
            {/* Search Input */}
            <div className="relative flex-1 sm:w-60">
              <Search className="absolute left-2.5 top-2.5 text-text-muted" size={13} />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
                placeholder="Search signals..."
                className="w-full bg-surface-muted border border-border-subtle rounded-xl pl-8.5 pr-4 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent-primary/40 focus:outline-none focus:ring-1 h-9"
              />
            </div>

            {/* Filters Button */}
            <button
              onClick={() => setIsFilterPanelOpen(!isFilterPanelOpen)}
              className={`p-2 bg-surface border rounded-xl text-text-muted hover:text-text-primary cursor-pointer flex items-center justify-center gap-1.5 text-xs font-semibold h-9 transition-colors ${
                isFilterPanelOpen || categoryFilter !== 'ALL' || statusFilter !== 'ALL' ? 'border-accent-primary/30 text-accent-primary bg-accent-soft' : 'border-border-subtle'
              }`}
            >
              <SlidersHorizontal size={13} />
              <span>Filters</span>
            </button>

            {/* Export Dropdown */}
            <div className="relative group">
              <button className="px-3 py-2 bg-surface border border-border-subtle rounded-xl text-xs font-semibold text-text-primary hover:bg-surface-muted cursor-pointer flex items-center gap-1.5 h-9">
                <span>Export</span>
                <ChevronDown size={11} />
              </button>
              
              {/* Dropdown Menu */}
              <div className="absolute right-0 top-10 w-40 bg-surface border border-border-subtle rounded-xl shadow-lg hidden group-hover:block z-20">
                <div className="p-1 text-xs">
                  <button 
                    onClick={() => {
                      const text = JSON.stringify(enrichedSignals, null, 2);
                      const blob = new Blob([text], {type: 'application/json'});
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = 'packetsage-signals.json';
                      a.click();
                    }}
                    className="w-full px-2.5 py-1.5 text-left rounded-lg text-text-primary hover:bg-surface-muted cursor-pointer"
                  >
                    Export JSON
                  </button>
                  <button 
                    onClick={() => {
                      const csvRows = ['id,title,severity,confidence,category,status,firstSeen'];
                      enrichedSignals.forEach(s => csvRows.push(`"${s.id}","${s.title}","${s.severity}","${s.confidenceScore}%","${s.category}","${s.status}","${s.firstSeenTime}"`));
                      const blob = new Blob([csvRows.join('\n')], {type: 'text/csv'});
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = 'packetsage-signals.csv';
                      a.click();
                    }}
                    className="w-full px-2.5 py-1.5 text-left rounded-lg text-text-primary hover:bg-surface-muted cursor-pointer"
                  >
                    Export CSV
                  </button>
                </div>
              </div>
            </div>

          </div>
        </div>

        {/* Collapsible Filters Bar */}
        {isFilterPanelOpen && (
          <div className="p-3 bg-surface-muted rounded-xl border border-border-subtle grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs animate-in slide-in-from-top duration-150">
            <div>
              <label className="text-text-muted font-semibold mb-1 block">Category</label>
              <select
                value={categoryFilter}
                onChange={(e) => {
                  setCategoryFilter(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-surface border border-border-subtle rounded-lg px-2.5 py-1.5 text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-primary"
              >
                <option value="ALL">All Categories</option>
                {categories.map(cat => (
                  <option key={cat} value={cat}>{cat}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-text-muted font-semibold mb-1 block">Status</label>
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-surface border border-border-subtle rounded-lg px-2.5 py-1.5 text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-primary"
              >
                <option value="ALL">All Statuses</option>
                <option value="Needs review">Needs Review</option>
                <option value="Added to report">Added to Report</option>
                <option value="Dismissed">Dismissed</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Main Table + Drawer Grid */}
      <div id="signals-and-observations-workspace" className={`grid grid-cols-1 gap-5 relative font-sans items-start ${selectedSignal ? 'xl:grid-cols-[minmax(0,1fr)_390px]' : 'grid-cols-1'}`}>
        
        {/* Signals Table Card */}
        <div className="bg-surface rounded-2xl border border-border-subtle overflow-hidden shadow-sm flex flex-col justify-between min-w-0 order-2 xl:order-none">
          <div className="md:hidden divide-y divide-border-subtle">
            {paginatedSignals.length > 0 ? (
              paginatedSignals.map((sig) => {
                const isSelected = selectedSignal?.id === sig.id;
                return (
                  <button
                    id={`signal-card-${sig.id}`}
                    key={sig.id}
                    type="button"
                    onClick={() => handleSelectSignal(sig)}
                    className={`w-full text-left p-4 transition-all cursor-pointer ${
                      isSelected ? 'bg-accent-soft border-l-4 border-accent-primary' : 'hover:bg-surface-muted/40 border-l-4 border-transparent'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-start gap-2.5 min-w-0">
                        <span className="mt-0.5 shrink-0">
                          {sig.severity === 'high' ? (
                            <ShieldAlert size={14} className="text-status-danger" />
                          ) : sig.severity === 'medium' ? (
                            <AlertTriangle size={14} className="text-status-warning" />
                          ) : (
                            <Shield size={14} className="text-status-info" />
                          )}
                        </span>
                        <div className="min-w-0">
                          <div className="font-semibold text-text-primary text-xs leading-snug line-clamp-2" title={sig.title}>
                            {sig.title}
                          </div>
                          <div className="text-[11px] text-text-muted mt-0.5 line-clamp-1" title={sig.subtitle}>
                            {sig.subtitle}
                          </div>
                        </div>
                      </div>
                      <ChevronRight size={13} className={`mt-1 shrink-0 transition-transform ${isSelected ? 'text-accent-primary translate-x-0.5' : 'text-text-muted'}`} />
                    </div>

                    <div className="mt-3 grid grid-cols-2 gap-2 text-[10px]">
                      <div className="space-y-1">
                        <span className="block text-text-muted font-bold uppercase tracking-wider">Severity</span>
                        <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold tracking-wider uppercase border inline-flex items-center gap-1 w-fit ${getSeverityBadgeStyle(sig.severity)}`}>
                          <span className={`w-1 h-1 rounded-full ${getSeverityIndicator(sig.severity)}`} />
                          {sig.severity}
                        </span>
                      </div>
                      <div className="space-y-1">
                        <span className="block text-text-muted font-bold uppercase tracking-wider">Status</span>
                        <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold border inline-flex w-fit ${getStatusBadgeStyle(sig.status)}`}>
                          {sig.status}
                        </span>
                      </div>
                      <div className="space-y-1">
                        <span className="block text-text-muted font-bold uppercase tracking-wider">Confidence</span>
                        <span className="font-mono text-text-primary font-semibold">{sig.confidenceScore}%</span>
                      </div>
                      <div className="space-y-1">
                        <span className="block text-text-muted font-bold uppercase tracking-wider">Related flows</span>
                        <span className="font-mono text-text-primary font-semibold">{sig.relatedFlowsCount}</span>
                      </div>
                    </div>

                    <div className="mt-3 font-mono text-[10px] bg-mono-bg border border-border-subtle/70 text-text-secondary px-2 py-1 rounded-lg truncate" title={redactSensitive(sig.observedEvidence)}>
                      {redactSensitive(sig.observedSnippet)}
                    </div>
                  </button>
                );
              })
            ) : (
              <div className="py-12 text-center text-text-muted text-xs">
                No signals match your query or filter criteria.
              </div>
            )}
          </div>

          <div className="hidden md:block overflow-x-auto">
            <table id="signals-table" className="w-full text-left text-xs">
              <thead className="bg-surface-muted border-b border-border-subtle text-text-muted select-none">
                <tr>
                  <th className="py-3 px-4 font-bold text-[10px] tracking-wider uppercase min-w-[240px]">Signal</th>
                  <th className="py-3 px-4 font-bold text-[10px] tracking-wider uppercase min-w-[105px]">
                    <div className="flex items-center gap-1">
                      <span>Severity</span>
                      <InfoPopover content="Severity indicates review priority and possible impact based on observed evidence. It does not prove malicious activity on its own." align="left" />
                    </div>
                  </th>
                  <th className="py-3 px-4 font-bold text-[10px] tracking-wider uppercase min-w-[95px]">
                    <div className="flex items-center gap-1">
                      <span>Confidence</span>
                      <InfoPopover content="Confidence describes how strongly PacketSage observed the behavior, not confidence that compromise occurred." align="left" />
                    </div>
                  </th>
                  <th className="py-3 px-4 font-bold text-[10px] tracking-wider uppercase min-w-[160px]">Category</th>
                  <th className="py-3 px-4 font-bold text-[10px] tracking-wider uppercase min-w-[200px]">Observed evidence</th>
                  <th className="py-3 px-4 font-bold text-[10px] tracking-wider uppercase text-right min-w-[100px]">Related flows</th>
                  <th className="py-3 px-4 font-bold text-[10px] tracking-wider uppercase min-w-[140px]">First seen</th>
                  <th className="py-3 px-4 font-bold text-[10px] tracking-wider uppercase min-w-[110px]">
                    <div className="flex items-center gap-1">
                      <span>Status</span>
                      <InfoPopover content="Needs review means the finding should be validated by an analyst before being added to a report or dismissed as noise." align="left" />
                    </div>
                  </th>
                  <th className="py-3 px-3 w-5"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {paginatedSignals.length > 0 ? (
                  paginatedSignals.map((sig) => {
                    const isSelected = selectedSignal?.id === sig.id;
                    return (
                      <tr
                        id={`signal-row-${sig.id}`}
                        key={sig.id}
                        onClick={() => handleSelectSignal(sig)}
                        className={`hover:bg-surface-muted/50 cursor-pointer transition-all ${
                          isSelected ? 'bg-accent-soft font-medium' : ''
                        }`}
                      >
                        {/* Signal Title / Description column with left absolute marker using a relative first cell */}
                        <td className={`py-3.5 px-4 min-w-[240px] relative ${isSelected ? 'before:absolute before:left-0 before:top-0 before:bottom-0 before:w-1 before:bg-accent-primary' : ''}`}>
                          <div className="flex items-start gap-2.5">
                            <span className="mt-0.5 shrink-0">
                              {sig.severity === 'high' ? (
                                <ShieldAlert size={14} className="text-status-danger" />
                              ) : sig.severity === 'medium' ? (
                                <AlertTriangle size={14} className="text-status-warning" />
                              ) : (
                                <Shield size={14} className="text-status-info" />
                              )}
                            </span>
                            <div>
                              <div className="font-semibold text-text-primary text-xs leading-snug line-clamp-2" title={sig.title}>{sig.title}</div>
                              <div className="text-[11px] text-text-muted mt-0.5 line-clamp-1" title={sig.subtitle}>{sig.subtitle}</div>
                            </div>
                          </div>
                        </td>

                        {/* Severity badge column */}
                        <td className="py-3.5 px-4 whitespace-nowrap min-w-[105px]">
                          <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold tracking-wider uppercase border flex items-center gap-1 w-fit ${getSeverityBadgeStyle(sig.severity)}`}>
                            <span className={`w-1 h-1 rounded-full ${getSeverityIndicator(sig.severity)}`} />
                            {sig.severity}
                          </span>
                        </td>

                        {/* Confidence indicator column */}
                        <td className="py-3.5 px-4 whitespace-nowrap min-w-[95px]">
                          <div className="space-y-1 w-16">
                            <div className="font-mono text-[11px] text-text-primary font-semibold">{sig.confidenceScore}%</div>
                            <div className="w-16 h-1 bg-surface-muted rounded-full overflow-hidden">
                              <div className="bg-accent-primary h-full" style={{ width: `${sig.confidenceScore}%` }} />
                            </div>
                          </div>
                        </td>

                        {/* Category column */}
                        <td className="py-3.5 px-4 text-text-secondary whitespace-nowrap text-xs min-w-[160px]">
                          {sig.category}
                        </td>

                        {/* Observed evidence column */}
                        <td className="py-3.5 px-4 min-w-[200px]">
                          <span 
                            className="font-mono text-[10px] bg-mono-bg border border-border-subtle/70 text-text-secondary px-2 py-0.5 rounded inline-block truncate max-w-[180px] hover:max-w-none transition-all duration-150" 
                            title={redactSensitive(sig.observedEvidence)}
                          >
                            {redactSensitive(sig.observedSnippet)}
                          </span>
                        </td>

                        {/* Related flows column */}
                        <td className="py-3.5 px-4 text-right font-mono text-text-secondary font-semibold min-w-[100px]">
                          {sig.relatedFlowsCount}
                        </td>

                        {/* First seen timestamp column */}
                        <td className="py-3.5 px-4 text-text-muted font-mono text-[11px] whitespace-nowrap min-w-[140px]">
                          {sig.firstSeenTime}
                        </td>

                        {/* Status column with clickable toggler */}
                        <td className="py-3.5 px-4 whitespace-nowrap min-w-[110px]">
                          <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold border transition-colors ${getStatusBadgeStyle(sig.status)}`}>
                            {sig.status}
                          </span>
                        </td>

                        {/* Arrow Chevron */}
                        <td className="py-3.5 px-3 text-text-muted">
                          <ChevronRight size={13} className={`transform transition-transform ${isSelected ? 'translate-x-0.5 text-accent-primary' : ''}`} />
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={9} className="py-12 text-center text-text-muted text-xs">
                      No signals match your query or filter criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Table Pagination Footer matching reference style */}
          <div className="p-3 border-t border-border-subtle flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-text-muted bg-surface-muted/25 select-none">
            <div>
              Showing <span className="text-text-primary font-semibold">{totalFindings > 0 ? startIndex + 1 : 0}</span> to <span className="text-text-primary font-semibold">{Math.min(startIndex + pageSize, totalFindings)}</span> of <span className="text-text-primary font-semibold">{totalFindings}</span> findings
            </div>

            <div className="flex items-center gap-4">
              {/* Pagination Controls */}
              <div className="flex items-center gap-1">
                <button
                  disabled={currentPage === 1}
                  onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                  className="p-1.5 bg-surface-muted border border-border-subtle rounded-lg text-text-primary hover:bg-surface disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                >
                  <ChevronLeft size={13} />
                </button>
                
                {Array.from({ length: Math.ceil(totalFindings / pageSize) }).map((_, idx) => (
                  <button
                    key={idx}
                    onClick={() => setCurrentPage(idx + 1)}
                    className={`px-2.5 py-1 rounded-lg text-xs font-semibold cursor-pointer transition-all ${
                      currentPage === idx + 1 
                        ? 'bg-accent-primary text-text-inverse border border-accent-primary' 
                        : 'bg-surface-muted border border-border-subtle text-text-muted hover:text-text-primary'
                    }`}
                  >
                    {idx + 1}
                  </button>
                ))}

                <button
                  disabled={currentPage >= Math.ceil(totalFindings / pageSize)}
                  onClick={() => setCurrentPage(prev => Math.min(prev + 1, Math.ceil(totalFindings / pageSize)))}
                  className="p-1.5 bg-surface-muted border border-border-subtle rounded-lg text-text-primary hover:bg-surface disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                >
                  <ChevronRight size={13} />
                </button>
              </div>

              {/* Page Size Select */}
              <div className="flex items-center gap-1.5">
                <select
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value));
                    setCurrentPage(1);
                  }}
                  className="bg-surface-muted border border-border-subtle rounded-lg px-2 py-1 text-text-primary focus:outline-none text-[11px] cursor-pointer font-semibold"
                >
                  <option value={5}>5 / page</option>
                  <option value={10}>10 / page</option>
                  <option value={20}>20 / page</option>
                </select>
              </div>
            </div>
          </div>
        </div>

        {/* Selected Finding Detail Sidebar */}
        {selectedSignal && (
          <div className="w-full bg-surface rounded-2xl border border-border-subtle p-4 space-y-4 shadow-lg h-fit xl:sticky xl:top-[84px] xl:max-h-[calc(100vh-140px)] overflow-y-auto animate-in slide-in-from-right duration-200 order-1 xl:order-none">
            
            {/* Title Block & Close Action */}
            <div className="flex justify-between items-start pb-2.5 border-b border-border-subtle">
              <div className="space-y-0.5">
                <span className="text-[10px] font-bold text-text-muted uppercase tracking-[0.16em] block">Finding details</span>
                <div className="text-[10px] font-mono text-text-muted">ID: {selectedSignal.id}</div>
              </div>
              <button
                onClick={() => setSelectedSignal(null)}
                className="p-1 text-text-muted hover:text-text-primary bg-surface-muted hover:bg-surface-muted/80 rounded border border-border-subtle cursor-pointer transition-colors"
              >
                <X size={12} />
              </button>
            </div>

            {/* Status / Severity Summary Block */}
            <div className="space-y-2 pb-3 border-b border-border-subtle">
              <h3 className="text-xs font-bold text-text-primary leading-snug">
                {selectedSignal.title}
              </h3>
              
              <div className="flex flex-wrap items-center gap-1.5">
                {/* Severity Badge */}
                <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-lg text-[9.5px] font-bold border ${
                  selectedSignal.severity === 'high'
                    ? 'bg-status-danger text-white border-transparent shadow-xs'
                    : selectedSignal.severity === 'medium'
                    ? 'border border-status-warning/40 text-status-warning bg-status-warning-bg/15 font-semibold'
                    : 'bg-surface-muted border border-border-subtle text-text-muted font-semibold'
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    selectedSignal.severity === 'high' ? 'bg-white animate-pulse' : selectedSignal.severity === 'medium' ? 'bg-status-warning' : 'bg-text-muted/60'
                  }`} />
                  {selectedSignal.severity === 'high' 
                    ? 'High Severity'
                    : selectedSignal.severity === 'medium'
                    ? 'Medium Severity'
                    : `${selectedSignal.severity.charAt(0).toUpperCase() + selectedSignal.severity.slice(1)} Severity`}
                </span>

                {/* Confidence Badge */}
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-lg text-[9.5px] font-bold bg-surface-muted border border-border-subtle text-text-secondary">
                  Confidence: {selectedSignal.confidenceScore}%
                </span>

                {/* Status Badge */}
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-lg text-[9.5px] font-bold bg-surface-muted border border-border-subtle text-text-muted">
                  {selectedSignal.status}
                </span>
              </div>

              <div className="text-[10px] text-text-muted font-medium flex items-center gap-1 mt-1.5">
                <span>Observation:</span>
                <span className="text-text-secondary font-semibold">{selectedSignal.subtitle}</span>
              </div>
            </div>

            {/* Finding Summary Section */}
            <div className="space-y-1.5 py-1 border-b border-border-subtle pb-3">
              <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-wider">Finding summary</h4>
              <p className="text-[11px] text-text-secondary leading-relaxed">
                {FINDING_SUMMARIES[selectedSignal.id] || `An observation of ${selectedSignal.category.toLowerCase()} was recorded for this host. Review the observed evidence and corresponding telemetry below.`}
              </p>
            </div>

            {/* Observed Evidence Section - structured with compact table-like fields */}
            <div className="space-y-2 py-1 border-b border-border-subtle pb-3">
              <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-wider">Observed evidence</h4>
              <p className="text-[11px] text-text-secondary leading-relaxed bg-surface-muted/40 p-2 rounded-xl border border-border-subtle/30 font-mono text-[10px] whitespace-pre-wrap break-all">
                {redactSensitive(selectedSignal.observedEvidence)}
              </p>

              {/* Structured Key/Value Rows */}
              <div className="bg-surface-muted/20 border border-border-subtle/50 rounded-xl overflow-hidden divide-y divide-border-subtle/30 text-[10px] mt-2">
                <div className="flex justify-between items-center px-3 py-1.5">
                  <span className="text-text-muted">Source host</span>
                  <span className="font-mono text-text-primary font-semibold">10.0.0.15</span>
                </div>

                <div className="flex justify-between items-center px-3 py-1.5">
                  <span className="text-text-muted">Target / Destination</span>
                  <span className="font-mono text-text-primary font-semibold text-right truncate max-w-[200px]" title={selectedSignal.observedSnippet}>
                    {redactSensitive(selectedSignal.observedSnippet)}
                  </span>
                </div>

                {selectedSignal.metrics && selectedSignal.metrics.map((m, idx) => (
                  <div key={idx} className="flex justify-between items-center px-3 py-1.5">
                    <span className="text-text-muted">{m.label}</span>
                    <span className="font-mono text-text-primary font-semibold text-right truncate max-w-[200px]" title={m.value}>
                      {redactSensitive(m.value)}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Analyst Interpretation - neutral & forensic */}
            <div className="space-y-1.5 py-1 border-b border-border-subtle pb-3">
              <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-wider">Analyst interpretation</h4>
              <p className="text-[11px] leading-relaxed text-text-secondary">
                {ANALYST_INTERPRETATIONS[selectedSignal.id] || selectedSignal.interpretation}
              </p>
            </div>

            {/* What it DOES NOT prove */}
            <div className="space-y-1.5 p-2.5 rounded-xl border border-status-warning/10 bg-status-warning-bg/5">
              <h4 className="text-[10px] font-bold text-status-warning uppercase tracking-wider flex items-center gap-1.5">
                <AlertCircle size={11} className="shrink-0 text-status-warning" />
                <span>What this does NOT prove</span>
              </h4>
              <p className="text-[11px] text-text-secondary leading-relaxed">
                {WHAT_IT_DOES_NOT_PROVE[selectedSignal.id] || "This observation does not confirm endpoint compromise or unauthorized activity on its own. Similar patterns can also result from legitimate services or resolver behaviors."}
              </p>
            </div>

            {/* Related Flows with clickable View all link */}
            <div className="space-y-2 py-1 border-b border-border-subtle pb-3">
              <div className="flex items-center justify-between">
                <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-wider">
                  Related flows ({selectedSignal.relatedFlowsCount})
                </h4>
                <button
                  onClick={() => handleViewRelatedFlows(selectedSignal)}
                  disabled={selectedSignal.relatedFlowsCount === 0}
                  title={selectedSignal.relatedFlowsCount === 0 ? 'No referenced flows are available in the current evidence.' : undefined}
                  className="text-[10px] font-bold text-accent-primary hover:text-accent-primary-hover transition-colors flex items-center gap-0.5 cursor-pointer disabled:text-text-muted disabled:cursor-not-allowed"
                >
                  <span>View all</span>
                  <ExternalLink size={9} />
                </button>
              </div>

              {selectedSignal.flowsList && selectedSignal.flowsList.length > 0 ? (
                <div className="bg-surface-muted/20 border border-border-subtle/40 rounded-xl divide-y divide-border-subtle/30 overflow-hidden text-[10px]">
                  {selectedSignal.flowsList.map((f, index) => (
                    <button
                      type="button"
                      key={f.id || index}
                      disabled={!f.id}
                      onClick={() => {
                        if (!f.id) return;
                        const relatedFlow = resolveRelatedFlows([f.id], flows);
                        if (relatedFlow.length > 0) onNavigateToFlows(relatedFlow);
                      }}
                      className="w-full px-3 py-1.5 flex items-center justify-between text-left text-text-secondary transition-colors hover:text-accent-primary cursor-pointer disabled:text-text-muted disabled:cursor-not-allowed"
                    >
                      <span className="font-mono truncate">{f.src} ➔ {f.dst}</span>
                      <span className="text-text-muted font-sans text-[8px] tracking-wider uppercase bg-surface-muted px-1.5 py-0.5 rounded border border-border-subtle/20">{f.proto}</span>
                    </button>
                  ))}
                  {selectedSignal.relatedFlowsCount > (selectedSignal.flowsList?.length || 0) && (
                    <div className="px-3 py-1.5 text-left text-[9px] text-text-muted bg-surface-muted/10">
                      ... and {selectedSignal.relatedFlowsCount - (selectedSignal.flowsList?.length || 0)} more flows recorded
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-[11px] text-text-muted italic">
                  {selectedSignal.relatedFlowIds?.length
                    ? 'Referenced flows are unavailable in the current evidence.'
                    : 'No related flows were recorded for this signal.'}
                </div>
              )}
            </div>

            {/* Evidence-scoped AI-assisted investigation */}
            <div className="space-y-2 border-b border-border-subtle pb-3">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <h4 className="text-[10px] font-bold uppercase tracking-wider text-text-muted">AI-assisted investigation</h4>
                  <p className="mt-0.5 text-[9px] leading-relaxed text-text-muted">
                    Uses only this signal and its exact referenced evidence IDs. Inference is not observed fact.
                  </p>
                </div>
                {!activeInvestigation || activeInvestigation.status === 'failure' ? (
                  <button
                    type="button"
                    onClick={handleInvestigate}
                    disabled={!investigationPacket}
                    className="inline-flex shrink-0 items-center gap-1 rounded-lg bg-accent-primary px-2.5 py-1.5 text-[10px] font-bold text-white shadow-sm hover:bg-accent-primary-hover cursor-pointer disabled:bg-surface-muted disabled:text-text-muted disabled:cursor-not-allowed"
                    title={!investigationPacket ? 'No valid referenced evidence is available for this signal.' : undefined}
                  >
                    {activeInvestigation?.status === 'failure' ? <RotateCcw size={11} /> : <Sparkles size={11} />}
                    {activeInvestigation?.status === 'failure' ? 'Retry' : 'Investigate with AI'}
                  </button>
                ) : null}
              </div>

              {!investigationPacket && (
                <div className="rounded-lg border border-border-subtle bg-surface-muted/40 p-2 text-[10px] text-text-muted">
                  AI-assisted investigation is unavailable because this signal has no valid referenced evidence.
                </div>
              )}
              {activeInvestigation?.status === 'analysing' && (
                <div className="flex items-center gap-2 rounded-lg border border-accent-primary/20 bg-accent-soft/30 p-2 text-[10px] text-accent-primary" role="status">
                  <LoaderCircle size={12} className="animate-spin" />
                  Analysing referenced evidence…
                </div>
              )}
              {activeInvestigation?.status === 'failure' && (
                <div className="rounded-lg border border-status-danger/20 bg-status-danger/5 p-2 text-[10px] text-text-secondary" role="alert">
                  <div className="font-semibold text-status-danger">AI-assisted investigation was not completed.</div>
                  <p className="mt-0.5">{activeInvestigation.error}</p>
                  <p className="mt-1 text-text-muted">No fallback findings were generated.</p>
                </div>
              )}
              {activeInvestigation?.status === 'success' && activeInvestigation.assessment && (
                <>
                  <InvestigationAssessmentPanel
                    assessment={activeInvestigation.assessment}
                    packet={activeInvestigation.packet}
                    flows={flows}
                    onNavigateToFlows={onNavigateToFlows}
                  />
                  <button
                    type="button"
                    onClick={handleInvestigate}
                    className="inline-flex items-center gap-1 text-[9px] font-semibold text-accent-primary hover:text-accent-primary-hover cursor-pointer"
                  >
                    <RotateCcw size={9} /> Run again with current referenced evidence
                  </button>
                </>
              )}
            </div>

            {/* Recommended checks */}
            <div className="space-y-2 py-1 border-b border-border-subtle pb-3">
              <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-wider">
                Recommended defensive checks
              </h4>
              <ul className="text-[11px] text-text-secondary leading-relaxed space-y-1.5 list-disc pl-4.5">
                {(DEFENSIVE_CHECKS[selectedSignal.id] || [
                  'Confirm whether the destination/domain is expected.',
                  'Review DNS query logs for surrounding activity.',
                  'Compare with endpoint process or scheduled task telemetry.',
                  'Add validated findings to the report.'
                ]).map((check, idx) => (
                  <li key={idx} className="marker:text-text-muted">{check}</li>
                ))}
              </ul>
            </div>

            {/* Workflow Action Buttons at the bottom */}
            <div className="pt-2 flex flex-col gap-2">
              <div className="grid grid-cols-2 gap-2">
                
                {/* Add to report trigger */}
                <button
                  onClick={() => handleUpdateStatus(selectedSignal.id, 'Added to report')}
                  className={`py-2 px-3 rounded-lg text-xs font-bold transition-all flex items-center justify-center gap-1.5 shadow-sm cursor-pointer ${
                    selectedSignal.status === 'Added to report'
                      ? 'bg-status-success text-white border-transparent cursor-default'
                      : 'bg-accent-primary hover:bg-accent-primary-hover text-white border border-accent-primary'
                  }`}
                  disabled={selectedSignal.status === 'Added to report'}
                >
                  {selectedSignal.status === 'Added to report' ? (
                    <>
                      <Check size={12} />
                      <span>Added</span>
                    </>
                  ) : (
                    <>
                      <span>Add to report</span>
                    </>
                  )}
                </button>

                {/* Mark as Dismissed trigger */}
                <button
                  onClick={() => handleUpdateStatus(selectedSignal.id, 'Dismissed')}
                  className={`py-2 px-3 rounded-lg text-xs font-semibold transition-all flex items-center justify-center gap-1.5 border cursor-pointer ${
                    selectedSignal.status === 'Dismissed'
                      ? 'bg-surface-muted text-text-muted border-border-subtle cursor-default'
                      : 'bg-surface hover:bg-surface-muted text-text-secondary border-border-default'
                  }`}
                  disabled={selectedSignal.status === 'Dismissed'}
                >
                  {selectedSignal.status === 'Dismissed' ? (
                    <>
                      <Check size={12} />
                      <span>Dismissed</span>
                    </>
                  ) : (
                    <>
                      <Ban size={12} className="shrink-0" />
                      <span>Dismiss noise</span>
                    </>
                  )}
                </button>

              </div>

              {/* Reset state helper */}
              {selectedSignal.status !== 'Needs review' && (
                <button
                  onClick={() => handleUpdateStatus(selectedSignal.id, 'Needs review')}
                  className="w-full py-1 text-[10px] text-accent-primary hover:text-accent-primary-hover transition-colors font-semibold text-center cursor-pointer mt-1"
                >
                  Reset finding status to 'Needs review'
                </button>
              )}
            </div>

          </div>
        )}
      </div>

    </div>
  );
}
