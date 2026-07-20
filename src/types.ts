/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface UploadedEvidence {
  id: string;
  name: string;
  type: string;
  size: number;
  uploadedAt: string;
  parseMode: 'demo' | 'csv' | 'json' | 'txt' | 'tshark' | 'zeek' | 'suricata' | 'pcap';
  sourceFormat: string;
  retentionMode: string;
  status: 'parsing' | 'completed' | 'failed';
}

export interface PacketEvent {
  id: string;
  timestamp: string;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  protocol: string;
  service?: string;
  length: number;
  capturedLength?: number;
  originalLength?: number;
  info: string;
  rawSummary?: string;
  sourceType?: string;
}

export interface FlowSummary {
  id: string;
  firstSeen: string;
  lastSeen: string;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  protocol: string;
  service?: string;
  packetCount: number;
  byteCount: number;
  duration: number; // in seconds
  direction: 'inbound' | 'outbound' | 'internal';
  riskLevel: 'info' | 'low' | 'medium' | 'high';
  notes?: string;
  relatedEvents?: string[]; // IDs of packets
}

export interface ProtocolStat {
  protocol: string;
  count: number;
  percentage: number;
  byteCount: number;
  explanation: string;
}

export interface DnsRecord {
  id?: string;
  relatedEventIds?: string[];
  timestamp: string;
  clientIp: string;
  query: string;
  queryType: string;
  response: string;
  rcode: string;
  notes?: string;
  riskLevel: 'info' | 'low' | 'medium' | 'high';
}

export interface HttpRecord {
  id?: string;
  relatedEventIds?: string[];
  timestamp: string;
  clientIp: string;
  host: string;
  method: string;
  uri: string;
  statusCode: number;
  userAgent?: string;
  cleartext: boolean;
  notes?: string;
  riskLevel: 'info' | 'low' | 'medium' | 'high';
}

export interface TlsRecord {
  id?: string;
  relatedEventIds?: string[];
  timestamp: string;
  clientIp: string;
  serverIp: string;
  sni: string;
  version?: string;
  ja3?: string;
  certificateSubject?: string;
  notes?: string;
  riskLevel: 'info' | 'low' | 'medium' | 'high';
}

export type SignalReviewStatus = 'Needs review' | 'Added to report' | 'Dismissed';

export interface SuspiciousSignal {
  id: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  confidence: 'low' | 'medium' | 'high';
  category: string;
  observedEvidence: string;
  interpretation: string;
  whatItDoesNotProve: string;
  recommendedDefensiveCheck: string;
  relatedFlowIds?: string[];
  relatedEventIds?: string[];
  status?: SignalReviewStatus;
}

export interface InvestigationSignalEvidence {
  id: string;
  title: string;
  severity: SuspiciousSignal['severity'];
  confidence: SuspiciousSignal['confidence'];
  category: string;
  observedEvidence: string;
  interpretation: string;
  whatItDoesNotProve: string;
  recommendedDefensiveCheck: string;
  relatedFlowIds: string[];
  relatedEventIds: string[];
}

export interface InvestigationFlowEvidence {
  id: string;
  firstSeen: string;
  lastSeen: string;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  protocol: string;
  service?: string;
  packetCount: number;
  byteCount: number;
  duration: number;
  direction: FlowSummary['direction'];
  riskLevel: FlowSummary['riskLevel'];
  relatedEventIds: string[];
}

export interface InvestigationEventEvidence {
  id: string;
  timestamp: string;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  protocol: string;
  service?: string;
  length: number;
  capturedLength?: number;
  originalLength?: number;
  sourceType?: string;
}

export interface InvestigationDnsEvidence {
  id: string;
  relatedEventIds: string[];
  timestamp: string;
  clientIp: string;
  query: string;
  queryType: string;
  response: string;
  rcode: string;
  riskLevel: DnsRecord['riskLevel'];
}

export interface InvestigationHttpEvidence {
  id: string;
  relatedEventIds: string[];
  timestamp: string;
  clientIp: string;
  host: string;
  method: string;
  uri: string;
  statusCode: number;
  cleartext: boolean;
  riskLevel: HttpRecord['riskLevel'];
}

export interface InvestigationTlsEvidence {
  id: string;
  relatedEventIds: string[];
  timestamp: string;
  clientIp: string;
  serverIp: string;
  sni: string;
  version?: string;
  ja3?: string;
  certificateSubject?: string;
  riskLevel: TlsRecord['riskLevel'];
}

export interface InvestigationEvidencePacket {
  version: '1';
  signal: InvestigationSignalEvidence;
  flows: InvestigationFlowEvidence[];
  events: InvestigationEventEvidence[];
  dns: InvestigationDnsEvidence[];
  http: InvestigationHttpEvidence[];
  tls: InvestigationTlsEvidence[];
  limitsApplied: {
    flowsTruncated: boolean;
    eventsTruncated: boolean;
    protocolRecordsTruncated: boolean;
  };
}

export interface InvestigationAssessment {
  summary: string;
  observedEvidence: Array<{
    statement: string;
    evidenceIds: string[];
  }>;
  inferences: Array<{
    statement: string;
    confidence: 'low' | 'medium' | 'high';
    evidenceIds: string[];
  }>;
  uncertainties: string[];
  nextSteps: Array<{
    action: string;
    reason: string;
  }>;
}

export interface AiAnalysisResult {
  executiveSummary: string;
  whatHappened: string;
  normalActivity: string;
  suspiciousActivity: string;
  keyEvidence: string;
  analystQuestions: string;
  recommendedChecks: string;
  beginnerExplanation: string;
  technicalExplanation: string;
  confidence: 'low' | 'medium' | 'high';
  limitations: string;
  reportReadySummary: string;
}

export interface AnalysisReport {
  id: string;
  createdAt: string;
  evidenceSummary: {
    name: string;
    type: string;
    size: number;
    parseMode: string;
    totalEvents: number;
    totalFlows: number;
  };
  scope: string;
  parserMethod: string;
  executiveSummary: string;
  trafficOverview: string;
  topFindings: string[];
  suspiciousSignals: string;
  timelineSummary: string;
  limitations: string;
  recommendedNextSteps: string;
  chainOfCustodyNotes: string;
  markdown: string;
}
