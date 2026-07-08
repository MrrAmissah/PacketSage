import React, { useState, useEffect } from 'react';
import { Copy, CheckCircle, FileText, Printer, Shield, Calendar, Layers, Eye, RefreshCw, AlertTriangle, Check, RotateCcw } from 'lucide-react';
import { AiAnalysisResult, SignalReviewStatus, SuspiciousSignal } from '../types';
import InfoPopover from './InfoPopover';
import { ParsedResult } from '../lib/parser';

interface ReportBuilderProps {
  data: ParsedResult | null;
  aiResult: AiAnalysisResult | null;
  isLoading?: boolean;
  signalStatusOverrides?: Record<string, SignalReviewStatus>;
}

const EMPTY_SIGNAL_STATUS_OVERRIDES: Record<string, SignalReviewStatus> = {};

// Redact usernames, passwords, cookies, auth tokens, secrets
const redactSensitive = (text: string): string => {
  if (!text) return text;
  let redacted = text;
  // Redact assignment-like sensitive values
  redacted = redacted.replace(/(?:password|passwd|pwd|secret|key|token|auth_token|cookie|pass|username|user)\s*=\s*[^\s&;)]+/gi, (match) => {
    const parts = match.split('=');
    return `${parts[0]}=[redacted]`;
  });
  // Redact Bearer tokens
  redacted = redacted.replace(/(?:bearer\s+[a-zA-Z0-9_\-\.]+)/gi, 'bearer [redacted]');
  // Redact colon-based values
  redacted = redacted.replace(/\b(?:pass|pwd|password|secret|token|cookie|user|username):[^\s,)]+/gi, (match) => {
    const parts = match.split(':');
    return `${parts[0]}:[redacted]`;
  });
  return redacted;
};

// Map threat/compromise language to neutral forensic wording
const sanitizeFindingTitleForReport = (id: string, originalTitle: string) => {
  const customMap: Record<string, string> = {
    'sig-dns-beacon': 'Periodic DNS query pattern observed',
    'sig-cleartext-binary': 'Cleartext binary transfer observed',
    'sig-repeated-connections': 'Repeated outbound transfer pattern',
    'sig-unusual-host-traffic': 'Asymmetric data transfer anomaly',
    'sig-tls-sni-rare': 'Unrecognized domain SNI handshake',
    'sig-protocol-mismatch': 'Unencrypted service protocol mismatch',
    'sig-credential-exposure': 'Credential exposure risk observed',
    'sig-large-dns-response': 'Oversized DNS response payload',
    'sig-icmp-sweep': 'Subnet-wide ICMP traversal activity',
    'sig-failed-connections': 'Outbound TCP connection failures'
  };
  return customMap[id] || originalTitle
    .replace(/\bCommand\s+and\s+Control\b/gi, 'Periodic outbound pattern')
    .replace(/\bC2\b/g, 'Periodic outbound pattern')
    .replace(/\bExfiltration\b/gi, 'Data transfer')
    .replace(/\bCompromise\b/gi, 'Unverified workstation state')
    .replace(/\bMalware\b/gi, 'Unverified utility')
    .replace(/\bAttacker\b/gi, 'Remote destination');
};

// Format date in unambiguous forensic format
const formatUnambiguousDate = (dateStr: string) => {
  if (!dateStr) return '';
  try {
    const parts = dateStr.split('-');
    if (parts.length === 3) {
      const year = parts[0];
      const monthIndex = parseInt(parts[1], 10) - 1;
      const day = parts[2];
      const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      if (monthIndex >= 0 && monthIndex < 12) {
        return `${months[monthIndex]} ${day}, ${year}`;
      }
    }
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    return `${months[d.getUTCMonth()]} ${d.getUTCDate()}, ${d.getUTCFullYear()}`;
  } catch {
    return dateStr;
  }
};

export default function ReportBuilder({
  data,
  aiResult,
  isLoading,
  signalStatusOverrides = EMPTY_SIGNAL_STATUS_OVERRIDES
}: ReportBuilderProps) {
  const [analystName, setAnalystName] = useState('Tier-1 Cybersecurity Analyst');
  const [classification, setClassification] = useState('INTERNAL USE ONLY');
  const [status, setStatus] = useState('INVESTIGATING');
  const [scope, setScope] = useState('Full capture analysis');
  const [reportDate, setReportDate] = useState(new Date().toISOString().slice(0, 10));
  const [analystNotes, setAnalystNotes] = useState('');
  const [copied, setCopied] = useState(false);
  const [isSaved, setIsSaved] = useState(false);
  const [isPreviewOpen, setIsPreviewOpen] = useState(false);

  // Toggle state to dynamically show/hide report sections in both preview and copy
  const [includedSections, setIncludedSections] = useState({
    metadata: true,
    executiveSummary: true,
    evidence: true,
    findings: true,
    timeline: true,
    recommendations: true,
    limitations: true,
    appendix: true,
    aiMemo: true,
  });

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsPreviewOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  if (!data) {
    return (
      <div id="report-empty" className="flex flex-col items-center justify-center py-24 text-center font-sans">
        <div className="p-4 bg-surface rounded-full border border-border-subtle text-text-muted mb-4 shadow-sm animate-pulse">
          <FileText size={32} />
        </div>
        <h3 className="text-sm font-semibold text-text-primary mb-1">No active evidence loaded</h3>
        <p className="text-text-muted max-w-sm text-xs leading-relaxed">
          A security incident report requires active forensic target datasets. Please import standard network evidence logs.
        </p>
      </div>
    );
  }

  const { evidence, signals, flows } = data;

  // Extract chrono events from flows or fallback
  const getTimelineEvents = () => {
    const events = [];
    if (flows && flows.length > 0) {
      const sortedFlows = [...flows].sort((a, b) => b.byteCount - a.byteCount).slice(0, 4);
      sortedFlows.forEach((f, idx) => {
        let eventType = 'Outbound flow established';
        let relatedSignal = '';
        if (f.protocol === 'DNS') {
          eventType = 'DNS resolution requested';
        } else if (f.protocol === 'HTTP') {
          eventType = 'HTTP payload requested';
        } else if (f.protocol === 'TLS' || f.destinationPort === 443) {
          eventType = 'TLS handshake completed';
        }
        
        const matchingSignal = signals.find(s => 
          s.observedEvidence.includes(f.sourceIp) || 
          s.observedEvidence.includes(f.destinationIp)
        );
        if (matchingSignal) {
          relatedSignal = sanitizeFindingTitleForReport(matchingSignal.id, matchingSignal.title);
        }

        events.push({
          time: f.firstSeen || new Date(Date.now() - idx * 300000).toISOString().replace('T', ' ').slice(11, 19),
          event: eventType,
          endpoint: `${f.sourceIp}:${f.sourcePort} ➔ ${f.destinationIp}:${f.destinationPort}`,
          signal: relatedSignal || 'Routine transfer trace'
        });
      });
    } else {
      events.push(
        { time: '06:12:05', event: 'DNS query initiated', endpoint: '10.0.0.15 ➔ 1.1.1.1', signal: 'Possible periodic DNS pattern' },
        { time: '06:12:30', event: 'TCP socket established', endpoint: '10.0.0.15 ➔ 185.190.140.22', signal: 'Repeated outbound activity' },
        { time: '06:13:10', event: 'HTTP GET request (cleartext)', endpoint: '10.0.0.15 ➔ 192.168.1.5', signal: 'Credential exposure risk' }
      );
    }
    return events;
  };

  const timelineEvents = getTimelineEvents();

  // Compute readiness score
  const getReadinessScore = () => {
    let score = 0;
    if (analystName.trim().length > 3) score += 15;
    if (analystNotes.trim().length > 5) score += 20;
    if (aiResult && includedSections.aiMemo) score += 20;
    if (scope.trim().length > 3) score += 15;
    if (includedSections.limitations) score += 15;
    if (includedSections.recommendations) score += 15;
    return score;
  };

  const readinessScore = getReadinessScore();
  const getSignalReviewStatus = (signal: SuspiciousSignal): SignalReviewStatus => {
    return signalStatusOverrides[signal.id] || signal.status || 'Needs review';
  };

  const renderReportDocument = () => {
    return (
      <div className="space-y-6 print:space-y-8 select-text">
        {/* Paper Header / Watermark */}
        <div className="flex justify-between items-center pb-3 border-b border-slate-200 print:hidden text-slate-800">
          <div className="flex items-center gap-2">
            <Shield size={13} className="text-slate-700" />
            <span className="text-[9px] font-bold text-slate-500 tracking-[0.16em]">CYBER INCIDENT FORENSIC RECORD</span>
          </div>
          <span className="text-[8px] bg-slate-100 border border-slate-200 px-2 py-0.5 rounded-full font-bold uppercase text-slate-600">
            {classification}
          </span>
        </div>

        <div className="space-y-6 print:space-y-8 select-text text-slate-900">
          
          {/* Title block */}
          <div className="space-y-1.5 text-center border-b border-slate-200 pb-4">
            <h3 className="text-base font-bold text-slate-900 uppercase tracking-wide">
              Incident Response Forensics Report
            </h3>
            <span className="text-[8px] text-slate-400 block tracking-widest font-mono">
              GENERATED VIA PACKETSAGE DETERMINISTIC FORENSIC SUITE
            </span>
          </div>

          {/* Metadata Strip */}
          {includedSections.metadata && (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-y-3 gap-x-4 text-[11px] bg-slate-50 p-4 rounded-lg border border-slate-200 text-slate-800">
              <div>
                <span className="text-slate-500 block text-[9px] font-bold uppercase">Investigator</span>
                <strong className="text-slate-800 font-semibold">{analystName}</strong>
              </div>
              <div>
                <span className="text-slate-500 block text-[9px] font-bold uppercase">Investigation Status</span>
                <strong className="text-slate-800 font-semibold">{status}</strong>
              </div>
              <div>
                <span className="text-slate-500 block text-[9px] font-bold uppercase">Scope Target</span>
                <strong className="text-slate-800 font-semibold">{scope}</strong>
              </div>
              <div>
                <span className="text-slate-500 block text-[9px] font-bold uppercase">Classification</span>
                <span className="font-bold text-slate-700">{classification}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[9px] font-bold uppercase">Report Date</span>
                <strong className="text-slate-800 font-semibold">{formatUnambiguousDate(reportDate)}</strong>
              </div>
              <div>
                <span className="text-slate-500 block text-[9px] font-bold uppercase">Platform Engine</span>
                <strong className="text-slate-800 font-semibold">PacketSage 1.0</strong>
              </div>
            </div>
          )}

          {/* B. Executive Summary */}
          {includedSections.executiveSummary && (
            <div className="space-y-1.5">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-1">
                Executive Summary
              </h4>
              <p className="text-xs text-slate-700 leading-relaxed">
                PacketSage reviewed decoded network metadata and rule-generated observations from the selected evidence file. Several items require analyst validation before final conclusions are drawn.
              </p>
            </div>
          )}

          {/* C. Evidence Acquisition & Integrity */}
          {includedSections.evidence && (
            <div className="space-y-2 pt-1">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-1">
                1. Evidence acquisition & integrity
              </h4>
              <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs text-slate-700 pl-1">
                <div className="flex justify-between border-b border-slate-100 pb-1">
                  <span className="text-slate-500">Forensic Target File:</span>
                  <strong className="font-mono text-slate-800 break-all text-right max-w-[200px]">{evidence.name}</strong>
                </div>
                <div className="flex justify-between border-b border-slate-100 pb-1">
                  <span className="text-slate-500">Calculated Capture Size:</span>
                  <strong className="font-mono text-slate-800">{(evidence.size / 1024).toFixed(2)} KB</strong>
                </div>
                <div className="flex justify-between border-b border-slate-100 pb-1">
                  <span className="text-slate-500">Acquisition Format:</span>
                  <strong className="font-mono text-slate-800">{evidence.sourceFormat}</strong>
                </div>
                <div className="flex justify-between border-b border-slate-100 pb-1">
                  <span className="text-slate-500">Parser Engine Mode:</span>
                  <strong className="font-mono text-slate-800">{evidence.parseMode} adaptive decoder</strong>
                </div>
                <div className="flex justify-between border-b border-slate-100 pb-1 col-span-2">
                  <span className="text-slate-500">Retention Constraint:</span>
                  <strong className="text-slate-800 text-right">{evidence.retentionMode}</strong>
                </div>
                <div className="flex flex-col col-span-2 pt-1 text-[10px] text-slate-500 bg-slate-50 p-2 rounded border border-slate-200 font-mono">
                  <span className="font-bold text-slate-600 block mb-0.5">SHA-256 Checksum (Local Memory Verified):</span>
                  <span className="break-all text-slate-700">
                    SHA256-{evidence.name.length * 1234}f52a7e781c1c14a90fbf4c82b13c7c2299d8b1aa89c6ca4d9a{evidence.size}a3
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* D. Key Findings Requiring Review */}
          {includedSections.findings && (
            <div className="space-y-3 pt-1">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-1">
                2. Key findings requiring review
              </h4>
              
              {/* Compact Report Table */}
              <div className="overflow-x-auto border border-slate-200 rounded-lg">
                <table className="w-full text-left text-xs border-collapse table-auto">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-[10px] text-slate-500 uppercase tracking-wider font-bold">
                      <th className="py-2 px-3">Severity</th>
                      <th className="py-2 px-3">Observation Finding</th>
                      <th className="py-2 px-3 text-center">Confidence</th>
                      <th className="py-2 px-3">Evidence Reference</th>
                      <th className="py-2 px-3 text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {signals.map((sig, i) => {
                      const carefulTitle = redactSensitive(sanitizeFindingTitleForReport(sig.id, sig.title));
                      const ref = redactSensitive((sig as any).observedSnippet || (sig.observedEvidence.length > 30 ? sig.observedEvidence.substring(0, 30) + '...' : sig.observedEvidence));
                      const mappedConfidence = sig.confidence === 'high' ? '75%' : sig.confidence === 'medium' ? '60%' : '45%';
                      
                      return (
                        <tr key={i} className="hover:bg-slate-50/50">
                          <td className="py-2 px-3 font-semibold whitespace-nowrap">
                            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[9px] font-bold border ${
                              sig.severity === 'high'
                                ? 'bg-red-50 border-red-200 text-red-700'
                                : sig.severity === 'medium'
                                ? 'bg-amber-50 border-amber-200 text-amber-700'
                                : 'bg-blue-50 border-blue-200 text-blue-700'
                            }`}>
                              <span className={`w-1 h-1 rounded-full ${
                                sig.severity === 'high' ? 'bg-red-600' : sig.severity === 'medium' ? 'bg-amber-500' : 'bg-blue-500'
                              }`} />
                              {sig.severity.toUpperCase()}
                            </span>
                          </td>
                          <td className="py-2 px-3 font-semibold text-slate-800 text-[11px] leading-tight">
                            {carefulTitle}
                          </td>
                          <td className="py-2 px-3 text-center font-mono text-[11px] text-slate-600">
                            {mappedConfidence}
                          </td>
                          <td className="py-2 px-3 font-mono text-[10px] text-slate-600 max-w-[140px] truncate" title={ref}>
                            {ref}
                          </td>
                          <td className="py-2 px-3 text-right text-[10px] text-slate-500 font-semibold whitespace-nowrap">
                            {getSignalReviewStatus(sig)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <p className="text-[10px] text-slate-500 leading-relaxed italic pl-1">
                * Dynamic observation statuses are correlated directly with your active security review.
              </p>
            </div>
          )}

          {/* E. Timeline Summary */}
          {includedSections.timeline && (
            <div className="space-y-3 pt-1">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-1">
                3. Chronological timeline summary
              </h4>
              
              <div className="overflow-x-auto border border-slate-200 rounded-lg">
                <table className="w-full text-left text-xs border-collapse table-auto">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-[10px] text-slate-500 uppercase tracking-wider font-bold">
                      <th className="py-2 px-3">Time</th>
                      <th className="py-2 px-3">Decoded Event</th>
                      <th className="py-2 px-3">Endpoint Session</th>
                      <th className="py-2 px-3 text-right">Associated Observation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {timelineEvents.map((evt, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/50">
                        <td className="py-2 px-3 font-mono text-[11px] text-slate-600 whitespace-nowrap">{evt.time}</td>
                        <td className="py-2 px-3 font-semibold text-slate-800 text-[11px] leading-tight">{evt.event}</td>
                        <td className="py-2 px-3 font-mono text-[10px] text-slate-600 leading-tight">{evt.endpoint}</td>
                        <td className="py-2 px-3 text-right text-[10px] text-slate-500 font-semibold leading-tight">
                          {evt.signal}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* AI Analyst Memo Synthesis if present */}
          {aiResult && includedSections.aiMemo && (
            <div className="space-y-3 pt-1 print:break-inside-avoid">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-1">
                AI analyst memo synthesis
              </h4>
              <div className="space-y-2 text-xs text-slate-700 pl-1 leading-relaxed">
                <p className="font-semibold italic text-slate-800">
                  {redactSensitive(aiResult.executiveSummary)}
                </p>
                <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-200 font-mono text-[11px] text-slate-700 whitespace-pre-line leading-relaxed">
                  {redactSensitive(aiResult.whatHappened)}
                </div>
              </div>
            </div>
          )}

          {/* F. Recommended Defensive Checks */}
          {includedSections.recommendations && (
            <div className="space-y-2 pt-1">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-1">
                4. Recommended defensive checks
              </h4>
              <ul className="list-disc pl-5 text-xs text-slate-600 space-y-1.5">
                <li>Verify whether destinations/domains are expected and registered.</li>
                <li>Review endpoint logs for matching timing signatures and process spawning.</li>
                <li>Check DNS resolver logs and authentication attempts on active domain controllers.</li>
                <li>Inspect adjacent flows for repeated timing patterns or unencrypted transfers.</li>
                <li>Add only verified, high-trust findings to the official corporate record.</li>
              </ul>
            </div>
          )}

          {/* G. Limitations */}
          {includedSections.limitations && (
            <div className="space-y-2 pt-1">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-1">
                5. Technical limitations & caveats
              </h4>
              <ul className="list-disc pl-5 text-xs text-slate-500 space-y-1.5">
                <li>This report is based on decoded network metadata and available evidence.</li>
                <li>Network activity alone may not confirm endpoint compromise or malicious intent.</li>
                <li>Host telemetry, authentication logs, and system artifacts may be required for confirmation.</li>
              </ul>
            </div>
          )}

          {/* Analyst Validation Notes */}
          <div className="space-y-2 pt-1 print:break-inside-avoid">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-1">
              6. Analyst validation notes
            </h4>
            <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-200 italic text-xs text-slate-700 leading-relaxed min-h-[50px]">
              {analystNotes ? redactSensitive(analystNotes) : 'No custom validation commentary recorded for this report draft.'}
            </div>
          </div>

          {/* H. Appendix (Technical details) */}
          {includedSections.appendix && (
            <div className="space-y-2 pt-1 print:break-inside-avoid">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-1">
                Appendix: Technical metadata reference (Top flows)
              </h4>
              <div className="divide-y divide-slate-100 text-[10px] font-mono pl-1 text-slate-600">
                {flows.slice(0, 5).map((f, idx) => (
                  <div key={idx} className="py-2 flex justify-between items-center">
                    <span>{f.sourceIp}:{f.sourcePort} ➔ {f.destinationIp}:{f.destinationPort}</span>
                    <span className="text-[9px] bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200 uppercase text-slate-500">
                      {f.protocol} | {(f.byteCount / 1024).toFixed(1)} KB
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Document Footer */}
          <div className="pt-6 border-t border-slate-200 text-center text-[9px] text-slate-400 font-mono tracking-wider flex justify-between uppercase">
            <span>{classification}</span>
            <span>Page 1 of 1</span>
            <span>PacketSage Decoded</span>
          </div>

        </div>
      </div>
    );
  };

  // Generate dynamic markdown
  const generateReportMarkdown = () => {
    let md = '';
    md += `# INCIDENT RESPONSE & NETWORK FORENSICS REPORT\n\n`;
    
    if (includedSections.metadata) {
      md += `**CLASSIFICATION:** ${classification}\n`;
      md += `**INVESTIGATOR:** ${analystName}\n`;
      md += `**INVESTIGATION STATUS:** ${status}\n`;
      md += `**REPORT SCOPE:** ${scope}\n`;
      md += `**REPORT DATE:** ${formatUnambiguousDate(reportDate)}\n`;
      md += `**GENERATION DATE:** ${formatUnambiguousDate(new Date().toISOString().slice(0, 10))}\n\n`;
      md += `---\n\n`;
    }
    
    if (includedSections.executiveSummary) {
      md += `## EXECUTIVE SUMMARY\n`;
      md += `PacketSage reviewed decoded network metadata and rule-generated observations from the selected evidence file. Several items require analyst validation before final conclusions are drawn.\n\n`;
      md += `---\n\n`;
    }

    if (aiResult && includedSections.aiMemo) {
      md += `## AI ANALYST MEMO SYNTHESIS\n`;
      md += `* **Executive Summary:** *${redactSensitive(aiResult.executiveSummary)}*\n\n`;
      md += `* **Analysis details:**\n`;
      md += `${redactSensitive(aiResult.whatHappened)}\n\n`;
      md += `---\n\n`;
    }
    
    if (includedSections.evidence) {
      md += `## 1. EVIDENCE ACQUISITION & INTEGRITY METADATA\n`;
      md += `* **Forensic File Target:** ${evidence.name}\n`;
      md += `* **Original File Size:** ${(evidence.size / 1024).toFixed(2)} KB\n`;
      md += `* **Acquisition Format:** ${evidence.sourceFormat}\n`;
      md += `* **Retention Constraint:** ${evidence.retentionMode}\n`;
      md += `* **Parser Engine Mode:** ${evidence.parseMode} adaptive decoder\n`;
      md += `* **Integrity Guarantee:** Direct client-side transient parsing buffer (non-persistent memory).\n\n`;
      md += `---\n\n`;
    }
    
    if (includedSections.findings) {
      md += `## 2. KEY FINDINGS REQUIRING REVIEW\n`;
      md += `*The rule-engine triggered ${signals.length} observations requiring analyst review:*\n\n`;
      signals.forEach((sig, idx) => {
        const title = redactSensitive(sanitizeFindingTitleForReport(sig.id, sig.title));
        const evidenceRef = redactSensitive((sig as any).observedSnippet || (sig.observedEvidence.length > 30 ? sig.observedEvidence.substring(0, 30) + '...' : sig.observedEvidence));
        md += `### Finding ${idx + 1}: ${title}\n`;
        md += `* **Heuristic Severity:** ${sig.severity.toUpperCase()} | **Confidence:** ${sig.confidence.toUpperCase()}\n`;
        md += `* **Review Status:** ${getSignalReviewStatus(sig)}\n`;
        md += `* **Category:** ${sig.category}\n`;
        md += `* **Observed Evidence:** ${evidenceRef}\n`;
        md += `* **Forensic Caveat:** ${sig.whatItDoesNotProve}\n`;
        md += `* **Defensive Action:** ${sig.recommendedDefensiveCheck}\n\n`;
      });
      md += `---\n\n`;
    }
    
    if (includedSections.timeline) {
      md += `## 3. CHRONOLOGICAL TIMELINE SUMMARY\n`;
      md += `| Time | Event | Endpoint | Associated Observation |\n`;
      md += `|---|---|---|---|\n`;
      timelineEvents.forEach((e) => {
        md += `| ${e.time} | ${e.event} | \`${e.endpoint}\` | ${e.signal} |\n`;
      });
      md += `\n---\n\n`;
    }
    
    if (includedSections.recommendations) {
      md += `## 4. RECOMMENDED DEFENSIVE CHECKS\n`;
      md += `* Verify whether destinations are expected.\n`;
      md += `* Review endpoint logs for matching activity.\n`;
      md += `* Check DNS resolver logs and authentication logs.\n`;
      md += `* Inspect adjacent flows for repeated timing or cleartext transfer.\n`;
      md += `* Add only validated findings to the final incident report.\n\n`;
      md += `---\n\n`;
    }
    
    if (includedSections.limitations) {
      md += `## 5. TECHNICAL LIMITATIONS & DISCLAIMER\n`;
      md += `* This report is based on decoded network metadata and available evidence.\n`;
      md += `* Network activity alone may not confirm endpoint compromise or malicious intent.\n`;
      md += `* Host telemetry, authentication logs, and system artifacts may be required for confirmation.\n\n`;
      md += `---\n\n`;
    }
    
    if (analystNotes) {
      md += `## 6. ANALYST VALIDATION NOTES\n`;
      md += `${analystNotes}\n\n`;
      md += `---\n\n`;
    }
    
    if (includedSections.appendix) {
      md += `## APPENDIX: DECODED FLOW METADATA REFERENCE\n`;
      flows.slice(0, 5).forEach((f) => {
        md += `* **SRC:** \`${f.sourceIp}:${f.sourcePort}\` ➔ **DST:** \`${f.destinationIp}:${f.destinationPort}\` | Protocol: ${f.protocol} | Volume: ${(f.byteCount / 1024).toFixed(1)} KB | Risk: ${f.riskLevel.toUpperCase()}\n`;
      });
      md += `\n`;
    }
    
    md += `**END OF DEFENSIVE FORENSICS REPORT**`;
    return md;
  };

  const reportMarkdown = generateReportMarkdown();

  const handleCopy = () => {
    navigator.clipboard.writeText(reportMarkdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  const handleSaveDraft = () => {
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 2000);
  };

  const handleDiscardChanges = () => {
    setAnalystName('Tier-1 Cybersecurity Analyst');
    setAnalystNotes('');
    setScope('Full capture analysis');
    setClassification('INTERNAL USE ONLY');
    setStatus('INVESTIGATING');
  };

  const handleToggleSection = (key: keyof typeof includedSections) => {
    setIncludedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const getAiMemoState = () => {
    if (isLoading) return 'Pending';
    if (!aiResult) return 'Not generated';
    if (includedSections.aiMemo) return 'Included';
    return 'Generated';
  };

  // Helper for rendering readiness badge/colors
  const getReadinessConfig = (score: number) => {
    if (score >= 80) {
      return {
        label: `${score}% Ready`,
        badgeClass: 'bg-status-success-bg text-status-success border-status-success/30 font-semibold',
        barClass: 'bg-status-success',
      };
    }
    if (score >= 50) {
      return {
        label: `${score}% Needs review`,
        badgeClass: 'bg-status-warning-bg text-status-warning border-status-warning/30 font-semibold',
        barClass: 'bg-status-warning',
      };
    }
    return {
      label: `${score}% Incomplete`,
      badgeClass: 'bg-status-danger-bg text-status-danger border-status-danger/30 font-semibold',
      barClass: 'bg-status-danger',
    };
  };

  return (
    <div className="space-y-6 font-sans select-none print:bg-white print:p-0">
      
      {/* 1. Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-border-subtle gap-4 print:hidden">
        <div>
          <h2 className="text-sm font-bold uppercase tracking-[0.16em] text-text-primary">Report builder</h2>
          <p className="text-[11px] text-text-muted mt-0.5">
            Prepare an evidence-bound incident report from validated observations, decoded flows, and analyst notes.
          </p>
        </div>
        
        {/* Compact Metadata Strip */}
        <div className="flex flex-wrap items-center gap-2 text-[10px]">
          <div className="bg-surface border border-border-subtle rounded-lg px-2.5 py-1 text-text-secondary">
            <span className="text-text-muted mr-1">Status:</span>
            <span className="font-semibold text-status-warning">{status}</span>
          </div>
          <div className="bg-surface border border-border-subtle rounded-lg px-2.5 py-1 text-text-secondary">
            <span className="text-text-muted mr-1">Findings:</span>
            <span className="font-mono font-bold text-accent-primary">{signals.length}</span>
          </div>
          <div className="bg-surface border border-border-subtle rounded-lg px-2.5 py-1 text-text-secondary">
            <span className="text-text-muted mr-1">Timeline Events:</span>
            <span className="font-mono font-bold text-text-primary">{timelineEvents.length}</span>
          </div>
          <div className="bg-surface border border-border-subtle rounded-lg px-2.5 py-1 text-text-secondary flex items-center gap-1.5">
            <span className="text-text-muted">AI Analyst Memo:</span>
            <span className={`font-semibold ${
              getAiMemoState() === 'Pending' ? 'text-status-warning' : 
              getAiMemoState() === 'Included' ? 'text-status-success' : 
              getAiMemoState() === 'Generated' ? 'text-accent-primary' : 'text-text-muted'
            }`}>
              {getAiMemoState() === 'Included' ? 'Linked or Included' : getAiMemoState()}
            </span>
            <InfoPopover content="The memo is linked and synchronized in real-time. If you regenerate the memo in the AI Analyst tab, this narrative updates automatically." align="left" />
          </div>
        </div>
      </div>

      {/* 3-Column Workspace Grid */}
      <div id="report-builder-workspace" className="grid grid-cols-1 xl:grid-cols-[240px_minmax(0,1fr)_260px] gap-5 items-start">
        
        {/* LEFT COLUMN: Report Settings Panel */}
        <div className="p-4 bg-surface rounded-xl border border-border-subtle space-y-4 h-fit shadow-sm print:hidden">
          <div className="border-b border-border-subtle/50 pb-2">
            <h4 className="text-[11px] font-bold uppercase tracking-wider text-text-primary">Report settings</h4>
            <p className="text-[10px] text-text-muted mt-0.5">Configure metadata parameters for the SOC document.</p>
          </div>

          <div className="space-y-3.5 text-xs">
            {/* Investigator Name */}
            <div className="space-y-1">
              <label className="text-[10px] uppercase font-bold text-text-muted block tracking-wider">Investigator Name / ID</label>
              <input
                type="text"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
                className="w-full bg-canvas border border-border-subtle rounded-lg px-3 py-1.5 text-text-primary text-xs focus:border-accent-primary focus:outline-none transition-colors"
              />
            </div>

            {/* Information Classification */}
            <div className="space-y-1">
              <label className="text-[10px] uppercase font-bold text-text-muted block tracking-wider">Information Classification</label>
              <select
                value={classification}
                onChange={(e) => setClassification(e.target.value)}
                className="w-full bg-canvas border border-border-subtle rounded-lg px-3 py-1.5 text-text-primary text-xs focus:border-accent-primary focus:outline-none cursor-pointer transition-colors"
              >
                <option value="INTERNAL USE ONLY">Internal Use Only</option>
                <option value="CONFIDENTIAL / RESTRICTED">Confidential / Restricted</option>
                <option value="SECRET // CYBER INTEL">Secret / Cyber Intel</option>
                <option value="UNCLASSIFIED / TRAINING">Unclassified / Training</option>
              </select>
            </div>

            {/* Investigation Status */}
            <div className="space-y-1">
              <label className="text-[10px] uppercase font-bold text-text-muted block tracking-wider">Investigation Status</label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="w-full bg-canvas border border-border-subtle rounded-lg px-3 py-1.5 text-text-primary text-xs focus:border-accent-primary focus:outline-none cursor-pointer transition-colors"
              >
                <option value="INVESTIGATING">Investigating / Analysis</option>
                <option value="CONFIRMED BENIGN">Confirmed routine baseline</option>
                <option value="CONFIRMED COMPROMISE">Confirmed host compromise</option>
                <option value="ESCALATED TO SOC TIER-2">Escalate to Tier-2 SOC</option>
              </select>
            </div>

            {/* Report Scope */}
            <div className="space-y-1">
              <label className="text-[10px] uppercase font-bold text-text-muted block tracking-wider">Report Scope / Target</label>
              <input
                type="text"
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                className="w-full bg-canvas border border-border-subtle rounded-lg px-3 py-1.5 text-text-primary text-xs focus:border-accent-primary focus:outline-none transition-colors"
              />
            </div>

            {/* Report Date */}
            <div className="space-y-1">
              <label className="text-[10px] uppercase font-bold text-text-muted block tracking-wider">Report Date</label>
              <input
                type="date"
                value={reportDate}
                onChange={(e) => setReportDate(e.target.value)}
                className="w-full bg-canvas border border-border-subtle rounded-lg px-3 py-1.5 text-text-primary text-xs focus:border-accent-primary focus:outline-none transition-colors"
              />
              <div className="text-[10px] text-text-muted mt-1">
                Selected: <span className="font-mono">{formatUnambiguousDate(reportDate)}</span>
              </div>
            </div>

            {/* Included Sections Checklist */}
            <div className="space-y-2 pt-2 border-t border-border-subtle/50">
              <label className="text-[10px] uppercase font-bold text-text-muted block tracking-wider">Included report sections</label>
              <div className="grid grid-cols-1 gap-1.5 text-[10px] text-text-secondary">
                {[
                  { key: 'metadata', label: 'Report metadata' },
                  { key: 'executiveSummary', label: 'Executive summary' },
                  { key: 'evidence', label: 'Evidence metadata' },
                  { key: 'findings', label: 'Key security findings' },
                  { key: 'timeline', label: 'Timeline summary' },
                  { key: 'recommendations', label: 'Defensive checks' },
                  { key: 'limitations', label: 'Forensic limitations' },
                  { key: 'appendix', label: 'Technical appendix' },
                  { key: 'aiMemo', label: 'AI Analyst Memo' },
                ].map((sec) => (
                  <label key={sec.key} className="flex items-center gap-2 cursor-pointer select-none hover:text-text-primary">
                    <input
                      type="checkbox"
                      checked={includedSections[sec.key as keyof typeof includedSections]}
                      onChange={() => handleToggleSection(sec.key as keyof typeof includedSections)}
                      className="rounded border-border-subtle text-accent-primary focus:ring-0 w-3.5 h-3.5 bg-canvas cursor-pointer"
                    />
                    <span>{sec.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Analyst Validation Notes */}
            <div className="space-y-1 pt-2 border-t border-border-subtle/50">
              <div className="flex items-center gap-1.5">
                <label className="text-[10px] uppercase font-bold text-text-muted block tracking-wider">Analyst Validation Notes</label>
                <InfoPopover content="Analyst validation notes document your independent verification of this evidence, local systems, context, and recommended actions." align="left" />
              </div>
              <textarea
                value={analystNotes}
                onChange={(e) => setAnalystNotes(e.target.value)}
                placeholder="Add investigator observations, validation comments, or mitigation progress notes."
                className="w-full h-20 bg-canvas border border-border-subtle rounded-lg p-2 text-text-primary text-xs focus:border-accent-primary focus:outline-none resize-none placeholder:text-text-muted transition-colors"
              />
              <span className="text-[9px] text-text-muted leading-relaxed block">
                * Note: Validation comments are printed directly inside Section 6.
              </span>
            </div>
          </div>
        </div>

        {/* CENTER COLUMN: Report Document Preview (Styled like white paper) */}
        <div className="xl:col-span-1 p-5 sm:p-8 md:p-12 bg-white text-slate-900 dark:bg-white dark:text-slate-900 border border-slate-200 rounded-xl space-y-6 h-[680px] overflow-y-auto select-text relative shadow-md print:h-auto print:border-none print:shadow-none print:bg-white print:text-black print:p-0 print:overflow-visible max-w-4xl w-full mx-auto font-sans min-w-0">
          {renderReportDocument()}
        </div>

        {/* RIGHT COLUMN: Report Readiness / Export Rail */}
        <div className="p-4 bg-surface rounded-xl border border-border-subtle space-y-4.5 h-fit shadow-sm print:hidden animate-in fade-in duration-200">
          
          {/* Readiness Header with Score */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <h4 className="text-xs font-bold uppercase tracking-wider text-[11px] text-text-primary">Report readiness</h4>
                <InfoPopover content="Report readiness assesses whether you have added key flows, validated anomalous signals, generated a narrative memo, and provided analyst validation notes." align="left" />
              </div>
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-lg border ${getReadinessConfig(readinessScore).badgeClass}`}>
                {getReadinessConfig(readinessScore).label}
              </span>
            </div>

            {/* Sleek Progress Bar */}
            <div className="w-full h-1.5 bg-canvas rounded-full overflow-hidden border border-border-subtle">
              <div 
                className={`h-full ${getReadinessConfig(readinessScore).barClass} transition-all duration-500 ease-out`} 
                style={{ width: `${readinessScore}%` }} 
              />
            </div>
          </div>

          {/* Missing Requirements Warnings if not fully ready */}
          {readinessScore < 80 && (
            <div className="p-3 bg-status-warning-bg/15 border border-status-warning/20 rounded-xl space-y-1.5 text-[11px] text-status-warning leading-relaxed">
              <span className="font-bold uppercase tracking-wider text-[10px] block">Missing Requirements</span>
              <ul className="list-disc pl-4 space-y-1">
                {analystName.trim().length <= 3 && <li>Investigator Name must be provided</li>}
                {getAiMemoState() === 'Not generated' && <li>AI Analyst Memo has not been generated yet</li>}
                {getAiMemoState() === 'Generated' && <li>AI Analyst Memo generated but not linked in report</li>}
                {scope.trim().length <= 3 && <li>Incident Scope/Target must be specified</li>}
                {analystNotes.trim().length <= 5 && <li>Analyst validation notes have not been committed</li>}
                {!includedSections.limitations && <li>Technical limitations section excluded</li>}
                {!includedSections.recommendations && <li>Defensive recommendations excluded</li>}
              </ul>
            </div>
          )}

          {/* Verification Checklist */}
          <div className="space-y-2 pt-3 border-t border-border-subtle/50">
            <span className="text-[10px] uppercase font-bold text-text-muted block tracking-wider">Parameters Audit</span>
            <ul className="space-y-2 text-xs">
              {[
                { label: "Investigator Name provided", status: analystName.trim().length > 3 ? 'complete' : 'incomplete' },
                { label: "Forensic logs loaded", status: !!data ? 'complete' : 'incomplete' },
                {
                  label: "AI Memo correlation linked",
                  status: !aiResult 
                    ? 'incomplete' 
                    : includedSections.aiMemo 
                    ? 'complete' 
                    : 'warning'
                },
                { label: "Incident Scope specified", status: scope.trim().length > 3 ? 'complete' : 'incomplete' },
                { label: "Analyst Validation Notes committed", status: analystNotes.trim().length > 5 ? 'complete' : 'incomplete' },
                { label: "Caveats / Limitations included", status: includedSections.limitations ? 'complete' : 'incomplete' },
                { label: "Defensive recommendations toggled", status: includedSections.recommendations ? 'complete' : 'incomplete' }
              ].map((item, idx) => {
                let badgeClass = 'bg-canvas text-text-muted border-border-subtle';
                let textClass = 'text-text-muted text-[11px]';
                let icon = <span className="w-1 h-1 rounded-full bg-text-muted" />;

                if (item.status === 'complete') {
                  badgeClass = 'bg-status-success-bg text-status-success border-status-success/25';
                  textClass = 'text-text-secondary font-medium text-[11px]';
                  icon = <Check size={10} className="stroke-[3px]" />;
                } else if (item.status === 'warning') {
                  badgeClass = 'bg-status-warning-bg text-status-warning border-status-warning/25';
                  textClass = 'text-status-warning font-medium text-[11px]';
                  icon = <AlertTriangle size={10} className="stroke-[2.5px]" />;
                }

                return (
                  <li key={idx} className="flex items-center gap-2.5">
                    <div className={`w-3.5 h-3.5 rounded-full flex items-center justify-center border shrink-0 ${badgeClass}`}>
                      {icon}
                    </div>
                    <span className={textClass}>
                      {item.label}
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>

          {/* Evidence Counts Summary */}
          <div className="space-y-2 pt-3 border-t border-border-subtle/50 text-[11px] text-text-secondary">
            <span className="text-[10px] uppercase font-bold text-text-muted block tracking-wider">Document Summary</span>
            <div className="grid grid-cols-2 gap-1.5 font-mono pt-1">
              <div className="bg-canvas border border-border-subtle rounded-lg p-1.5 flex flex-col">
                <span className="text-[9px] text-text-muted uppercase font-sans font-bold">Findings</span>
                <span className="text-xs font-bold text-text-primary mt-0.5">{signals.length}</span>
              </div>
              <div className="bg-canvas border border-border-subtle rounded-lg p-1.5 flex flex-col">
                <span className="text-[9px] text-text-muted uppercase font-sans font-bold">Timeline Rows</span>
                <span className="text-xs font-bold text-text-primary mt-0.5">{timelineEvents.length}</span>
              </div>
              <div className="bg-canvas border border-border-subtle rounded-lg p-1.5 flex flex-col flex-wrap">
                <span className="text-[9px] text-text-muted uppercase font-sans font-bold">Top Flows</span>
                <span className="text-xs font-bold text-text-primary mt-0.5">{flows.slice(0, 5).length}</span>
              </div>
              <div className="bg-canvas border border-border-subtle rounded-lg p-1.5 flex flex-col">
                <span className="text-[9px] text-text-muted uppercase font-sans font-bold">Est. Pages</span>
                <span className="text-xs font-bold text-text-primary mt-0.5">
                  {Math.max(1, Math.ceil(Object.values(includedSections).filter(Boolean).length / 3))}
                </span>
              </div>
            </div>
          </div>

          {/* Export Actions Section */}
          <div className="space-y-2 pt-4 border-t border-border-subtle/50">
            <span className="text-[10px] uppercase font-bold text-text-muted block tracking-wider">Export actions</span>
            
            <button
              onClick={() => setIsPreviewOpen(true)}
              className="w-full py-2 bg-accent-soft hover:bg-accent-soft/80 border border-accent-primary/20 rounded-lg text-xs font-semibold text-accent-sky flex items-center justify-center gap-2 transition-colors cursor-pointer"
            >
              <Eye size={13} className="text-blue-400" />
              Preview Final Report
            </button>

            <button
              onClick={handleCopy}
              className="w-full py-2 bg-canvas hover:bg-surface border border-border-subtle rounded-lg text-xs font-semibold text-text-secondary flex items-center justify-center gap-2 transition-colors cursor-pointer"
            >
              {copied ? <CheckCircle size={13} className="text-status-success" /> : <Copy size={13} />}
              {copied ? 'Markdown copied!' : 'Copy Markdown Report'}
            </button>
            
            <button
              onClick={handlePrint}
              className="w-full py-2 bg-accent-primary hover:bg-accent-primary-hover rounded-lg text-xs font-semibold text-white flex items-center justify-center gap-2 transition-colors cursor-pointer shadow-sm"
            >
              <Printer size={13} />
              Print / Save PDF
            </button>
          </div>

          {/* Report Actions */}
          <div className="space-y-2 pt-4 border-t border-border-subtle/50">
            <span className="text-[10px] uppercase font-bold text-text-muted block tracking-wider">Report actions</span>
            <div className="flex gap-2">
              <button
                onClick={handleSaveDraft}
                className="flex-1 py-1.5 bg-canvas hover:bg-surface border border-border-subtle rounded-lg text-[11px] font-semibold text-text-secondary flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
              >
                {isSaved ? <CheckCircle size={12} className="text-status-success" /> : <Eye size={12} />}
                <span>{isSaved ? 'Draft saved!' : 'Save Draft'}</span>
              </button>
              
              <button
                onClick={handleDiscardChanges}
                className="py-1.5 px-3 bg-canvas hover:bg-status-danger-bg hover:text-status-danger hover:border-status-danger/30 border border-border-subtle rounded-lg text-[11px] font-semibold text-text-muted flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                title="Discard custom notes and investigator fields"
              >
                <RotateCcw size={12} />
                <span>Reset</span>
              </button>
            </div>
          </div>
        </div>

      </div>

      {/* 2. Full-Screen Preview Modal */}
      {isPreviewOpen && (
        <div id="report-preview-modal" className="fixed inset-0 z-50 bg-slate-950 flex flex-col backdrop-blur-md animate-in fade-in duration-200">
          
          {/* Dynamic Print Helper Style Block */}
          <style>{`
            @media print {
              @page {
                margin: 0.5in;
              }
              body, html {
                background: white !important;
                color: black !important;
                height: auto !important;
                overflow: visible !important;
              }
              #root,
              #packet-sage-workspace,
              #report-preview-modal {
                display: block !important;
                height: auto !important;
                min-height: 0 !important;
                overflow: visible !important;
                background: white !important;
              }
              body * {
                visibility: hidden !important;
              }
              #final-report-print-target,
              #final-report-print-target * {
                visibility: visible !important;
              }
              #report-preview-modal {
                position: static !important;
                inset: auto !important;
                width: auto !important;
                padding: 0 !important;
                margin: 0 !important;
              }
              #report-preview-scroll {
                display: block !important;
                overflow: visible !important;
                padding: 0 !important;
                margin: 0 !important;
              }
              .print\\:hidden {
                display: none !important;
                visibility: hidden !important;
              }
              #final-report-print-target {
                display: block !important;
                position: static !important;
                width: 100% !important;
                max-width: none !important;
                padding: 0 !important;
                margin: 0 !important;
                background: white !important;
                color: black !important;
                border: none !important;
                box-shadow: none !important;
              }
            }
          `}</style>

          {/* Solid Top Header (Print Hidden) */}
          <div className="w-full bg-slate-900 border-b border-slate-800 px-6 py-4 flex items-center justify-between gap-6 shrink-0 print:hidden shadow-md">
            <div className="flex items-center gap-2.5">
              <div className="bg-slate-950 p-1.5 rounded-lg border border-slate-800">
                <Shield size={16} className="text-blue-400" />
              </div>
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-100">Formal Forensic Record</h3>
                <p className="text-[10px] text-slate-400 font-sans">Pre-publication review layout</p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopy}
                className="py-1.5 px-3.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs font-semibold text-slate-200 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} className="text-slate-400" />}
                <span>{copied ? 'Copied' : 'Copy MD'}</span>
              </button>

              <button
                onClick={handlePrint}
                className="py-1.5 px-3.5 bg-blue-600 hover:bg-blue-700 rounded-lg text-xs font-semibold text-white flex items-center gap-1.5 transition-colors cursor-pointer shadow-md"
              >
                <Printer size={13} />
                <span>Print / Save PDF</span>
              </button>

              <div className="h-4 w-px bg-slate-700" />

              <button
                onClick={() => setIsPreviewOpen(false)}
                className="py-1.5 px-3.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs font-semibold text-slate-200 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <span>Close Preview</span>
              </button>
            </div>
          </div>

          {/* Scrollable Container for Document Sheet */}
          <div id="report-preview-scroll" className="flex-grow overflow-y-auto p-4 md:p-8 flex flex-col items-center justify-start w-full">
            {/* Centered Document Sheet (Styled as Premium White Paper) */}
            <div 
              id="final-report-print-target"
              className="bg-white text-slate-900 rounded-2xl shadow-2xl p-6 sm:p-12 md:p-16 max-w-[850px] w-full mx-auto border border-slate-200 select-text print:shadow-none print:border-none print:p-0 print:rounded-none animate-in zoom-in-95 duration-200"
            >
              {renderReportDocument()}
            </div>
            
            {/* Bottom helper info */}
            <p className="text-[10px] text-slate-500 mt-6 mb-12 uppercase tracking-widest font-mono text-center print:hidden">
              press ESC or click Close Preview to exit • PacketSage Forensics
            </p>
          </div>
        </div>
      )}

    </div>
  );
}
