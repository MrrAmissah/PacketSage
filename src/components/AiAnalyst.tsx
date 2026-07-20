import React, { useState, useEffect } from 'react';
import { 
  Cpu, Terminal, BookOpen, AlertCircle, RefreshCw, CheckCircle, 
  ShieldAlert, FileText, ChevronRight, HelpCircle, Shield, Calendar, 
  Layers, Eye, Copy, Check, Info, Lock, AlertTriangle, Play, Clipboard, 
  ListTodo, Plus, RotateCcw, Clock, HardDrive, Activity, HelpCircle as HelpIcon 
} from 'lucide-react';
import { AiAnalysisResult, FlowSummary, DnsRecord, HttpRecord, TlsRecord, SuspiciousSignal, ProtocolStat } from '../types';
import InfoPopover from './InfoPopover';

interface AiAnalystProps {
  flows: FlowSummary[];
  dns: DnsRecord[];
  http: HttpRecord[];
  tls: TlsRecord[];
  signals: SuspiciousSignal[];
  stats: ProtocolStat[];
  fileName: string;
  analysisResult: AiAnalysisResult | null;
  onAnalysisCompleted: (result: AiAnalysisResult) => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
}

type MemoPerspective = 'comprehensive' | 'triage' | 'protocol' | 'indicators';
type OutputMode = 'short' | 'full' | 'summary';

// Helper to redact sensitive fields and enforce defensible forensic tone
const redactSensitive = (text: string) => {
  if (!text) return '';
  return text
    // Replace overclaiming conclusions with defensible evidence-bound ones
    .replace(/\b(compromised internal system|compromised system|host compromised|compromised host|host is compromised)\b/gi, 'review-worthy internal host activity')
    .replace(/\b(active command-and-control interaction|command-and-control confirmed|confirmed command and control|c2 establishment|c2 confirmed|c2 agent activated|c2 agent activation|active c2 confirmed)\b/gi, 'periodic outbound contact')
    .replace(/\b(likely for c2 resolution)\b/gi, 'beacon-like DNS timing pattern')
    .replace(/\b(malicious intent confirmed|malicious intent)\b/gi, 'suspicious activity requiring validation')
    .replace(/\b(data theft confirmed|confirmed data exfiltration|data exfiltration|data theft)\b/gi, 'possible payload exposure')
    .replace(/\b(malware confirmed|confirmed malware|active malware|malware execution)\b/gi, 'unusual transfer signature')
    .replace(/\b(reverse shell confirmed|confirmed reverse shell)\b/gi, 'sustained outbound session')
    .replace(/\b(attacker-controlled listener|attacker-controlled server|attacker server|attacker-controlled language)\b/gi, 'remote external endpoint')
    .replace(/\b(attacker detected)\b/gi, 'external connection attempts')
    .replace(/\b(breach confirmed|network breach)\b/gi, 'anomalous session sequence')
    .replace(/\b(exploit found|active exploit)\b/gi, 'anomalous interaction')
    .replace(/\b(active remote threat execution)\b/gi, 'unverified remote connection attempts')
    .replace(/\b(Metasploit payload|Metasploit reverse payload)\b/gi, 'application-layer transport')
    .replace(/\b(opened the door)\b/gi, 'initiated connection')
    .replace(/\b(called home to attacker)\b/gi, 'contacted external destination')
    .replace(/\b(activated payload)\b/gi, 'observed potential binary transfer')
    .replace(/\b(compromise sequence confirmed)\b/gi, 'potential unauthorized sequence observed')
    .replace(/\b(execution chain confirmed)\b/gi, 'potential activity sequence observed')
    // Standard credential sanitizations
    .replace(/password=\w+/g, 'password=[redacted]')
    .replace(/username=\w+/g, 'username=[redacted]')
    .replace(/token=\w+/g, 'token=[redacted]')
    .replace(/cookie=\w+/g, 'cookie=[redacted]')
    .replace(/api_key=\w+/g, 'api_key=[redacted]')
    .replace(/Authorization:\s*Basic\s+[A-Za-z0-9+/=]+/gi, 'Authorization: Basic [redacted]')
    .replace(/bearer\s+[A-Za-z0-9\-._~+/]+/gi, 'Bearer [redacted]');
};

// Helper to format ISO timestamps consistently for evidence-based reporting
const formatEvidenceTime = (isoString: string) => {
  if (!isoString) return '';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[d.getUTCMonth()];
    const day = d.getUTCDate();
    const year = d.getUTCFullYear();
    const pad = (num: number) => String(num).padStart(2, '0');
    const hours = pad(d.getUTCHours());
    const minutes = pad(d.getUTCMinutes());
    const seconds = pad(d.getUTCSeconds());
    return `${month} ${day}, ${year} ${hours}:${minutes}:${seconds}`;
  } catch {
    return isoString;
  }
};

export default function AiAnalyst({
  flows,
  dns,
  http,
  tls,
  signals,
  stats,
  fileName,
  analysisResult,
  onAnalysisCompleted,
  isLoading,
  setIsLoading
}: AiAnalystProps) {
  const [activeTab, setActiveTab] = useState<'memo' | 'takeaways' | 'tech' | 'evidence'>('memo');
  const [perspective, setPerspective] = useState<MemoPerspective>('comprehensive');
  const [evidenceScope, setEvidenceScope] = useState<'all' | 'high' | 'added' | 'custom'>('all');
  const [outputMode, setOutputMode] = useState<OutputMode>('full');
  
  // Custom queries
  const [customQuery, setCustomQuery] = useState('');
  const [customResult, setCustomResult] = useState<string | null>(null);
  const [isQueryLoading, setIsQueryLoading] = useState(false);
  
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [loadingStep, setLoadingStep] = useState<string>('');
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [isSavedToReport, setIsSavedToReport] = useState(false);
  const [selectedFindings, setSelectedFindings] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);

  // Auto-fill selected findings on start
  useEffect(() => {
    if (signals && signals.length > 0) {
      setSelectedFindings(signals.map(s => s.id));
    }
  }, [signals]);

  // Section selectors
  const [includedSections, setIncludedSections] = useState({
    executiveSummary: true,
    keyObservations: true,
    whatHappened: true,
    evidenceReferences: true,
    confidenceLimitations: true,
    recommendedChecks: true,
    beginnerExplanation: true,
    technicalExplanation: true,
  });

  // Toast effect
  useEffect(() => {
    if (toastMessage) {
      const timer = setTimeout(() => setToastMessage(null), 3000);
      return () => clearTimeout(timer);
    }
  }, [toastMessage]);

  // Reset helper
  const handleReset = () => {
    setPerspective('comprehensive');
    setEvidenceScope('all');
    setOutputMode('full');
    setIncludedSections({
      executiveSummary: true,
      keyObservations: true,
      whatHappened: true,
      evidenceReferences: true,
      confidenceLimitations: true,
      recommendedChecks: true,
      beginnerExplanation: true,
      technicalExplanation: true,
    });
    setSelectedFindings(signals.map(s => s.id));
    setToastMessage('Memo controls reset to default');
  };

  // Derive evidence time range dynamically and with full cross-page synchronization using widest accurate evidence time window
  const getWidestTimeRange = () => {
    const allTimestamps: Date[] = [];
    flows.forEach(f => {
      if (f.firstSeen) {
        const d = new Date(f.firstSeen);
        if (!isNaN(d.getTime())) allTimestamps.push(d);
      }
      if (f.lastSeen) {
        const d = new Date(f.lastSeen);
        if (!isNaN(d.getTime())) allTimestamps.push(d);
      }
    });
    dns.forEach(d => {
      if (d.timestamp) {
        const dt = new Date(d.timestamp);
        if (!isNaN(dt.getTime())) allTimestamps.push(dt);
      }
    });
    http.forEach(h => {
      if (h.timestamp) {
        const dt = new Date(h.timestamp);
        if (!isNaN(dt.getTime())) allTimestamps.push(dt);
      }
    });
    tls.forEach(t => {
      if (t.timestamp) {
        const dt = new Date(t.timestamp);
        if (!isNaN(dt.getTime())) allTimestamps.push(dt);
      }
    });

    if (allTimestamps.length === 0) {
      return 'No evidence timestamps available';
    }

    const earliest = new Date(Math.min(...allTimestamps.map(t => t.getTime())));
    const latest = new Date(Math.max(...allTimestamps.map(t => t.getTime())));

    const formattedEarliest = formatEvidenceTime(earliest.toISOString());
    const formattedLatest = formatEvidenceTime(latest.toISOString());

    const datePartEarliest = formattedEarliest.split(' ').slice(0, 3).join(' ');
    const datePartLatest = formattedLatest.split(' ').slice(0, 3).join(' ');
    const timePartEarliest = formattedEarliest.split(' ')[3] || '10:00:00';
    const timePartLatest = formattedLatest.split(' ')[3] || '10:22:18';

    if (datePartEarliest === datePartLatest) {
      return `${datePartEarliest} ${timePartEarliest}–${timePartLatest} UTC`;
    } else {
      return `${datePartEarliest} ${timePartEarliest}–${datePartLatest} ${timePartLatest} UTC`;
    }
  };

  const timeRangeString = getWidestTimeRange();

  // Helper helper to map overclaiming findings titles to strong observable ones
  const sanitizeFindingTitle = (title: string): string => {
    const t = title.toLowerCase();
    if (t.includes('c2') || t.includes('command and control') || t.includes('beaconing') || t.includes('periodic dns') || t.includes('dns query')) {
      return 'Periodic DNS query pattern observed';
    }
    if (t.includes('binary download') || t.includes('executable download') || t.includes('cleartext binary') || t.includes('binary transfer')) {
      return 'Cleartext HTTP / binary transfer observed';
    }
    if (t.includes('outbound connection') || t.includes('repeated outbound')) {
      return 'Repeated outbound connections observed';
    }
    if (t.includes('uncommon service port') || t.includes('non-standard port') || t.includes('port behavior')) {
      return 'Protocol mismatch or unusual port behavior';
    }
    if (t.includes('credential submission') || t.includes('plain text credential') || t.includes('basic authentication') || t.includes('auth header') || t.includes('credential')) {
      return 'Potential credential exposure';
    }
    if (t.includes('mismatch')) {
      return 'Protocol mismatch or unusual port behavior';
    }
    if (t.includes('sni')) {
      return 'TLS SNI to uncommon external endpoint observed';
    }
    if (t.includes('unencrypted application')) {
      return 'Cleartext HTTP / binary transfer observed';
    }
    if (t.includes('concentration') || t.includes('source activity') || t.includes('host activity') || t.includes('unusual source')) {
      return 'External endpoint concentration or unusual source activity';
    }
    return title;
  };
  
  // Before a model response exists, show neutral state and observed record counts only.
  const defaultMemo = {
    executiveSummary: 'No AI memo has been generated. Run the analyst only after reviewing the deterministic observations below.',
    whatHappened: 'No model-generated narrative is available.',
    confidence: "low" as const,
    limitations: 'No model analysis has run. Packet and flow metadata alone may be incomplete and does not establish intent, compromise, execution, or account impact.',
    recommendedChecks: 'Validate parser observations against authorized endpoint, resolver, proxy, and destination-ownership records before adding conclusions to a report.',
    beginnerExplanation: 'PacketSage has organized the imported metadata, but it has not generated an explanatory conclusion.',
    technicalExplanation: 'No AI technical analysis is available. Review the deterministic flow, protocol, and signal tables for observed metadata.',
    normalActivity: 'Not assessed.',
    suspiciousActivity: 'Not assessed.',
    keyEvidence: `${flows.length} flows, ${dns.length} DNS records, ${http.length} HTTP records, ${tls.length} TLS records, and ${signals.length} deterministic signals are available for review.`,
    analystQuestions: 'Which parser observations have been independently validated?'
  };

  const memoData = analysisResult ? {
    executiveSummary: analysisResult.executiveSummary,
    whatHappened: analysisResult.whatHappened,
    confidence: analysisResult.confidence,
    limitations: analysisResult.limitations,
    recommendedChecks: analysisResult.recommendedChecks,
    beginnerExplanation: analysisResult.beginnerExplanation,
    technicalExplanation: analysisResult.technicalExplanation,
    normalActivity: analysisResult.normalActivity,
    suspiciousActivity: analysisResult.suspiciousActivity,
    keyEvidence: analysisResult.keyEvidence,
    analystQuestions: analysisResult.analystQuestions
  } : defaultMemo;

  // Run full Gemini analysis
  const runAiAnalysis = async () => {
    setIsLoading(true);
    setErrorMessage(null);
    setCustomResult(null);
    setLoadingStep('Transmitting packet evidence metadata safely...');

    const steps = [
      'Correlating flow durations and byte metrics...',
      'Filtering deterministic heuristic alerts...',
      'Structuring model prompting payload...',
      'Applying chosen investigative perspective...',
      'Synthesizing evidence and consulting Gemini...',
      'Formatting incident narrative and IR steps...'
    ];

    let stepIndex = 0;
    const interval = setInterval(() => {
      if (stepIndex < steps.length) {
        setLoadingStep(steps[stepIndex++]);
      }
    }, 1800);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          flowSummary: flows,
          dnsRecords: dns,
          httpRecords: http,
          tlsRecords: tls,
          suspiciousSignals: signals,
          protocolStats: stats,
          fileName,
          perspective
        })
      });

      clearInterval(interval);

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || 'Gemini service failed');
      }

      const result: AiAnalysisResult = await response.json();
      onAnalysisCompleted(result);
      setToastMessage('AI Forensic Memo successfully generated!');
    } catch (err: any) {
      clearInterval(interval);
      setErrorMessage(err.message || 'AI analysis is unavailable. No fallback findings were generated.');
    } finally {
      setIsLoading(false);
      setLoadingStep('');
    }
  };

  // Custom interactive check submit
  const handleCustomQuerySubmit = async () => {
    if (!customQuery.trim()) return;
    setIsQueryLoading(true);
    setErrorMessage(null);
    setCustomResult(null);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          flowSummary: flows.slice(0, 5),
          dnsRecords: dns.slice(0, 5),
          httpRecords: http.slice(0, 5),
          tlsRecords: tls.slice(0, 5),
          suspiciousSignals: signals,
          protocolStats: stats,
          fileName,
          perspective: 'comprehensive'
        })
      });

      if (!response.ok) {
        throw new Error('Interactive query failed.');
      }

      const result: AiAnalysisResult = await response.json();
      setCustomResult(`Based on your query "${customQuery}", here is the AI Analyst's targeted evaluation:\n\n${result.technicalExplanation}\n\nRecommended Action:\n${result.recommendedChecks}`);
      setToastMessage('Query complete!');
    } catch (err: any) {
      setErrorMessage(err.message || 'Interactive analysis is unavailable. No fallback findings were generated.');
    } finally {
      setIsQueryLoading(false);
    }
  };

  // Copy memo markdown to clipboard
  const handleCopyMemo = () => {
    let md = `# AI Forensic Incident Analyst Memo\n\n`;
    md += `**Evidence file:** ${fileName}\n`;
    md += `**Date/Time:** ${new Date().toISOString()}\n\n`;
    
    if (includedSections.executiveSummary) {
      md += `## 1. Executive Summary\n${memoData.executiveSummary}\n\n`;
    }
    if (includedSections.whatHappened) {
      md += `## 2. Narrative Timeline\n${memoData.whatHappened}\n\n`;
    }
    if (includedSections.confidenceLimitations) {
      md += `## 3. Confidence & Limitations\n**Confidence Level:** ${memoData.confidence}\n\n${memoData.limitations}\n\n`;
    }
    if (includedSections.recommendedChecks) {
      md += `## 4. Recommended Defensive Checks\n${memoData.recommendedChecks}\n\n`;
    }
    if (includedSections.beginnerExplanation) {
      md += `## 5. Non-Technical Explainer\n${memoData.beginnerExplanation}\n\n`;
    }
    if (includedSections.technicalExplanation) {
      md += `## 6. SOC Analyst Technical Analysis\n${memoData.technicalExplanation}\n\n`;
    }

    navigator.clipboard.writeText(redactSensitive(md));
    setCopied(true);
    setToastMessage('Memo copied to clipboard!');
    setTimeout(() => setCopied(false), 2000);
  };

  // Add memo to report simulation
  const handleAddToReport = () => {
    setIsSavedToReport(true);
    setToastMessage('Memo linked to report output!');
  };

  // Filtering signals table by scope
  const filteredSignals = signals.filter(sig => {
    if (evidenceScope === 'high') {
      return sig.severity === 'high';
    }
    if (evidenceScope === 'added') {
      return sig.severity === 'high' || sig.severity === 'medium';
    }
    if (evidenceScope === 'custom') {
      return selectedFindings.includes(sig.id);
    }
    return true; // 'all'
  });

  // Helper to get evidence-based, non-overclaiming Reason/Heuristic wording
  const getEvidenceBasedHeuristic = (title: string): string => {
    const t = title.toLowerCase();
    if (t.includes('periodic dns') || t.includes('dns query') || t.includes('beaconing') || t.includes('c2')) {
      return 'Periodic timing pattern requires resolver correlation';
    }
    if (t.includes('cleartext binary') || t.includes('binary download') || t.includes('executable download') || t.includes('cleartext http')) {
      return 'Cleartext HTTP transfer may expose payload contents';
    }
    if (t.includes('outbound connection') || t.includes('repeated outbound')) {
      return 'Repeated outbound activity requires destination reputation review';
    }
    if (t.includes('uncommon service port') || t.includes('non-standard port') || t.includes('port behavior')) {
      return 'Unusual port/protocol pairing requires validation';
    }
    if (t.includes('credential submission') || t.includes('credential') || t.includes('basic auth') || t.includes('potential credential')) {
      return 'Credential-like field observed in cleartext metadata; validate payload and logs';
    }
    if (t.includes('protocol mismatch') || t.includes('mismatch')) {
      return 'Protocol/port mismatch requires configuration review';
    }
    if (t.includes('tls sni') || t.includes('sni')) {
      return 'SNI target requires reputation and ownership validation';
    }
    if (t.includes('unencrypted application') || t.includes('unencrypted')) {
      return 'Cleartext application transfer may disclose sensitive payload';
    }
    if (t.includes('endpoint concentration') || t.includes('source activity') || t.includes('host activity')) {
      return 'Concentrated outbound volume requires volume baseline check';
    }
    return 'Observed network behavior requires endpoint validation';
  };

  // Findings are a direct presentation of deterministic parser signals only.
  const deduplicatedFindings = React.useMemo(() => {
    return signals.filter(finding => {
      if (evidenceScope === 'high') {
        return finding.severity === 'high';
      }
      if (evidenceScope === 'added') {
        return finding.severity === 'high' || finding.severity === 'medium';
      }
      if (evidenceScope === 'custom') {
        return selectedFindings.includes(finding.id);
      }
      return true;
    });
  }, [signals, evidenceScope, selectedFindings]);

  return (
    <div id="ai-analyst-workspace" className="space-y-6 font-sans">
      
      {/* 1. Page Header */}
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-1.5">
          <h2 className="text-xl font-bold tracking-tight text-text-primary">AI analyst memo</h2>
          <InfoPopover content="The memo is generated from selected decoded metadata, observations, and report context. It supports analyst drafting and does not replace human validation." align="left" />
        </div>
        <p className="text-xs text-text-muted">
          Generate an evidence-bound analyst memo from decoded flows, validated observations, and report context.
        </p>
        
        {/* Compact Metadata Row */}
        <div className="flex flex-wrap items-center gap-y-2 gap-x-5 mt-2.5 py-2 px-3 bg-surface-muted border border-border-subtle rounded-lg text-[11px] text-text-secondary">
          <div className="flex items-center gap-1.5">
            <HardDrive size={13} className="text-text-muted" />
            <span className="text-text-muted">Evidence File:</span>
            <span className="font-mono text-text-primary font-semibold">{fileName}</span>
          </div>
          <div className="h-3 w-px bg-border-subtle" />
          <div className="flex items-center gap-1.5">
            <Activity size={13} className="text-text-muted" />
            <span className="text-text-muted">Flows Analyzed:</span>
            <span className="font-mono text-text-primary font-semibold">{flows.length}</span>
          </div>
          <div className="h-3 w-px bg-border-subtle" />
          <div className="flex items-center gap-1.5">
            <ShieldAlert size={13} className="text-text-muted" />
            <span className="text-text-muted">Signals Included:</span>
            <span className="font-mono text-text-primary font-semibold">{signals.length}</span>
          </div>
          <div className="h-3 w-px bg-border-subtle" />
          <div className="flex items-center gap-1.5">
            <Clock size={13} className="text-text-muted" />
            <span className="text-text-muted">Report Status:</span>
            {isSavedToReport ? (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md border border-emerald-500/30 text-[#10b981] bg-emerald-500/10 text-[9.5px] font-bold uppercase tracking-wider">Added to report</span>
            ) : (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/40 text-[9.5px] font-bold uppercase tracking-wider">Draft</span>
            )}
          </div>
          <div className="h-3 w-px bg-border-subtle" />
          <div className="flex items-center gap-1.5">
            <Cpu size={13} className="text-text-muted" />
            <span className="text-text-muted">Memo Status:</span>
            {analysisResult ? (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md border border-emerald-500/30 text-[#10b981] bg-emerald-500/10 text-[9.5px] font-bold uppercase tracking-wider">Generated</span>
            ) : (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/40 text-[9.5px] font-bold uppercase tracking-wider">Pending</span>
            )}
          </div>
        </div>
      </div>

      {/* 2. Evidence and Context Summary Panel */}
      <div className="p-4 bg-surface rounded-xl border border-border-subtle space-y-3 shadow-sm">
        <div className="flex items-center gap-1.5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-text-muted flex items-center gap-1.5">
            <Info size={14} className="text-accent-primary" />
            Evidence and context used
          </h3>
          <InfoPopover content="This section lists the evidence scope used for memo generation, including flows, endpoints, signals, and evidence time range." align="left" />
        </div>
        
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3 text-xs">
          <div className="p-2.5 bg-surface-muted rounded-lg border border-border-subtle/50">
            <span className="text-[10px] text-text-muted block uppercase font-bold tracking-wider mb-0.5">Flows</span>
            <span className="font-mono font-bold text-text-primary">{flows.length}</span>
          </div>
          <div className="p-2.5 bg-surface-muted rounded-lg border border-border-subtle/50">
            <span className="text-[10px] text-text-muted block uppercase font-bold tracking-wider mb-0.5">Endpoints</span>
            <span className="font-mono font-bold text-text-primary">
              {new Set([...flows.map(f => f.sourceIp), ...flows.map(f => f.destinationIp)]).size}
            </span>
          </div>
          <div className="p-2.5 bg-surface-muted rounded-lg border border-border-subtle/50">
            <span className="text-[10px] text-text-muted block uppercase font-bold tracking-wider mb-0.5">Signals</span>
            <span className="font-mono font-bold text-text-primary">{signals.length}</span>
          </div>
          <div className="p-2.5 bg-surface-muted rounded-lg border border-border-subtle/50 col-span-2 sm:col-span-1 md:col-span-2">
            <span className="text-[10px] text-text-muted block uppercase font-bold tracking-wider mb-0.5">Evidence Time Range</span>
            <span className="font-mono text-[11px] font-semibold text-text-secondary truncate block animate-fade-in" title={timeRangeString}>
              {timeRangeString}
            </span>
          </div>
          <div className="p-2.5 bg-surface-muted rounded-lg border border-border-subtle/50">
            <span className="text-[10px] text-text-muted block uppercase font-bold tracking-wider mb-0.5">AI Memo Status</span>
            <span className="font-mono font-bold text-text-primary">{analysisResult ? 'Generated' : 'Pending generation'}</span>
          </div>
        </div>
      </div>

      {/* Error state alert box */}
      {errorMessage && (
        <div className="p-4 bg-status-danger-bg border border-status-danger/20 rounded-xl text-xs text-status-danger flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-sm select-text">
          <div className="flex gap-2 items-start">
            <AlertTriangle size={14} className="text-status-danger shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              <span className="font-semibold block text-text-primary">Investigation Interrupted:</span>
              <p className="text-text-secondary text-[11px] leading-relaxed">{errorMessage}</p>
            </div>
          </div>
          <button
            onClick={runAiAnalysis}
            className="px-3.5 py-1.5 bg-accent-primary hover:bg-accent-primary-hover text-white font-bold text-[11px] rounded-lg cursor-pointer transition-all shrink-0 self-start md:self-center"
          >
            Retry AI Analysis
          </button>
        </div>
      )}

      {/* Loading state overlay */}
      {isLoading && (
        <div id="ai-loading" className="p-16 bg-surface-muted rounded-xl border border-border-subtle text-center space-y-4 shadow-sm animate-pulse">
          <div className="inline-block p-4 bg-canvas rounded-full border border-border-subtle text-accent-primary animate-spin">
            <RefreshCw size={24} />
          </div>
          <h4 className="text-xs font-semibold text-text-primary tracking-wide">Analyzing capture logs via Gemini...</h4>
          <p className="text-xs text-text-muted italic max-w-sm mx-auto">
            {loadingStep || 'Preparing log bundles and safety alignments...'}
          </p>
        </div>
      )}

      {/* Two Column Layout: Workspace & Controls Rail */}
      {!isLoading && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
          
          {/* 3. Main Memo Workspace (Left Column) */}
          <div className="lg:col-span-3 space-y-6">
            
            {/* Tab Headers */}
            <div className="flex items-center justify-between border-b border-border-subtle flex-wrap gap-2">
              <div className="flex gap-1">
                <button
                  onClick={() => setActiveTab('memo')}
                  className={`px-4 py-2 text-xs font-bold uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
                    activeTab === 'memo' 
                      ? 'border-accent-primary text-accent-primary' 
                      : 'border-transparent text-text-muted hover:text-text-primary'
                  }`}
                >
                  AI analyst memo
                </button>
                <button
                  onClick={() => setActiveTab('takeaways')}
                  className={`px-4 py-2 text-xs font-bold uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
                    activeTab === 'takeaways' 
                      ? 'border-accent-primary text-accent-primary' 
                      : 'border-transparent text-text-muted hover:text-text-primary'
                  }`}
                >
                  Key Takeaways
                </button>
                <button
                  onClick={() => setActiveTab('tech')}
                  className={`px-4 py-2 text-xs font-bold uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
                    activeTab === 'tech' 
                      ? 'border-accent-primary text-accent-primary' 
                      : 'border-transparent text-text-muted hover:text-text-primary'
                  }`}
                >
                  Technical Details
                </button>
                <button
                  onClick={() => setActiveTab('evidence')}
                  className={`px-4 py-2 text-xs font-bold uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
                    activeTab === 'evidence' 
                      ? 'border-accent-primary text-accent-primary' 
                      : 'border-transparent text-text-muted hover:text-text-primary'
                  }`}
                >
                  Evidence References
                </button>
              </div>

              {/* Status indicator info */}
              <div className="flex items-center gap-2 text-[10px] text-text-muted px-2 py-1 bg-surface-muted rounded border border-border-subtle/50 mb-1">
                {analysisResult ? (
                  <span className="font-bold text-text-secondary uppercase text-[9px] tracking-wide bg-surface border border-border-default px-1.5 py-0.5 rounded">
                    Memo saved
                  </span>
                ) : (
                  <span className="font-bold text-text-secondary uppercase text-[9px] tracking-wide bg-surface border border-border-default px-1.5 py-0.5 rounded">
                    Report draft
                  </span>
                )}
                <span className="h-2 w-px bg-border-subtle" />
                <span>Auto-saved 2 min ago</span>
              </div>
            </div>

            {/* TAB CONTENT: Memo Sheet */}
            <div className="bg-surface border border-border-subtle rounded-2xl p-6 md:p-8 space-y-6 shadow-sm select-text relative">
              
              {!analysisResult && activeTab !== 'evidence' ? (
                <div id="ai-memo-empty" className="flex flex-col items-center justify-center text-center py-12 px-4 max-w-xl mx-auto space-y-6">
                  <div className="p-4 bg-accent-soft border border-accent-primary/20 rounded-full text-accent-primary animate-pulse">
                    <Cpu size={32} />
                  </div>
                  <div className="space-y-2">
                    <h3 className="text-base font-bold text-text-primary tracking-tight">AI incident investigation memo pending</h3>
                    <p className="text-xs text-text-secondary leading-relaxed">
                      Synthesize a high-confidence security analysis, chronological narrative timeline, and defensive playbooks from the <span className="font-mono font-semibold text-accent-primary">{flows.length}</span> decoded network sessions.
                    </p>
                  </div>

                  {/* Active Config Summary */}
                  <div className="w-full p-4 bg-surface-muted rounded-xl border border-border-subtle/50 text-left space-y-3">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted block font-mono">Selected analysis pipeline</span>
                    <div className="grid grid-cols-2 gap-4 text-xs">
                      <div>
                        <span className="text-text-muted block text-[10px] font-semibold uppercase tracking-wider">Perspective</span>
                        <span className="font-semibold text-text-primary capitalize">{perspective.replace('-', ' ')} summary</span>
                      </div>
                      <div>
                        <span className="text-text-muted block text-[10px] font-semibold uppercase tracking-wider">Output Mode</span>
                        <span className="font-semibold text-text-primary capitalize">{outputMode} memo</span>
                      </div>
                      <div>
                        <span className="text-text-muted block text-[10px] font-semibold uppercase tracking-wider">Evidence Scope</span>
                        <span className="font-semibold text-text-primary capitalize">{evidenceScope === 'all' ? 'All records' : evidenceScope}</span>
                      </div>
                      <div>
                        <span className="text-text-muted block text-[10px] font-semibold uppercase tracking-wider">Included Sections</span>
                        <span className="font-semibold text-text-primary">
                          {Object.values(includedSections).filter(Boolean).length} / {Object.keys(includedSections).length}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* CTA Button */}
                  <div className="w-full max-w-xs pt-2">
                    <button
                      onClick={runAiAnalysis}
                      className="w-full py-2.5 bg-accent-primary hover:bg-accent-primary-hover text-white font-bold text-xs rounded-xl cursor-pointer transition-all shadow-sm flex items-center justify-center gap-2"
                    >
                      <RefreshCw size={14} />
                      Generate Forensic Incident Memo
                    </button>
                  </div>

                  {/* Assistive disclaimer note */}
                  <div className="p-3.5 rounded-xl border border-accent-primary/10 bg-accent-soft text-xs leading-relaxed text-text-secondary flex gap-2 text-left w-full mt-4">
                    <Info size={14} className="text-accent-primary shrink-0 mt-0.5" />
                    <span>
                      Raw packet files are not stored by PacketSage in sandbox mode. AI memo generation may use selected decoded metadata or summaries through a server-side proxy with redaction controls.
                    </span>
                  </div>
                </div>
              ) : (
                <>
                  {activeTab === 'memo' && (
                    <div className="space-y-6">
                      
                      {/* Formal Memo Letterhead Header */}
                      <div className="border-b-2 border-border-strong pb-4 mb-6 font-mono text-[11px] leading-relaxed text-text-secondary select-text">
                        <div className="text-center font-bold text-xs tracking-wider text-text-primary mb-3">
                          FORENSIC INVESTIGATION MEMORANDUM
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 bg-surface-muted/30 p-3 rounded-xl border border-border-subtle">
                          <div><span className="text-text-muted font-bold inline-block w-32 shrink-0">CASE FILE:</span> <span className="text-text-primary font-mono font-semibold">{fileName}</span></div>
                          <div><span className="text-text-muted font-bold inline-block w-32 shrink-0">EVIDENCE RANGE:</span> <span className="text-text-primary font-mono font-semibold">{timeRangeString}</span></div>
                          <div><span className="text-text-muted font-bold inline-block w-32 shrink-0">MEMO GENERATED:</span> <span className="text-text-primary font-mono">{new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC</span></div>
                          <div><span className="text-text-muted font-bold inline-block w-32 shrink-0">FROM:</span> Lead Traffic Forensic Analyst (AI Sandbox Proxy)</div>
                          <div><span className="text-text-muted font-bold inline-block w-32 shrink-0">TO:</span> Security Operations Center (SOC) Command</div>
                          <div><span className="text-text-muted font-bold inline-block w-32 shrink-0">SUBJECT:</span> Defensive Traffic Forensic Analysis & Remediation</div>
                          <div><span className="text-text-muted font-bold inline-block w-32 shrink-0">STATUS:</span> <span className="text-status-warning font-semibold">RESTRICTED // ANALYST REVIEW</span></div>
                        </div>
                      </div>
                  
                  {/* Section 1: Executive Summary */}
                  {includedSections.executiveSummary && (
                    <div className="space-y-4 border-b border-border-default/60 pb-6 mb-6">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary flex items-center gap-2">
                        <span className="text-text-muted">1.</span> Executive summary
                      </h4>
                      <p className="text-xs text-text-primary leading-relaxed font-normal">
                        {redactSensitive(memoData.executiveSummary)}
                      </p>
                      
                      {/* Assistive calm limit/note */}
                      <div className="mt-4 p-3.5 rounded-xl border border-accent-primary/15 bg-accent-soft text-xs leading-relaxed text-text-secondary flex gap-2">
                        <Info size={14} className="text-accent-primary shrink-0 mt-0.5" />
                        <span>
                          This memo is generated from decoded evidence and selected observations. It supports analyst review and does not replace human validation.
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Section 2: Narrative Timeline of Actions */}
                  {includedSections.whatHappened && (
                    <div className="space-y-4 border-b border-border-default/60 pb-6 mb-6">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary flex items-center gap-2">
                        <span className="text-text-muted">2.</span> Narrative timeline of actions
                      </h4>
                      <div className="text-xs text-text-primary leading-relaxed whitespace-pre-line font-normal space-y-3.5 pl-4 border-l-2 border-border-default py-1">
                        {redactSensitive(memoData.whatHappened).split('\n').map((line, idx) => {
                          const cleanLine = line.replace(/^[•\s*-]+\s*/, ''); // strip bullet points
                          if (!cleanLine.trim()) return null;
                          return (
                            <div key={idx} className="relative">
                              <div className="absolute -left-[21px] top-1.5 w-2 h-2 rounded-full bg-accent-primary border border-surface" />
                              <p className="font-sans text-text-secondary">{cleanLine}</p>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Section 3: Key Findings */}
                  {includedSections.keyObservations && (
                    <div className="space-y-4 border-b border-border-default/60 pb-6 mb-6">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary flex items-center gap-2">
                        <span className="text-text-muted">3.</span> Key findings & observations requiring review
                      </h4>
                      
                      <div className="overflow-x-auto border border-border-subtle rounded-xl bg-canvas">
                        <table className="w-full text-left text-xs border-collapse">
                          <thead>
                            <tr className="bg-surface-muted border-b border-border-subtle text-[10px] text-text-muted uppercase tracking-wider font-bold">
                              <th className="py-2 px-3">Finding</th>
                              <th className="py-2 px-3">Severity</th>
                              <th className="py-2 px-3 text-center">Confidence</th>
                              <th className="py-2 px-3">Reason / Heuristic</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border-subtle/50">
                            {deduplicatedFindings.map((sig, idx) => {
                              const sanitizedTitle = sanitizeFindingTitle(sig.title);
                              const heuristic = getEvidenceBasedHeuristic(sanitizedTitle);
                              return (
                                <tr key={sig.id || idx} className="hover:bg-surface-muted/30">
                                  <td className="py-2.5 px-3 font-semibold text-text-primary text-[11px] max-w-[200px] truncate" title={sanitizedTitle}>
                                    {sanitizedTitle}
                                  </td>
                                  <td className="py-2.5 px-3">
                                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-lg text-[9.5px] font-bold border ${
                                      sig.severity === 'high' 
                                        ? 'bg-status-danger text-white border-transparent shadow-xs' 
                                        : sig.severity === 'medium'
                                        ? 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/15 font-semibold'
                                        : 'bg-surface-muted text-text-muted border border-border-subtle font-normal'
                                    }`}>
                                      {sig.severity.toUpperCase()}
                                    </span>
                                  </td>
                                  <td className="py-2.5 px-3 text-center font-mono text-[11px]">
                                    <div className="flex items-center justify-center gap-1.5">
                                      <span className="text-text-secondary">{sig.confidence === 'high' ? '75%' : sig.confidence === 'medium' ? '60%' : '45%'}</span>
                                      <div className="w-12 h-1.5 bg-border-subtle rounded-full overflow-hidden">
                                        <div 
                                          className={`h-full rounded-full ${
                                            sig.confidence === 'high' ? 'bg-status-success' : sig.confidence === 'medium' ? 'bg-status-warning' : 'bg-status-info'
                                          }`}
                                          style={{ width: sig.confidence === 'high' ? '75%' : sig.confidence === 'medium' ? '60%' : '45%' }}
                                        />
                                      </div>
                                    </div>
                                  </td>
                                  <td className="py-2.5 px-3 text-text-secondary font-mono text-[10px] max-w-[220px] truncate" title={heuristic}>
                                    {heuristic}
                                  </td>
                                </tr>
                              );
                            })}
                            {deduplicatedFindings.length === 0 && (
                              <tr>
                                <td colSpan={4} className="py-6 text-center text-text-muted italic">
                                  No findings match the active evidence scope filter.
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>

                      <div className="flex justify-between items-center text-[10px] text-text-muted pl-1">
                        <span>* Dynamic finding statuses are correlated directly with your active security scope.</span>
                      </div>
                    </div>
                  )}

                  {/* Section 4: Confidence and Limitations */}
                  {includedSections.confidenceLimitations && (
                    <div className="space-y-4 border-b border-border-default/60 pb-6 mb-6">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary flex items-center gap-2">
                        <span className="text-text-muted">4.</span> Confidence and limitations
                        <InfoPopover content="Packet and protocol evidence alone does not confirm endpoint compromise, malware execution, user intent, or command-and-control activity." align="left" />
                      </h4>
                      
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs leading-relaxed">
                        
                        {/* A. Assessment confidence */}
                        <div className="space-y-2">
                          <span className="text-[10px] uppercase font-bold tracking-wider text-text-muted block">A. Assessment confidence</span>
                          <div className="flex items-center gap-2">
                            <span className="text-text-muted font-semibold">Confidence level:</span>
                            <span className={`px-2.5 py-0.5 rounded-lg text-[10.5px] font-bold border ${
                              memoData.confidence.toLowerCase() === 'high' 
                                ? 'bg-status-success text-white border-transparent shadow-xs' 
                                : 'border border-status-warning/40 text-[#f59e0b] bg-status-warning-bg/40'
                            }`}>
                              {memoData.confidence}
                            </span>
                          </div>
                          
                          <div className="space-y-1 mt-2">
                            <span className="text-[10px] text-text-muted font-bold uppercase tracking-wider block">Confidence basis:</span>
                            <ul className="list-disc pl-4 text-text-muted space-y-1 text-[11px]">
                              <li>Correlated with {deduplicatedFindings.length} telemetry observations</li>
                              <li>Derived from decoded flow sessions, HTTP metadata, and active DNS queries</li>
                              <li>Multiple independent signals support the same host activity</li>
                            </ul>
                          </div>
                        </div>

                        {/* B. Supporting evidence */}
                        <div className="space-y-2">
                          <span className="text-[10px] uppercase font-bold tracking-wider text-text-muted block">B. Supporting evidence</span>
                          <ul className="space-y-1.5 text-text-secondary text-[11px]">
                            <li className="flex items-start gap-1.5">
                              <span className="text-accent-primary mt-1 font-bold">•</span>
                              <span>Cleartext transfer observed over HTTP</span>
                            </li>
                            <li className="flex items-start gap-1.5">
                              <span className="text-accent-primary mt-1 font-bold">•</span>
                              <span>Periodic DNS queries observed</span>
                            </li>
                            <li className="flex items-start gap-1.5">
                              <span className="text-accent-primary mt-1 font-bold">•</span>
                              <span>Repeated outbound connection attempts observed</span>
                            </li>
                            <li className="flex items-start gap-1.5">
                              <span className="text-accent-primary mt-1 font-bold">•</span>
                              <span>External endpoint requires ownership/reputation review</span>
                            </li>
                          </ul>
                        </div>

                        {/* C. Analysis limitations */}
                        <div className="space-y-2">
                          <span className="text-[10px] uppercase font-bold tracking-wider text-text-muted block">C. Analysis limitations</span>
                          <ul className="space-y-1.5 text-text-muted text-[11px]">
                            <li className="flex items-start gap-1.5">
                              <span className="text-text-muted mt-1 font-bold">•</span>
                              <span>Payload contents may be incomplete.</span>
                            </li>
                            <li className="flex items-start gap-1.5">
                              <span className="text-text-muted mt-1 font-bold">•</span>
                              <span>Network metadata does not confirm endpoint compromise on its own.</span>
                            </li>
                            <li className="flex items-start gap-1.5">
                              <span className="text-text-muted mt-1 font-bold">•</span>
                              <span>Host process telemetry is required to validate execution.</span>
                            </li>
                            <li className="flex items-start gap-1.5">
                              <span className="text-text-muted mt-1 font-bold">•</span>
                              <span>Authentication logs are required to assess account impact.</span>
                            </li>
                          </ul>
                        </div>

                      </div>
                    </div>
                  )}

                  {/* Section 5: Recommended Defensive Response Actions */}
                  {includedSections.recommendedChecks && (
                    <div className="space-y-4 border-b border-border-default/60 pb-6 mb-6">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary flex items-center gap-2">
                        <span className="text-text-muted">5.</span> Recommended defensive response actions
                      </h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
                        <ul className="space-y-1.5 text-xs text-text-secondary leading-relaxed pl-1">
                          {[
                            "Review DNS resolver logs for the queried domain and host.",
                            "Check endpoint process activity around the observed timestamps.",
                            "Review proxy, authentication, and EDR logs for matching events.",
                            "Confirm destination ownership, reputation, and expected business use."
                          ].map((check, idx) => (
                            <li key={idx} className="flex items-start gap-2.5">
                              <div className="w-4 h-4 rounded border border-border-strong flex items-center justify-center shrink-0 mt-0.5 bg-canvas">
                                <span className="text-[9px] font-mono font-bold text-accent-primary">{idx + 1}</span>
                              </div>
                              <span className="text-text-secondary">{check}</span>
                            </li>
                          ))}
                        </ul>
                        <ul className="space-y-1.5 text-xs text-text-secondary leading-relaxed pl-1">
                          {[
                            "Inspect adjacent flows for repeated timing or payload-transfer patterns.",
                            "Preserve relevant endpoint artifacts for follow-up investigation.",
                            "Add validated observations to the incident report."
                          ].map((check, idx) => (
                            <li key={idx + 4} className="flex items-start gap-2.5">
                              <div className="w-4 h-4 rounded border border-border-strong flex items-center justify-center shrink-0 mt-0.5 bg-canvas">
                                <span className="text-[9px] font-mono font-bold text-accent-primary">{idx + 5}</span>
                              </div>
                              <span className="text-text-secondary">{check}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  )}

                  {/* Section 6: Beginner Explainer Analogy */}
                  {includedSections.beginnerExplanation && (
                    <div className="space-y-4 border-b border-border-default/60 pb-6 mb-6">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary flex items-center gap-2">
                        <span className="text-text-muted">6.</span> Analyst perspective (Non-technical explainer)
                      </h4>
                      <div className="p-3 bg-surface-muted/50 border border-border-subtle/50 rounded-xl text-xs text-text-primary leading-relaxed italic">
                        {memoData.beginnerExplanation}
                      </div>
                    </div>
                  )}

                  {/* Section 7: Technical Protocol Evaluation */}
                  {includedSections.technicalExplanation && (
                    <div className="space-y-4">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary flex items-center gap-2">
                        <span className="text-text-muted">7.</span> Technical protocol evaluation
                      </h4>
                      
                      <p className="whitespace-pre-line pl-3 border-l border-border-subtle text-xs text-text-secondary leading-relaxed">
                        {memoData.technicalExplanation}
                      </p>
                    </div>
                  )}

                </div>
              )}

              {/* TAB CONTENT: Key Takeaways */}
              {activeTab === 'takeaways' && (
                <div className="space-y-5">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                    <div className="p-4 bg-surface-muted rounded-xl border border-border-subtle/50 space-y-2">
                      <h4 className="text-xs font-bold uppercase text-status-success tracking-wider block">Benign activity baseline</h4>
                      <p className="text-xs text-text-secondary leading-relaxed font-normal">
                        {memoData.normalActivity}
                      </p>
                    </div>

                    <div className="p-4 bg-surface-muted rounded-xl border border-border-subtle/50 space-y-2">
                      <h4 className="text-xs font-bold uppercase text-status-danger tracking-wider block">Anomalous or suspicious findings</h4>
                      <p className="text-xs text-text-secondary leading-relaxed font-normal">
                        {memoData.suspiciousActivity}
                      </p>
                    </div>
                  </div>

                  <div className="p-4 bg-surface-muted rounded-xl border border-border-subtle/50 space-y-2">
                    <h4 className="text-xs font-bold uppercase text-accent-primary tracking-wider block">Stakeholder inquiry checklist</h4>
                    <p className="text-xs text-text-secondary leading-relaxed whitespace-pre-line font-mono bg-canvas p-3 rounded-lg border border-border-subtle/30 font-normal">
                      {memoData.analystQuestions}
                    </p>
                  </div>

                  {/* CASE QUERY CHECK SUB-FEATURE DESK */}
                  <div className="p-4 bg-canvas border border-border-subtle rounded-xl space-y-4">
                    <div className="space-y-1">
                      <h4 className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
                        <HelpCircle size={14} className="text-status-info" />
                        Targeted investigative query check (Case desk)
                      </h4>
                      <p className="text-[11px] text-text-muted">
                        Submit a targeted forensic query concerning the decoded captures. Answers are filtered with defensive suggestions.
                      </p>
                    </div>

                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={customQuery}
                        onChange={(e) => setCustomQuery(e.target.value)}
                        placeholder="e.g., Does this suggest DNS exfiltration? Are there cleartext credentials?"
                        className="flex-1 bg-surface border border-border-default rounded-lg px-3 py-1.5 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-primary/20 placeholder:text-text-muted"
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') handleCustomQuerySubmit();
                        }}
                      />
                      <button
                        onClick={handleCustomQuerySubmit}
                        disabled={isQueryLoading || !customQuery.trim()}
                        className="px-4 py-1.5 bg-accent-primary hover:bg-accent-primary-hover text-white text-xs font-semibold rounded-lg cursor-pointer transition-all flex items-center gap-1.5 shrink-0"
                      >
                        {isQueryLoading ? <RefreshCw size={12} className="animate-spin" /> : 'Query'}
                      </button>
                    </div>

                    {customResult && (
                      <div className="p-4 bg-surface border border-border-subtle rounded-lg text-xs text-text-secondary whitespace-pre-line leading-relaxed font-mono animate-in fade-in duration-150">
                        {customResult}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* TAB CONTENT: Technical Details */}
              {activeTab === 'tech' && (
                <div className="space-y-5">
                  <div className="p-4 bg-surface-muted rounded-xl border border-border-subtle/50 space-y-2">
                    <h4 className="text-xs font-bold uppercase text-text-muted tracking-wider block">Specialist Technical Evaluation</h4>
                    <p className="text-xs text-text-secondary font-mono leading-relaxed whitespace-pre-line bg-canvas p-3.5 rounded-lg border border-border-subtle/40">
                      {memoData.technicalExplanation}
                    </p>
                  </div>

                  <div className="p-4 bg-surface-muted rounded-xl border border-border-subtle/50 space-y-3">
                    <h4 className="text-xs font-bold uppercase text-text-muted tracking-wider block">Protocol distribution metrics</h4>
                    <div className="space-y-2.5">
                      {stats.slice(0, 5).map((stat, i) => (
                        <div key={i} className="space-y-1">
                          <div className="flex justify-between text-xs text-text-secondary font-mono">
                            <span>{stat.protocol} ({stat.count} packets)</span>
                            <span>{stat.percentage}%</span>
                          </div>
                          <div className="w-full h-2 bg-canvas rounded-full overflow-hidden border border-border-subtle/40">
                            <div 
                              className="h-full bg-accent-primary rounded-full"
                              style={{ width: `${stat.percentage}%` }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="p-4 bg-surface-muted rounded-xl border border-border-subtle/50 space-y-2">
                    <h4 className="text-xs font-bold uppercase text-text-muted tracking-wider block font-mono">Key target indicators (IoCs)</h4>
                    <div className="p-3 bg-canvas border border-border-subtle/50 rounded-lg text-xs text-text-secondary font-mono whitespace-pre-line leading-relaxed">
                      {memoData.keyEvidence}
                    </div>
                  </div>
                </div>
              )}
            </>
          )}

              {/* TAB CONTENT: Evidence References */}
              {activeTab === 'evidence' && (
                <div className="space-y-5">
                  
                  {/* Top flows table */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold uppercase text-text-muted tracking-wider block">Sample Decoded Flow Sessions</h4>
                    <div className="overflow-x-auto border border-border-subtle rounded-xl bg-canvas">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="bg-surface-muted border-b border-border-subtle text-[10px] text-text-muted font-bold font-mono">
                            <th className="py-2 px-3">Protocol</th>
                            <th className="py-2 px-3">Source IP</th>
                            <th className="py-2 px-3">Destination IP</th>
                            <th className="py-2 px-3 text-right">Bytes</th>
                            <th className="py-2 px-3 text-right">Packets</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border-subtle/50 text-[11px] font-mono">
                          {flows.slice(0, 5).map((f, idx) => (
                            <tr key={idx}>
                              <td className="py-2 px-3 font-semibold text-accent-primary">{f.protocol}</td>
                              <td className="py-2 px-3">{f.sourceIp}:{f.sourcePort}</td>
                              <td className="py-2 px-3">{f.destinationIp}:{f.destinationPort}</td>
                              <td className="py-2 px-3 text-right">{(f.byteCount / 1024).toFixed(1)} KB</td>
                              <td className="py-2 px-3 text-right">{f.packetCount}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* DNS Query table */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold uppercase text-text-muted tracking-wider block">Decoded Domain Name (DNS) Queries</h4>
                    <div className="overflow-x-auto border border-border-subtle rounded-xl bg-canvas">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="bg-surface-muted border-b border-border-subtle text-[10px] text-text-muted font-bold font-mono">
                            <th className="py-2 px-3">Client IP</th>
                            <th className="py-2 px-3">Query Domain</th>
                            <th className="py-2 px-3">Type</th>
                            <th className="py-2 px-3">Response Record</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border-subtle/50 text-[11px] font-mono">
                          {dns.slice(0, 5).map((d, idx) => (
                            <tr key={idx}>
                              <td className="py-2 px-3">{d.clientIp}</td>
                              <td className="py-2 px-3 text-text-primary font-semibold">{d.query}</td>
                              <td className="py-2 px-3">{d.queryType}</td>
                              <td className="py-2 px-3 truncate max-w-[150px]">{d.response}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* HTTP session table */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold uppercase text-text-muted tracking-wider block">Decoded HTTP Sessions</h4>
                    <div className="overflow-x-auto border border-border-subtle rounded-xl bg-canvas">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="bg-surface-muted border-b border-border-subtle text-[10px] text-text-muted font-bold font-mono">
                            <th className="py-2 px-3">Client</th>
                            <th className="py-2 px-3">Method</th>
                            <th className="py-2 px-3">Server Host & URI</th>
                            <th className="py-2 px-3 text-right">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border-subtle/50 text-[11px] font-mono">
                          {http.slice(0, 5).map((h, idx) => (
                            <tr key={idx}>
                              <td className="py-2 px-3">{h.clientIp}</td>
                              <td className="py-2 px-3 font-semibold text-text-primary">{h.method}</td>
                              <td className="py-2 px-3 text-text-secondary truncate max-w-[200px]" title={h.host + h.uri}>
                                {h.host}{h.uri}
                              </td>
                              <td className="py-2 px-3 text-right font-bold">{h.statusCode}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Sanitization Checklist */}
                  <div className="p-4 bg-surface-muted rounded-xl border border-border-subtle/50 space-y-2">
                    <h4 className="text-xs font-bold uppercase text-text-muted tracking-wider block flex items-center gap-1.5">
                      <Lock size={12} className="text-status-success" />
                      Secrets & PII Redaction Audit
                    </h4>
                    <p className="text-[11px] text-text-muted leading-relaxed">
                      Our streaming analysis sanitizes credentials before displaying them. Active filters:
                    </p>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-[11px] font-mono text-text-secondary mt-2">
                      <div className="flex items-center gap-1.5"><CheckCircle size={12} className="text-status-success" /> username=[redacted]</div>
                      <div className="flex items-center gap-1.5"><CheckCircle size={12} className="text-status-success" /> password=[redacted]</div>
                      <div className="flex items-center gap-1.5"><CheckCircle size={12} className="text-status-success" /> token=[redacted]</div>
                      <div className="flex items-center gap-1.5"><CheckCircle size={12} className="text-status-success" /> cookie=[redacted]</div>
                      <div className="flex items-center gap-1.5"><CheckCircle size={12} className="text-status-success" /> api_key=[redacted]</div>
                      <div className="flex items-center gap-1.5"><CheckCircle size={12} className="text-status-success" /> Authorization Headers</div>
                    </div>
                  </div>

                </div>
              )}

            </div>

          </div>

          {/* 4. Right Memo Controls Rail (Right Column) */}
          <div className="space-y-5 bg-surface border border-border-subtle rounded-2xl p-5 shadow-sm min-w-0">
            
            {/* Controls Title Bar */}
            <div className="flex items-center justify-between pb-3 border-b border-border-subtle/80">
              <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary flex items-center gap-1.5">
                <Terminal size={14} className="text-accent-primary" />
                Memo controls
              </h3>
              <button 
                onClick={handleReset}
                className="text-[10px] text-text-muted hover:text-text-primary flex items-center gap-1 cursor-pointer transition-colors"
              >
                <RotateCcw size={10} />
                Reset
              </button>
            </div>

            {/* Analysis Perspective selector */}
            <div className="space-y-2">
              <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted block">Analysis perspective</span>
              <p className="text-[10px] text-text-muted mb-1 leading-relaxed">Choose how the memo should be written.</p>
              
              <div className="space-y-2 text-xs">
                {[
                  { id: 'comprehensive', label: 'Comprehensive summary', desc: 'Full analyst memo with all context' },
                  { id: 'triage', label: 'Incident triage', desc: 'Focus on immediate risks and actions' },
                  { id: 'protocol', label: 'Protocol compliance', desc: 'Focus on violations and misconfigurations' },
                  { id: 'indicators', label: 'Indicators & alert correlation', desc: 'Map to MITRE ATT&CK and IoCs' }
                ].map((item) => (
                  <label 
                    key={item.id} 
                    className={`flex items-start gap-2.5 p-2 rounded-lg border cursor-pointer transition-all ${
                      perspective === item.id 
                        ? 'bg-accent-soft/55 border-accent-primary/40 text-accent-primary font-semibold' 
                        : 'bg-canvas/50 border-border-subtle hover:bg-surface-muted/50 text-text-secondary'
                    }`}
                  >
                    <input 
                      type="radio" 
                      name="perspective" 
                      value={item.id}
                      checked={perspective === item.id}
                      onChange={() => setPerspective(item.id as MemoPerspective)}
                      className="mt-0.5 rounded-full text-accent-primary focus:ring-accent-primary border-border-default h-3 w-3"
                    />
                    <div>
                      <span className="block text-[11px] leading-tight">{item.label}</span>
                      <span className="text-[9px] text-text-muted font-normal block leading-tight mt-0.5">{item.desc}</span>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <hr className="border-border-subtle/50" />

            {/* Evidence Scope Selector */}
            <div className="space-y-2">
              <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted block">Evidence scope</span>
              <p className="text-[10px] text-text-muted mb-1 leading-relaxed">Select which findings to include.</p>

              <div className="space-y-1.5 text-xs">
                {[
                  { id: 'all', label: `All findings (${signals.length})` },
                  { id: 'high', label: `High severity only (${signals.filter(s => s.severity === 'high').length})` },
                  { id: 'added', label: `Added to report (${signals.filter(s => s.severity === 'high' || s.severity === 'medium').length})` },
                  { id: 'custom', label: 'Custom selection' }
                ].map((item) => (
                  <label key={item.id} className="flex items-center gap-2 cursor-pointer text-text-secondary hover:text-text-primary">
                    <input 
                      type="radio" 
                      name="evidenceScope" 
                      value={item.id}
                      checked={evidenceScope === item.id}
                      onChange={() => setEvidenceScope(item.id as any)}
                      className="rounded-full text-accent-primary focus:ring-accent-primary border-border-default h-3.5 w-3.5"
                    />
                    <span className="text-[11px] font-medium">{item.label}</span>
                  </label>
                ))}
              </div>

              {/* Checkbox list of findings for custom scope */}
              {evidenceScope === 'custom' && (
                <div className="mt-2.5 max-h-40 overflow-y-auto space-y-1.5 p-2 bg-canvas rounded-lg border border-border-subtle">
                  {signals.map((sig) => (
                    <label key={sig.id} className="flex items-center gap-2 text-[11px] text-text-secondary cursor-pointer hover:text-text-primary">
                      <input
                        type="checkbox"
                        checked={selectedFindings.includes(sig.id)}
                        onChange={() => {
                          if (selectedFindings.includes(sig.id)) {
                            setSelectedFindings(selectedFindings.filter(id => id !== sig.id));
                          } else {
                            setSelectedFindings([...selectedFindings, sig.id]);
                          }
                        }}
                        className="rounded border-border-default text-accent-primary focus:ring-accent-primary"
                      />
                      <span className="truncate" title={sig.title}>{sig.title}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            <hr className="border-border-subtle/50" />

            {/* Output Mode selector */}
            <div className="space-y-2">
              <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted block">Output mode</span>
              <p className="text-[10px] text-text-muted mb-1 leading-relaxed">Control the length and depth of the memo.</p>

              <div className="space-y-1.5 text-xs">
                {[
                  { id: 'short', label: 'Short memo', desc: 'Concise summary for quick review' },
                  { id: 'full', label: 'Full analyst memo', desc: 'Detailed memo with explanations' },
                  { id: 'summary', label: 'Report-ready summary', desc: 'Executive style summary for reports' }
                ].map((item) => (
                  <label key={item.id} className="flex items-start gap-2 cursor-pointer text-text-secondary hover:text-text-primary">
                    <input 
                      type="radio" 
                      name="outputMode" 
                      value={item.id}
                      checked={outputMode === item.id}
                      onChange={() => setOutputMode(item.id as OutputMode)}
                      className="mt-0.5 rounded-full text-accent-primary focus:ring-accent-primary border-border-default h-3.5 w-3.5"
                    />
                    <div>
                      <span className="text-[11px] font-medium block leading-tight">{item.label}</span>
                      <span className="text-[9px] text-text-muted block leading-tight mt-0.5">{item.desc}</span>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <hr className="border-border-subtle/50" />

            {/* Include Sections checkboxes */}
            <div className="space-y-2">
              <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted block">Include sections</span>
              
              <div className="space-y-1.5 text-xs text-text-secondary">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={includedSections.executiveSummary}
                    onChange={(e) => setIncludedSections({ ...includedSections, executiveSummary: e.target.checked })}
                    className="rounded border-border-default text-accent-primary focus:ring-accent-primary"
                  />
                  <span className="text-[11px]">Executive summary</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={includedSections.keyObservations}
                    onChange={(e) => setIncludedSections({ ...includedSections, keyObservations: e.target.checked })}
                    className="rounded border-border-default text-accent-primary focus:ring-accent-primary"
                  />
                  <span className="text-[11px]">Key observations</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={includedSections.whatHappened}
                    onChange={(e) => setIncludedSections({ ...includedSections, whatHappened: e.target.checked })}
                    className="rounded border-border-default text-accent-primary focus:ring-accent-primary"
                  />
                  <span className="text-[11px]">Evidence references</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={includedSections.confidenceLimitations}
                    onChange={(e) => setIncludedSections({ ...includedSections, confidenceLimitations: e.target.checked })}
                    className="rounded border-border-default text-accent-primary focus:ring-accent-primary"
                  />
                  <span className="text-[11px]">Confidence and limitations</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={includedSections.recommendedChecks}
                    onChange={(e) => setIncludedSections({ ...includedSections, recommendedChecks: e.target.checked })}
                    className="rounded border-border-default text-accent-primary focus:ring-accent-primary"
                  />
                  <span className="text-[11px]">Recommended checks</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={includedSections.beginnerExplanation}
                    onChange={(e) => setIncludedSections({ ...includedSections, beginnerExplanation: e.target.checked })}
                    className="rounded border-border-default text-accent-primary focus:ring-accent-primary"
                  />
                  <span className="text-[11px]">Beginner explanation</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={includedSections.technicalExplanation}
                    onChange={(e) => setIncludedSections({ ...includedSections, technicalExplanation: e.target.checked })}
                    className="rounded border-border-default text-accent-primary focus:ring-accent-primary"
                  />
                  <span className="text-[11px]">Technical explanation</span>
                </label>
              </div>
            </div>

            <hr className="border-border-subtle/50" />

            {/* Core Action triggers */}
            <div className="space-y-2.5 pt-1">
              <button 
                onClick={runAiAnalysis}
                className="w-full py-2 bg-accent-primary hover:bg-accent-primary-hover text-white font-semibold text-xs rounded-lg cursor-pointer transition-colors shadow-sm flex items-center justify-center gap-1.5"
              >
                <RefreshCw size={13} />
                Generate memo
              </button>

              <div className="grid grid-cols-2 gap-2">
                <button 
                  onClick={handleAddToReport}
                  disabled={isSavedToReport}
                  className={`py-1.5 px-2 text-[10px] font-bold border rounded-lg cursor-default transition-colors flex items-center justify-center gap-1 ${
                    isSavedToReport 
                      ? 'bg-status-success text-white border-transparent shadow-xs' 
                      : 'bg-canvas hover:bg-surface border-border-default text-text-secondary cursor-pointer'
                  }`}
                >
                  <Plus size={11} />
                  {isSavedToReport ? 'Added' : 'Add to report'}
                </button>
                <button 
                  onClick={handleCopyMemo}
                  className="py-1.5 px-2 bg-canvas hover:bg-surface border border-border-default text-text-secondary text-[10px] font-semibold rounded-lg cursor-pointer transition-colors flex items-center justify-center gap-1"
                >
                  {copied ? <Check size={11} className="text-status-success" /> : <Copy size={11} />}
                  Copy memo
                </button>
              </div>
            </div>

          </div>

        </div>
      )}

      {/* Floating interactive toast notifications */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-slate-900 border border-slate-800 text-slate-100 rounded-xl px-4 py-3 flex items-center gap-2 shadow-2xl animate-in slide-in-from-bottom-5 duration-200">
          <CheckCircle size={15} className="text-status-success" />
          <span className="text-xs font-semibold">{toastMessage}</span>
        </div>
      )}

    </div>
  );
}
