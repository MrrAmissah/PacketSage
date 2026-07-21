import React, { useState, useRef } from 'react';
import { Upload, FileText, Shield, Terminal, AlertCircle, Database, Info, Lock } from 'lucide-react';
import { ParsedResult } from '../lib/parser';
import { parseCapture } from '../lib/capture';
import { MAX_CAPTURE_BYTES, MAX_TEXT_CHARACTERS } from '../lib/limits';
import { sha256Hex } from '../lib/checksum';
import InfoPopover from './InfoPopover';

interface EvidenceImportProps {
  onDataParsed: (data: ParsedResult) => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
}

export default function EvidenceImport({ onDataParsed, isLoading, setIsLoading }: EvidenceImportProps) {
  const [pastedLog, setPastedLog] = useState('');
  const [parseMode, setParseMode] = useState<'csv' | 'suricata' | 'zeek' | 'tshark' | 'txt' | 'pcap'>('csv');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [authorizedChecked, setAuthorizedChecked] = useState(false);
  const [showAuthInfo, setShowAuthInfo] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    processFile(file);
  };

  const processFile = async (file: File) => {
    if (!authorizedChecked) {
      setErrorMessage('Confirm authorization to import your own evidence.');
      return;
    }

    const lowerName = file.name.toLowerCase();
    const isCapture = lowerName.endsWith('.pcap') || lowerName.endsWith('.pcapng');
    if (isCapture && file.size > MAX_CAPTURE_BYTES) {
      setErrorMessage(`Capture exceeds the ${MAX_CAPTURE_BYTES / 1024 / 1024} MB browser-decoding limit.`);
      return;
    }
    if (!isCapture && file.size > MAX_TEXT_CHARACTERS) {
      setErrorMessage(`Text evidence exceeds the ${MAX_TEXT_CHARACTERS.toLocaleString()} character limit.`);
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    try {
      const buffer = await file.arrayBuffer();
      if (isCapture) {
        const data = await parseCapture(file.name, buffer);
        onDataParsed(data);
      } else {
        const text = new TextDecoder().decode(buffer);
        let mode = parseMode;
        if (lowerName.endsWith('.csv')) mode = 'csv';
        else if (lowerName.endsWith('.json') && lowerName.includes('eve')) mode = 'suricata';
        else if (lowerName.endsWith('.json')) mode = 'tshark';
        else if (lowerName.endsWith('.log') || lowerName.includes('conn') || lowerName.includes('dns') || lowerName.includes('http')) mode = 'zeek';
        else mode = 'txt';

        const response = await fetch('/api/parse', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fileName: file.name,
            fileContent: text,
            parseMode: mode,
            fileSize: file.size
          })
        });

        if (!response.ok) {
          const errData = await response.json();
          throw new Error(errData.error || 'Server parsing error');
        }

        const data: ParsedResult = await response.json();
        const sha256 = await sha256Hex(buffer);
        onDataParsed({
          ...data,
          evidence: { ...data.evidence, sha256, checksumStatus: 'calculated' },
        });
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to parse file. Ensure format is valid.');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePasteSubmit = async () => {
    if (!authorizedChecked) {
      setErrorMessage('Confirm authorization to import your own evidence.');
      return;
    }
    if (!pastedLog.trim()) {
      setErrorMessage('Please paste structured log lines before submitting.');
      return;
    }
    if (pastedLog.length > MAX_TEXT_CHARACTERS) {
      setErrorMessage(`Pasted evidence exceeds the ${MAX_TEXT_CHARACTERS.toLocaleString()} character limit.`);
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    try {
      const response = await fetch('/api/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fileName: 'pasted_analyst_log.txt',
          fileContent: pastedLog,
          parseMode: 'txt'
        })
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.error || 'Server parsing error');
      }

      const data: ParsedResult = await response.json();
      const sha256 = await sha256Hex(pastedLog);
      onDataParsed({
        ...data,
        evidence: { ...data.evidence, sha256, checksumStatus: 'calculated' },
      });
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to parse pasted data.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLoadDemo = async () => {
    setIsLoading(true);
    setErrorMessage(null);

    try {
      const response = await fetch('/api/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fileName: 'guided_defensive_analysis_sample.json',
          parseMode: 'demo'
        })
      });

      if (!response.ok) {
        throw new Error('Failed to load demo data from endpoint.');
      }

      const data: ParsedResult = await response.json();
      onDataParsed({
        ...data,
        evidence: { ...data.evidence, checksumStatus: 'demo-not-applicable' },
      });
    } catch (err: any) {
      setErrorMessage(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div id="evidence-import-workspace" className="space-y-6 font-sans">
      
      {/* A. Page Title & Short Explanation */}
      <div className="space-y-1.5">
        <span className="text-[10px] font-bold text-accent-primary uppercase tracking-widest block">
          Evidence Intake
        </span>
        <h2 className="text-xl sm:text-2xl font-bold text-text-primary tracking-tight">
          Import evidence
        </h2>
        <p className="text-xs text-text-muted max-w-2xl leading-relaxed">
          Upload packet exports, JSON event streams, or structured log fragments to begin analysis.
        </p>
        <div className="flex items-center gap-1.5 text-[11px] text-text-muted select-none">
          <Database size={12} className="text-accent-primary shrink-0" />
          <span>Load a sample dataset or import evidence to unlock analysis modules.</span>
        </div>
      </div>

      {/* Error message boundary */}
      {errorMessage && (
        <div role="alert" className="p-3 bg-status-danger-bg border border-status-danger/20 text-status-danger rounded-xl flex gap-2 items-center text-xs animate-fade-in">
          <AlertCircle size={14} className="shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* C. Main Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Option 1: Upload Container */}
        <div className="p-[18px] bg-surface rounded-xl border border-border-subtle shadow-sm flex flex-col justify-between space-y-4">
          <div className="flex items-start gap-3">
            <div className="w-5.5 h-5.5 rounded-full bg-accent-soft border border-accent-primary/25 text-accent-primary text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
              1
            </div>
            <div className="space-y-1 min-w-0">
              <span className="text-[9px] font-bold text-accent-primary bg-accent-soft border border-accent-primary/15 px-2 py-0.5 rounded uppercase tracking-wider">
                Option 1
              </span>
              <h4 className="text-sm font-semibold text-text-primary flex items-center gap-1.5 mt-1">
                <Upload size={14} className="text-accent-primary shrink-0" />
                Upload network logs or packet captures
              </h4>
              <p className="text-xs text-text-muted leading-relaxed">
                Raw PCAP/PCAPNG captures are decoded in browser memory. Supported text exports are sent to the parsing endpoint.
              </p>
            </div>
          </div>

          {/* Drag and Drop Zone */}
          <div
            role="button"
            tabIndex={isLoading || !authorizedChecked ? -1 : 0}
            aria-disabled={isLoading || !authorizedChecked}
            aria-label="Browse authorized evidence files"
            onClick={() => {
              if (isLoading) return;
              if (!authorizedChecked) {
                setErrorMessage('Confirm authorization to import your own evidence.');
                return;
              }
              fileInputRef.current?.click();
            }}
            onKeyDown={(event) => {
              if ((event.key === 'Enter' || event.key === ' ') && !isLoading && authorizedChecked) {
                event.preventDefault();
                fileInputRef.current?.click();
              }
            }}
            className={`p-4 border-2 border-dashed rounded-xl flex flex-col items-center justify-center text-center transition-all group ${
              isLoading 
                ? 'opacity-50 cursor-not-allowed border-border-subtle' 
                : !authorizedChecked
                ? 'border-border-subtle/60 bg-surface-muted/40 cursor-not-allowed'
                : 'border-border-subtle hover:border-accent-primary/50 bg-surface-muted hover:bg-canvas cursor-pointer'
            }`}
          >
            <Upload size={20} className={`transition-colors mb-1.5 ${!authorizedChecked ? 'text-text-muted/40' : 'text-text-muted group-hover:text-accent-primary'}`} />
            <span className={`text-xs font-semibold ${!authorizedChecked ? 'text-text-muted/70' : 'text-text-secondary'}`}>
              Drag and drop files here
            </span>
            <span className="text-[10px] text-text-muted mt-0.5">
              {!authorizedChecked ? 'Confirm authorization below to enable upload' : 'or click to browse your computer'}
            </span>
            <input
              ref={fileInputRef}
              type="file"
              disabled={isLoading}
              onChange={handleFileUpload}
              className="hidden"
            />
          </div>

          {/* Compact Authorization Checkbox and Privacy Note */}
          <div className="bg-surface-muted border border-border-subtle rounded-xl p-3 relative">
            <div className="flex items-start gap-2 justify-between">
              <label className="flex items-start gap-2 cursor-pointer select-none flex-1">
                <input
                  type="checkbox"
                  checked={authorizedChecked}
                  onChange={(e) => {
                    setAuthorizedChecked(e.target.checked);
                    if (e.target.checked) {
                      setErrorMessage(null);
                    }
                  }}
                  className="mt-0.5 rounded border-border-subtle bg-canvas text-accent-primary focus:ring-accent-primary/20 cursor-pointer w-3.5 h-3.5"
                />
                <span className="text-xs text-text-secondary font-semibold leading-tight">
                  I confirm I’m authorized to inspect and upload these logs.
                </span>
              </label>
              
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setShowAuthInfo(!showAuthInfo)}
                  className="text-text-muted hover:text-text-primary p-0.5 rounded-lg hover:bg-surface transition-colors shrink-0"
                  title="View authorization details"
                >
                  <Info size={14} />
                </button>
                
                {showAuthInfo && (
                  <>
                    <div 
                      className="fixed inset-0 z-40" 
                      onClick={() => setShowAuthInfo(false)}
                    />
                    <div className="absolute right-0 bottom-6 sm:bottom-auto sm:top-6 z-50 w-72 sm:w-80 p-3 bg-surface border border-border-strong rounded-xl text-[11px] text-text-muted leading-relaxed shadow-lg animate-fade-in">
                      PacketSage is for defensive analysis of authorized, non-sensitive evidence. PCAP/PCAPNG files are decoded in browser memory; supported text exports are sent to the serverless parsing endpoint. Active evidence is cleared on refresh, while some review-status preferences may persist locally. PacketSage does not initiate probes or live scans.
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <button
              onClick={() => {
                if (!authorizedChecked) return;
                fileInputRef.current?.click();
              }}
              disabled={isLoading || !authorizedChecked}
              className={`py-1.5 px-3 font-semibold rounded-lg text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer shadow-sm ${
                !authorizedChecked 
                  ? 'bg-surface-muted text-text-muted/60 border border-border-subtle/50 cursor-not-allowed' 
                  : 'bg-accent-primary hover:bg-accent-primary-hover text-white'
              }`}
            >
              <Upload size={13} />
              Browse files to upload
            </button>
            <button
              onClick={() => {
                const pasteArea = document.getElementById('paste-textarea');
                if (pasteArea) {
                  pasteArea.focus();
                  pasteArea.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
              }}
              disabled={isLoading}
              className="py-1.5 px-3 bg-surface hover:bg-surface-muted disabled:opacity-50 border border-border-subtle hover:border-border-strong text-text-secondary hover:text-text-primary font-medium rounded-lg text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer shadow-sm"
            >
              <FileText size={13} />
              Use paste mode
            </button>
          </div>

          <div className="pt-2.5 border-t border-border-subtle/50 flex justify-between items-center text-[10px] text-text-muted font-mono">
            <span>Formats: CSV, JSON, LOG, TSV, PCAP</span>
            <span>Capture max: 10MB</span>
          </div>
        </div>

        {/* Option 2 & Paste Container */}
        <div className="space-y-4 flex flex-col justify-between">
          
          {/* Prominent Demo/Sample Card */}
          <div className="p-[18px] bg-surface rounded-xl border border-accent-primary/25 dark:border-accent-primary/15 bg-accent-soft/[0.12] shadow-sm flex flex-col justify-between space-y-3 hover:border-accent-primary/45 transition-all">
            <div className="flex items-start gap-3">
              <div className="w-5.5 h-5.5 rounded-full bg-accent-soft text-accent-primary text-xs font-bold flex items-center justify-center shrink-0 mt-0.5 border border-accent-primary/20">
                2
              </div>
              <div className="space-y-1 min-w-0 flex-1">
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="text-[9px] font-bold text-accent-primary bg-accent-soft border border-accent-primary/15 px-2 py-0.5 rounded uppercase tracking-wider">
                    Option 2
                  </span>
                  <span className="text-[9px] font-bold text-white bg-blue-600 dark:bg-blue-500 px-2.5 py-0.5 rounded-full uppercase tracking-wider shadow-xs flex items-center shrink-0">
                    RECOMMENDED
                  </span>
                </div>
                
                <h4 className="text-sm font-bold text-text-primary flex items-center gap-1.5 mt-1.5">
                  <Terminal size={14} className="text-accent-primary shrink-0" />
                  Guided defensive-analysis sample
                </h4>
                <p className="text-xs text-text-muted leading-relaxed">
                  A generated dataset containing routine and review-worthy activity for a complete, evidence-grounded walkthrough.
                </p>
                
                <div className="text-[11px] text-text-muted flex items-center gap-1.5 mt-1">
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-accent-primary/50" />
                  <span>No authorization needed — generated sample evidence.</span>
                  <InfoPopover content="The sample dataset is built into PacketSage for demonstration and training. It does not require authorization because it is not user-provided evidence." align="left" />
                </div>
              </div>
            </div>

            <button
              onClick={handleLoadDemo}
              disabled={isLoading}
              className="w-full py-1.5 px-3 bg-accent-primary hover:bg-accent-primary-hover disabled:opacity-50 text-white font-semibold rounded-lg text-xs transition-all cursor-pointer flex items-center justify-center gap-2 shadow-sm"
            >
              {isLoading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  Loading guided sample…
                </>
              ) : (
                <>
                  <Database size={13} />
                  Load guided investigation sample
                </>
              )}
            </button>
          </div>

          {/* Paste structured log sample */}
          <div className="p-[18px] bg-surface rounded-xl border border-border-subtle shadow-sm flex flex-col justify-between space-y-3">
            <div className="space-y-0.5">
              <h4 className="text-xs font-semibold text-text-primary">
                Paste structured log sample
              </h4>
              <p className="text-[11px] text-text-muted leading-relaxed">
                Paste raw console text, network logs, or packet events below to parse immediately.
              </p>
            </div>

            <div className="space-y-2">
              <textarea
                id="paste-textarea"
                value={pastedLog}
                onChange={(e) => setPastedLog(e.target.value)}
                placeholder="e.g. 10.0.0.15 to 203.0.113.80 port 4444 Protocol TCP"
                className="w-full h-[60px] bg-surface-muted border border-border-subtle focus:border-accent-primary/40 rounded-lg p-2 font-mono text-[11px] text-text-primary placeholder:text-text-muted focus:outline-none resize-none focus:ring-1 focus:ring-accent-primary/20"
              />
            </div>

            {pastedLog.trim() && !authorizedChecked && (
              <div className="text-[10.5px] text-status-warning bg-status-warning-bg/10 border border-status-warning/15 px-2.5 py-2 rounded-lg leading-relaxed font-medium">
                Confirm authorization in Option 1 before submitting pasted logs.
              </div>
            )}

            <button
              onClick={handlePasteSubmit}
              disabled={isLoading || !pastedLog.trim() || !authorizedChecked}
              className={`w-full py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center justify-center gap-1.5 ${
                isLoading || !pastedLog.trim() || !authorizedChecked
                  ? 'bg-surface-muted text-text-muted/65 border border-border-subtle/60 cursor-not-allowed'
                  : 'bg-accent-primary hover:bg-accent-primary-hover text-white shadow-sm cursor-pointer border border-transparent'
              }`}
            >
              {isLoading ? (
                <>
                  <div className="w-3 h-3 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  Parsing logs...
                </>
              ) : (
                <>
                  <FileText size={13} />
                  Submit pasted logs
                </>
              )}
            </button>
          </div>

        </div>
      </div>

      {/* D. Supported Formats */}
      <div className="space-y-3 pt-2">
        <h4 className="text-[11px] font-bold text-text-muted uppercase tracking-wider select-none">
          Supported export formats guide
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          
          {/* Card 1: Wireshark CSV */}
          <div className="p-4 bg-surface rounded-xl border border-border-subtle shadow-xs flex gap-4 items-start">
            <div className="w-10 h-12 shrink-0">
              <svg viewBox="0 0 40 48" className="w-full h-full" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path
                  d="M4 2C4 0.895431 4.89543 0 6 0H26L36 10V42C36 43.1046 35.1046 44 34 44H6C4.89543 44 4 43.1046 4 42V2Z"
                  fill="var(--bg-surface-muted)"
                  stroke="var(--border-strong)"
                  strokeWidth="1.5"
                />
                <path
                  d="M26 0V10H36L26 0Z"
                  fill="var(--border-strong)"
                  stroke="var(--border-strong)"
                  strokeWidth="1.5"
                  strokeLinejoin="round"
                />
                <rect x="8" y="14" width="6" height="4" rx="0.5" fill="#10b981" fillOpacity="0.15" stroke="#10b981" strokeWidth="0.5" />
                <rect x="16" y="14" width="16" height="4" rx="0.5" fill="var(--bg-surface)" stroke="var(--border-default)" strokeWidth="0.5" />
                <rect x="8" y="20" width="6" height="4" rx="0.5" fill="#10b981" fillOpacity="0.15" stroke="#10b981" strokeWidth="0.5" />
                <rect x="16" y="20" width="16" height="4" rx="0.5" fill="var(--bg-surface)" stroke="var(--border-default)" strokeWidth="0.5" />
                <rect x="4" y="28" width="32" height="12" rx="2" fill="#10b981" />
                <text
                  x="20"
                  y="37"
                  fill="#ffffff"
                  fontSize="8"
                  fontWeight="bold"
                  fontFamily="ui-monospace, SFMono-Regular, monospace"
                  textAnchor="middle"
                >
                  CSV
                </text>
              </svg>
            </div>
            <div className="space-y-1 min-w-0">
              <span className="font-bold text-xs text-text-primary block truncate">Wireshark CSV</span>
              <p className="text-text-muted text-[11px] leading-relaxed">
                Export packet list from Wireshark via File &gt; Export Packet Dissections &gt; as CSV. Include standard Time, Source, Destination, and Info.
              </p>
            </div>
          </div>

          {/* Card 2: Suricata EVE JSON */}
          <div className="p-4 bg-surface rounded-xl border border-border-subtle shadow-xs flex gap-4 items-start">
            <div className="w-10 h-12 shrink-0">
              <svg viewBox="0 0 40 48" className="w-full h-full" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path
                  d="M4 2C4 0.895431 4.89543 0 6 0H26L36 10V42C36 43.1046 35.1046 44 34 44H6C4.89543 44 4 43.1046 4 42V2Z"
                  fill="var(--bg-surface-muted)"
                  stroke="var(--border-strong)"
                  strokeWidth="1.5"
                />
                <path
                  d="M26 0V10H36L26 0Z"
                  fill="var(--border-strong)"
                  stroke="var(--border-strong)"
                  strokeWidth="1.5"
                  strokeLinejoin="round"
                />
                <text
                  x="20"
                  y="21"
                  fill="#a855f7"
                  fontSize="11"
                  fontWeight="bold"
                  fontFamily="ui-monospace, SFMono-Regular, monospace"
                  textAnchor="middle"
                  opacity="0.9"
                >
                  {`{ }`}
                </text>
                <rect x="4" y="28" width="32" height="12" rx="2" fill="#a855f7" />
                <text
                  x="20"
                  y="37"
                  fill="#ffffff"
                  fontSize="8"
                  fontWeight="bold"
                  fontFamily="ui-monospace, SFMono-Regular, monospace"
                  textAnchor="middle"
                >
                  JSON
                </text>
              </svg>
            </div>
            <div className="space-y-1 min-w-0">
              <span className="font-bold text-xs text-text-primary block truncate">Suricata EVE JSON</span>
              <p className="text-text-muted text-[11px] leading-relaxed">
                Accepts raw lines of `eve.json` alerts, DNS queries, HTTP logs, or SSL/TLS negotiations. Full intrusion signatures are parsed directly.
              </p>
            </div>
          </div>

          {/* Card 3: Zeek Logs TSV */}
          <div className="p-4 bg-surface rounded-xl border border-border-subtle shadow-xs flex gap-4 items-start">
            <div className="w-10 h-12 shrink-0">
              <svg viewBox="0 0 40 48" className="w-full h-full" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path
                  d="M4 2C4 0.895431 4.89543 0 6 0H26L36 10V42C36 43.1046 35.1046 44 34 44H6C4.89543 44 4 43.1046 4 42V2Z"
                  fill="var(--bg-surface-muted)"
                  stroke="var(--border-strong)"
                  strokeWidth="1.5"
                />
                <path
                  d="M26 0V10H36L26 0Z"
                  fill="var(--border-strong)"
                  stroke="var(--border-strong)"
                  strokeWidth="1.5"
                  strokeLinejoin="round"
                />
                <line x1="8" y1="16" x2="14" y2="16" stroke="#0d9488" strokeWidth="1.5" strokeLinecap="round" opacity="0.8" />
                <line x1="18" y1="16" x2="30" y2="16" stroke="var(--text-muted)" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
                <line x1="8" y1="22" x2="12" y2="22" stroke="#0d9488" strokeWidth="1.5" strokeLinecap="round" opacity="0.8" />
                <line x1="16" y1="22" x2="30" y2="22" stroke="var(--text-muted)" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
                <rect x="4" y="28" width="32" height="12" rx="2" fill="#0d9488" />
                <text
                  x="20"
                  y="37"
                  fill="#ffffff"
                  fontSize="8"
                  fontWeight="bold"
                  fontFamily="ui-monospace, SFMono-Regular, monospace"
                  textAnchor="middle"
                >
                  TSV
                </text>
              </svg>
            </div>
            <div className="space-y-1 min-w-0">
              <span className="font-bold text-xs text-text-primary block truncate">Zeek Logs TSV</span>
              <p className="text-text-muted text-[11px] leading-relaxed">
                Supports standard tab-separated values from `conn.log`, `dns.log`, `http.log`, and `ssl.log` folders containing `fields` headers.
              </p>
            </div>
          </div>

          {/* Card 4: TShark JSON Export */}
          <div className="p-4 bg-surface rounded-xl border border-border-subtle shadow-xs flex gap-4 items-start">
            <div className="w-10 h-12 shrink-0">
              <svg viewBox="0 0 40 48" className="w-full h-full" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path
                  d="M4 2C4 0.895431 4.89543 0 6 0H26L36 10V42C36 43.1046 35.1046 44 34 44H6C4.89543 44 4 43.1046 4 42V2Z"
                  fill="var(--bg-surface-muted)"
                  stroke="var(--border-strong)"
                  strokeWidth="1.5"
                />
                <path
                  d="M26 0V10H36L26 0Z"
                  fill="var(--border-strong)"
                  stroke="var(--border-strong)"
                  strokeWidth="1.5"
                  strokeLinejoin="round"
                />
                <text
                  x="20"
                  y="21"
                  fill="#0062f1"
                  fontSize="11"
                  fontWeight="bold"
                  fontFamily="ui-monospace, SFMono-Regular, monospace"
                  textAnchor="middle"
                  opacity="0.9"
                >
                  {`[ ]`}
                </text>
                <rect x="4" y="28" width="32" height="12" rx="2" fill="#0062f1" />
                <text
                  x="20"
                  y="37"
                  fill="#ffffff"
                  fontSize="8"
                  fontWeight="bold"
                  fontFamily="ui-monospace, SFMono-Regular, monospace"
                  textAnchor="middle"
                >
                  JSON
                </text>
              </svg>
            </div>
            <div className="space-y-1 min-w-0">
              <span className="font-bold text-xs text-text-primary block truncate">TShark JSON Export</span>
              <p className="text-text-muted text-[11px] leading-relaxed">
                Parsed from full-scale json translations run via command-line: `tshark -T json &gt; capture.json`. Extract multi-layer protocols.
              </p>
            </div>
          </div>

        </div>
      </div>

      {/* E. Before-Import Checklist */}
      <div className="pt-2">
        <div className="p-4 bg-surface rounded-xl border border-border-subtle shadow-xs space-y-2.5 max-w-2xl">
          <h4 className="text-[11px] font-bold text-text-muted uppercase tracking-wider flex items-center gap-1.5 select-none">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-primary" />
            Before-Import Checklist
          </h4>
          <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-xs text-text-secondary">
            {[
              "Verify full legal authorization to inspect these logs",
              "Ensure logs are sanitized of plaintext PII if needed",
              "Confirm file size is under 20MB for fast client-side decoding",
              "Select appropriate parser mode or leave on auto-detect"
            ].map((item, idx) => (
              <li key={idx} className="flex items-center gap-2">
                <input
                  type="checkbox"
                  defaultChecked
                  disabled
                  className="rounded border-status-success/30 text-status-success focus:ring-0 w-3.5 h-3.5 bg-status-success-bg cursor-default"
                />
                <span className="text-[11px] text-text-muted">{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

    </div>
  );
}
