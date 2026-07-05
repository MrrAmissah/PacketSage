/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  Shield,
  Server,
  Activity,
  Terminal,
  Layers,
  BookOpen,
  Cpu,
  Globe,
  Lock,
  FileText,
  Database,
  ShieldCheck,
  AlertCircle,
  HelpCircle,
  Clock,
  ArrowRight,
  Sun,
  Moon,
  Monitor,
  Sparkles
} from 'lucide-react';

import { AiAnalysisResult, FlowSummary } from './types';
import { ParsedResult } from './lib/parser';
import { PacketSageLogo } from './components/Logo';
import InfoPopover from './components/InfoPopover';
import CommandCenter from './components/CommandCenter';
import EvidenceImport from './components/EvidenceImport';
import FlowExplorer from './components/FlowExplorer';
import ProtocolIntelligence from './components/ProtocolIntelligence';
import SuspiciousSignals from './components/SuspiciousSignals';
import AiAnalyst from './components/AiAnalyst';
import IncidentTimeline from './components/IncidentTimeline';
import ReportBuilder from './components/ReportBuilder';
import LearningMode from './components/LearningMode';
import ArchitectureRoadmap from './components/ArchitectureRoadmap';

type TabType = 'overview' | 'import' | 'flows' | 'protocols' | 'signals' | 'ai' | 'timeline' | 'report' | 'academy' | 'architecture';
type ThemeMode = 'light' | 'dark' | 'system';

export default function App() {
  const [activeTab, setActiveTab] = useState<TabType>('import');
  const [parsedData, setParsedData] = useState<ParsedResult | null>(null);
  const [aiResult, setAiResult] = useState<AiAnalysisResult | null>(null);
  const [selectedFlow, setSelectedFlow] = useState<FlowSummary | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  
  const [theme, setTheme] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem('packet-sage-theme');
    return (saved as ThemeMode) || 'system';
  });

  React.useEffect(() => {
    const root = document.documentElement;
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    const applyTheme = () => {
      if (theme === 'dark') {
        root.classList.add('dark');
        root.classList.remove('light');
      } else if (theme === 'light') {
        root.classList.add('light');
        root.classList.remove('dark');
      } else {
        if (mediaQuery.matches) {
          root.classList.add('dark');
          root.classList.remove('light');
        } else {
          root.classList.add('light');
          root.classList.remove('dark');
        }
      }
    };

    applyTheme();
    localStorage.setItem('packet-sage-theme', theme);

    const listener = () => {
      if (theme === 'system') {
        applyTheme();
      }
    };

    mediaQuery.addEventListener('change', listener);
    return () => mediaQuery.removeEventListener('change', listener);
  }, [theme]);

  const handleDataParsed = (data: ParsedResult) => {
    setParsedData(data);
    setAiResult(null); // Reset AI result when new data is parsed
    setSelectedFlow(null);
    setActiveTab('overview'); // Take them to command center automatically
  };

  const handleResetData = () => {
    if (confirm("Are you sure you want to clear current forensic evidence? All volatile packet and log tables will be deleted.")) {
      setParsedData(null);
      setAiResult(null);
      setSelectedFlow(null);
      setActiveTab('import');
    }
  };

  const handleUpdateSignalStatus = (id: string, status: 'Needs review' | 'Added to report' | 'Dismissed') => {
    if (!parsedData) return;
    const updatedSignals = parsedData.signals.map(s => {
      if (s.id === id) {
        return { ...s, status };
      }
      return s;
    });
    setParsedData({
      ...parsedData,
      signals: updatedSignals
    });
  };

  const renderActiveContent = () => {
    switch (activeTab) {
      case 'overview':
        return <CommandCenter data={parsedData} onNavigate={(tab) => setActiveTab(tab as TabType)} />;
      case 'import':
        return <EvidenceImport onDataParsed={handleDataParsed} isLoading={isLoading} setIsLoading={setIsLoading} />;
      case 'flows':
        return (
          <FlowExplorer
            flows={parsedData?.flows || []}
            events={parsedData?.events || []}
            onSelectFlow={setSelectedFlow}
            selectedFlow={selectedFlow}
            onCloseDrawer={() => setSelectedFlow(null)}
            evidenceName={parsedData?.evidence.name}
          />
        );
      case 'protocols':
        return (
          <ProtocolIntelligence
            dns={parsedData?.dns || []}
            http={parsedData?.http || []}
            tls={parsedData?.tls || []}
            stats={parsedData?.protocolStats || []}
          />
        );
      case 'signals':
        return (
          <SuspiciousSignals
            signals={parsedData?.signals || []}
            flows={parsedData?.flows || []}
            onNavigateToFlows={(flow) => {
              setSelectedFlow(flow);
              setActiveTab('flows');
            }}
            onUpdateSignalStatus={handleUpdateSignalStatus}
          />
        );
      case 'ai':
        return (
          <AiAnalyst
            flows={parsedData?.flows || []}
            dns={parsedData?.dns || []}
            http={parsedData?.http || []}
            tls={parsedData?.tls || []}
            signals={parsedData?.signals || []}
            stats={parsedData?.protocolStats || []}
            fileName={parsedData?.evidence.name || 'unnamed_evidence'}
            analysisResult={aiResult}
            onAnalysisCompleted={setAiResult}
            isLoading={isLoading}
            setIsLoading={setIsLoading}
          />
        );
      case 'timeline':
        return (
          <IncidentTimeline
            events={parsedData?.events || []}
            flows={parsedData?.flows || []}
            signals={parsedData?.signals || []}
            onNavigateToFlows={(flow) => {
              setSelectedFlow(flow);
              setActiveTab('flows');
            }}
          />
        );
      case 'report':
        return <ReportBuilder data={parsedData} aiResult={aiResult} isLoading={isLoading} />;
      case 'academy':
        return <LearningMode hasEvidence={!!parsedData} parsedData={parsedData} />;
      case 'architecture':
        return <ArchitectureRoadmap />;
      default:
        return <CommandCenter data={parsedData} onNavigate={(tab) => setActiveTab(tab as TabType)} />;
    }
  };

  return (
    <div id="packet-sage-workspace" className="flex h-screen bg-canvas text-text-primary overflow-hidden font-sans transition-colors duration-150">
      
      {/* Sidebar Rail */}
      <aside className="w-60 bg-[#08162e] border-r border-slate-900 flex flex-col justify-between shrink-0 select-none text-slate-100">
        <div className="space-y-6 pt-6">
          {/* Logo Heading */}
          <div className="px-5 pb-4 border-b border-[#1e293b]/40">
            <PacketSageLogo iconClassName="w-8 h-8" forceLight={true} />
          </div>

          {/* Navigation Items */}
          <nav className="space-y-1 px-3">
            {[
              { id: 'overview', label: 'Command center', icon: Server, enabled: !!parsedData },
              { id: 'import', label: 'Import evidence', icon: Database, enabled: true },
              { id: 'flows', label: 'Flow explorer', icon: Layers, enabled: !!parsedData },
              { id: 'protocols', label: 'Protocol intelligence', icon: Globe, enabled: !!parsedData },
              { id: 'signals', label: 'Signals & observations', icon: ShieldCheck, enabled: !!parsedData },
              { id: 'ai', label: 'AI analyst memo', icon: Cpu, enabled: !!parsedData },
              { id: 'timeline', label: 'Incident timeline', icon: Activity, enabled: !!parsedData },
              { id: 'report', label: 'Report builder', icon: FileText, enabled: !!parsedData },
              { id: 'academy', label: 'Packet Academy', icon: BookOpen, enabled: true },
              { id: 'architecture', label: 'Architecture spec', icon: Terminal, enabled: true },
            ].map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  disabled={!item.enabled}
                  onClick={() => setActiveTab(item.id as TabType)}
                  className={`relative w-full flex items-center gap-3 px-3.5 py-2.5 text-xs font-medium rounded-lg transition-all text-left cursor-pointer group ${
                    !item.enabled
                      ? 'text-slate-500 hover:bg-transparent cursor-not-allowed border border-transparent'
                      : isActive
                      ? 'bg-blue-600/10 text-white font-semibold border border-blue-500/10 shadow-sm'
                      : 'text-slate-300 hover:text-white hover:bg-white/5 border border-transparent'
                  }`}
                  title={!item.enabled ? "Available after importing evidence" : undefined}
                >
                  {/* Premium left indicator vertical bar */}
                  {isActive && (
                    <span className="absolute left-0 top-2 bottom-2 w-1 bg-[#38bdf8] rounded-r-md" />
                  )}
                  <Icon 
                    size={14} 
                    className={`transition-colors duration-150 shrink-0 ${
                      !item.enabled 
                        ? 'text-slate-500/60' 
                        : isActive 
                        ? 'text-[#38bdf8]' 
                        : 'text-slate-400 group-hover:text-slate-200'
                    }`} 
                  />
                  <span>{item.label}</span>
                  {!item.enabled && (
                    <Lock size={10} className="ml-auto text-slate-500/40" />
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Workspace Footer Actions */}
        <div className="p-4 border-t border-[#1e293b]/40 space-y-3 text-[10px] text-slate-400 font-medium bg-[#051022]/40">
          {parsedData && (
            <button
              onClick={handleResetData}
              className="w-full py-2 text-slate-300 hover:text-red-400 bg-transparent hover:bg-red-500/10 border border-slate-800 hover:border-red-500/20 rounded-lg text-[10px] font-medium tracking-wide transition-all cursor-pointer flex items-center justify-center gap-1.5"
            >
              Clear current evidence
            </button>
          )}
          <div className="flex justify-between items-center text-[9px] text-slate-400 uppercase tracking-wider">
            <span>Session: <strong className="text-amber-500 font-semibold">Volatile</strong></span>
            <span>Version: <strong className="text-slate-300 font-mono">v1.1.0</strong></span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0">
        
        {/* Top Evidence Bar */}
        <header className="h-12 bg-shell/80 backdrop-blur-md border-b border-border-subtle px-4 sm:px-6 flex items-center justify-between shrink-0 select-none transition-colors duration-150 z-20">
          <div className="flex items-center gap-1.5 sm:gap-3 text-xs text-text-muted font-normal min-w-0">
            {!parsedData ? (
              <>
                {/* 1. No Evidence Loaded */}
                <div className="flex items-center gap-1.5 min-w-0 shrink-0">
                  <Database size={12} className="text-text-muted shrink-0" />
                  <span className="text-text-muted font-normal hidden xs:inline">Evidence:</span>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-status-warning-bg/15 text-[#f59e0b] border border-status-warning/25 text-[10.5px] font-semibold tracking-wide uppercase select-none">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#f59e0b] animate-pulse shrink-0" />
                    None loaded
                  </span>
                </div>

                <span className="h-3 w-[1px] bg-border-subtle/60 shrink-0" />

                {/* 2. Parser / Decoder Idle */}
                <div className="flex items-center gap-1.5 min-w-0 shrink-0">
                  <Cpu size={12} className="text-text-muted shrink-0" />
                  <span className="text-text-muted font-normal hidden sm:inline">Parser:</span>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-surface-muted border border-border-subtle/50 text-text-muted text-[10.5px] font-semibold tracking-wide uppercase select-none">
                    <span className="w-1.5 h-1.5 rounded-full bg-text-muted/40 shrink-0" />
                    Idle
                  </span>
                  <InfoPopover content="Demo Decoder means PacketSage is using browser-side structured parsing for sample or exported evidence. Full binary PCAP decoding is a planned production decoder-worker target." align="left" />
                </div>

                <span className="h-3 w-[1px] bg-border-subtle/60 shrink-0" />

                {/* 3. AI memo N/A */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <Sparkles size={12} className="text-text-muted shrink-0" />
                  <span className="text-text-muted font-normal hidden md:inline">AI memo:</span>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-surface-muted border border-border-subtle/50 text-text-muted text-[10.5px] font-semibold tracking-wide uppercase select-none">
                    N/A
                  </span>
                </div>

                <span className="h-3 w-[1px] bg-border-subtle/60 shrink-0 hidden sm:inline" />

                {/* 4. Retention */}
                <div className="flex items-center gap-1.5 shrink-0 hidden sm:flex">
                  <Clock size={12} className="text-text-muted shrink-0" />
                  <span className="text-text-muted font-normal hidden lg:inline">Retention:</span>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-surface-muted border border-border-subtle/50 text-text-muted text-[10.5px] font-semibold tracking-wide uppercase select-none">
                    Volatile
                  </span>
                  <InfoPopover content="Volatile means active evidence is staged in browser/session memory during sandbox analysis and cleared when the session is refreshed or reset." align="left" />
                </div>
              </>
            ) : (
              <>
                {/* 1. Evidence Loaded */}
                <div className="flex items-center gap-1.5 min-w-0 shrink-0">
                  <Database size={12} className="text-accent-primary shrink-0" />
                  <span className="text-text-muted font-normal hidden xs:inline">Evidence:</span>
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md bg-accent-soft text-accent-primary border border-accent-primary/20 text-[10.5px] font-mono font-bold truncate max-w-[80px] xs:max-w-[110px] sm:max-w-[140px] md:max-w-[170px] lg:max-w-[210px]" title={parsedData.evidence.name}>
                    {parsedData.evidence.name}
                  </span>
                </div>

                <span className="h-3 w-[1px] bg-border-subtle/60 shrink-0" />

                {/* 2. Parser / Decoder */}
                <div className="flex items-center gap-1.5 min-w-0 shrink-0">
                  <Cpu size={12} className="text-blue-400 shrink-0" />
                  <span className="text-text-muted font-normal hidden sm:inline">Parser:</span>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-blue-500/10 text-blue-400 border border-blue-500/20 text-[10.5px] font-bold uppercase tracking-wide">
                    {parsedData.evidence.parseMode}
                  </span>
                  <InfoPopover content="Demo Decoder means PacketSage is using browser-side structured parsing for sample or exported evidence. Full binary PCAP decoding is a planned production decoder-worker target." align="left" />
                </div>

                <span className="h-3 w-[1px] bg-border-subtle/60 shrink-0" />

                {/* 3. AI memo */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <Sparkles size={12} className="text-purple-400 shrink-0" />
                  <span className="text-text-muted font-normal hidden md:inline">AI memo:</span>
                  <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10.5px] font-bold uppercase tracking-wide ${
                    aiResult 
                      ? 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20' 
                      : 'bg-status-warning-bg/15 text-status-warning border border-status-warning/20'
                  }`}>
                    {aiResult ? 'Generated' : 'Pending'}
                  </span>
                  <InfoPopover content="AI memo generation uses selected decoded metadata and summaries to draft an analyst memo. PacketSage still requires human validation before conclusions are drawn." align="left" />
                </div>

                <span className="h-3 w-[1px] bg-border-subtle/60 shrink-0 hidden sm:inline" />

                {/* 4. Retention */}
                <div className="flex items-center gap-1.5 shrink-0 hidden sm:flex">
                  <Clock size={12} className="text-text-muted shrink-0" />
                  <span className="text-text-muted font-normal hidden lg:inline">Retention:</span>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-500 border border-amber-500/20 text-[10.5px] font-bold uppercase tracking-wide">
                    Volatile
                  </span>
                  <InfoPopover content="Volatile means active evidence is staged in browser/session memory during sandbox analysis and cleared when the session is refreshed or reset." align="left" />
                </div>
              </>
            )}
          </div>

          {/* Right actions sequence: Theme toggle → Build report → No cloud retention */}
          <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
            {/* Theme toggle */}
            <div className="flex items-center bg-surface-muted border border-border-subtle rounded-lg p-0.5 h-8">
              {[
                { id: 'light', icon: Sun, label: 'Light' },
                { id: 'dark', icon: Moon, label: 'Dark' },
                { id: 'system', icon: Monitor, label: 'System' },
              ].map((t) => {
                const Icon = t.icon;
                const isSelected = theme === t.id;
                return (
                  <button
                    key={t.id}
                    onClick={() => setTheme(t.id as ThemeMode)}
                    className={`flex items-center gap-1 px-1.5 py-0.5 rounded-md transition-all text-[11px] font-medium cursor-pointer h-7 ${
                      isSelected
                        ? 'bg-surface text-accent-primary shadow-sm font-semibold'
                        : 'text-text-muted hover:text-text-primary font-normal'
                    }`}
                  >
                    <Icon size={11} />
                    <span className="hidden lg:inline">{t.label}</span>
                  </button>
                );
              })}
            </div>

            {/* Build report CTA */}
            {activeTab !== 'report' && (
              <button
                disabled={!parsedData}
                onClick={() => parsedData && setActiveTab('report')}
                className={`h-8 px-2.5 text-[11px] font-semibold rounded-lg transition-all flex items-center gap-1 shadow-sm ${
                  parsedData
                    ? 'bg-accent-primary hover:bg-accent-primary-hover text-white cursor-pointer'
                    : 'bg-surface-muted text-text-muted border border-border-subtle cursor-not-allowed opacity-60'
                }`}
                title={!parsedData ? "Please import evidence to build an incident report" : undefined}
              >
                Build Incident Report
                <ArrowRight size={11} />
              </button>
            )}

            {/* No cloud retention */}
            <div className="h-8 px-2 bg-status-success-bg border border-status-success/25 rounded-lg text-[10px] text-status-success font-semibold flex items-center gap-1 select-none">
              <Lock size={10} className="text-status-success" />
              <span className="hidden xs:inline">No Cloud Retention</span>
            </div>
          </div>
        </header>

        {/* Tab workspace window with standard responsive layout */}
        <div className="flex-1 overflow-y-auto px-6 md:px-8 py-6 bg-canvas transition-colors duration-150">
          <div className="max-w-[1440px] mx-auto w-full">
            {renderActiveContent()}
          </div>
        </div>
      </main>
    </div>
  );
}

