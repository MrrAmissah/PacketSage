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
  Sparkles,
  Compass
} from 'lucide-react';

import { CaptureOverviewRecord, FlowSummary, InvestigationRecord, SignalReviewStatus } from './types';
import { ParsedResult } from './lib/parser';
import { resolveRelatedFlows } from './lib/relatedFlows';
import {
  clearInvestigationRecords,
  removeInvestigationRecord,
  setInvestigationReportInclusion,
  upsertInvestigationRecord,
} from './lib/investigationRecords';
import { PacketSageLogo } from './components/Logo';
import InfoPopover from './components/InfoPopover';
import CommandCenter from './components/CommandCenter';
import EvidenceImport from './components/EvidenceImport';
import FlowExplorer from './components/FlowExplorer';
import ProtocolIntelligence from './components/ProtocolIntelligence';
import SuspiciousSignals from './components/SuspiciousSignals';
import IncidentTimeline from './components/IncidentTimeline';
import ReportBuilder from './components/ReportBuilder';
import LearningMode from './components/LearningMode';
import CaptureOverview from './components/CaptureOverview';
import GuidedSampleJourney from './components/GuidedSampleJourney';
import { setCaptureOverviewInclusion } from './lib/captureOverview';
import { createJudgePathSession, deriveJudgePathProgress, shouldShowGuidedJourney, type JudgePathDestination, type JudgePathSession } from './lib/judgePath';

type TabType = 'overview' | 'import' | 'flows' | 'protocols' | 'signals' | 'capture-overview' | 'timeline' | 'report' | 'academy';
type ThemeMode = 'light' | 'dark' | 'system';

export default function App() {
  const [activeTab, setActiveTab] = useState<TabType>('import');
  const [parsedData, setParsedData] = useState<ParsedResult | null>(null);
  const [investigations, setInvestigations] = useState<InvestigationRecord[]>([]);
  const [captureOverview, setCaptureOverview] = useState<CaptureOverviewRecord | null>(null);
  const [selectedFlow, setSelectedFlow] = useState<FlowSummary | null>(null);
  const [relatedFlowScopeIds, setRelatedFlowScopeIds] = useState<string[] | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [signalStatusOverrides, setSignalStatusOverrides] = useState<Record<string, SignalReviewStatus>>({});
  const [guideSession, setGuideSession] = useState<JudgePathSession | null>(null);
  const workspaceScrollRef = React.useRef<HTMLDivElement>(null);
  
  const [theme, setTheme] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem('packet-sage-theme');
    return (saved as ThemeMode) || 'light';
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

  React.useEffect(() => {
    workspaceScrollRef.current?.scrollTo({ top: 0, left: 0 });
    if (activeTab === 'report') setGuideSession(previous => previous ? { ...previous, reportVisited: true } : previous);
  }, [activeTab, parsedData?.evidence.id]);

  const handleDataParsed = (data: ParsedResult) => {
    setParsedData(data);
    setInvestigations(clearInvestigationRecords());
    setCaptureOverview(null);
    setSignalStatusOverrides({});
    setSelectedFlow(null);
    setRelatedFlowScopeIds(null);
    setGuideSession(createJudgePathSession(data.evidence.id));
    setActiveTab('overview'); // Take them to command center automatically
  };

  const handleResetData = () => {
    if (confirm("Are you sure you want to clear current forensic evidence? All volatile packet and log tables will be deleted.")) {
      setParsedData(null);
      setInvestigations(clearInvestigationRecords());
      setCaptureOverview(null);
      setSignalStatusOverrides({});
      setSelectedFlow(null);
      setRelatedFlowScopeIds(null);
      setGuideSession(null);
      setActiveTab('import');
    }
  };

  const handleUpdateSignalStatus = (id: string, status: SignalReviewStatus, linkedIds: string[] = []) => {
    const idsToUpdate = Array.from(new Set([id, ...linkedIds].filter(Boolean)));

    setSignalStatusOverrides(prev => {
      const next = { ...prev };
      idsToUpdate.forEach(signalId => {
        next[signalId] = status;
      });
      return next;
    });

    if (!parsedData) return;
    const updatedSignals = parsedData.signals.map(s => {
      if (idsToUpdate.includes(s.id)) {
        return { ...s, status };
      }
      return s;
    });
    setParsedData({
      ...parsedData,
      signals: updatedSignals
    });
  };

  const handleInvestigationCompleted = (record: InvestigationRecord) => {
    setInvestigations(previous => upsertInvestigationRecord(previous, record));
  };

  const handleInvestigationInvalidated = (signalId: string) => {
    setInvestigations(previous => removeInvestigationRecord(previous, signalId));
  };

  const handleInvestigationInclusion = (
    context: { selectedEvidenceId: string; signalId: string; packetIdentity: string },
    includedInReport: boolean,
  ) => {
    setInvestigations(previous => setInvestigationReportInclusion(previous, context, includedInReport));
  };

  const renderActiveContent = () => {
    const availableFlows = parsedData?.flows || [];
    const visibleFlows = relatedFlowScopeIds === null
      ? availableFlows
      : resolveRelatedFlows(relatedFlowScopeIds, availableFlows);

    switch (activeTab) {
      case 'overview':
        return <CommandCenter data={parsedData} signalStatusOverrides={signalStatusOverrides} onNavigate={(tab) => {
          if (tab === 'flows') setRelatedFlowScopeIds(null);
          setActiveTab(tab as TabType);
        }} />;
      case 'import':
        return <EvidenceImport onDataParsed={handleDataParsed} isLoading={isLoading} setIsLoading={setIsLoading} />;
      case 'flows':
        return (
          <FlowExplorer
            flows={visibleFlows}
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
            events={parsedData?.events || []}
            dns={parsedData?.dns || []}
            http={parsedData?.http || []}
            tls={parsedData?.tls || []}
            signalStatusOverrides={signalStatusOverrides}
            selectedEvidenceId={parsedData?.evidence.id || ''}
            investigationRecords={investigations}
            onInvestigationCompleted={handleInvestigationCompleted}
            onInvestigationInvalidated={handleInvestigationInvalidated}
            onInvestigationInclusionChange={handleInvestigationInclusion}
            onSignalSelected={() => setGuideSession(previous => previous ? { ...previous, signalSelected: true } : previous)}
            onOpenReport={() => setActiveTab('report')}
            onNavigateToFlows={(relatedFlows) => {
              setRelatedFlowScopeIds(relatedFlows.map(flow => flow.id));
              setSelectedFlow(relatedFlows[0] || null);
              setActiveTab('flows');
            }}
            onUpdateSignalStatus={handleUpdateSignalStatus}
          />
        );
      case 'capture-overview':
        return parsedData ? (
          <CaptureOverview
            data={parsedData}
            record={captureOverview}
            onCompleted={setCaptureOverview}
            onInvalidated={() => setCaptureOverview(null)}
            onInclusionChange={(included) => setCaptureOverview(previous => setCaptureOverviewInclusion(previous, parsedData.evidence.id, included))}
            onNavigate={(destination) => setActiveTab(destination)}
          />
        ) : null;
      case 'timeline':
        return (
          <IncidentTimeline
            events={parsedData?.events || []}
            flows={parsedData?.flows || []}
            signals={parsedData?.signals || []}
            onNavigateToFlows={(flow) => {
              setRelatedFlowScopeIds(null);
              setSelectedFlow(flow);
              setActiveTab('flows');
            }}
          />
        );
      case 'report':
        return <ReportBuilder data={parsedData} investigations={investigations} captureOverview={captureOverview} signalStatusOverrides={signalStatusOverrides} />;
      case 'academy':
        return <LearningMode hasEvidence={!!parsedData} parsedData={parsedData} />;
      default:
        return <CommandCenter data={parsedData} signalStatusOverrides={signalStatusOverrides} onNavigate={(tab) => {
          if (tab === 'flows') setRelatedFlowScopeIds(null);
          setActiveTab(tab as TabType);
        }} />;
    }
  };

  return (
    <div id="packet-sage-workspace" className="flex flex-col md:flex-row h-screen bg-canvas text-text-primary overflow-hidden font-sans transition-colors duration-150">
      
      {/* Sidebar Rail */}
      <aside className="w-full md:w-60 bg-[#08162e] border-b md:border-b-0 md:border-r border-slate-900 flex flex-col md:justify-between shrink-0 select-none text-slate-100">
        <div className="space-y-2 md:space-y-6 pt-2 md:pt-6 min-w-0">
          {/* Logo Heading */}
          <div className="px-3 md:px-5 pb-2 md:pb-4 border-b border-[#1e293b]/40">
            <PacketSageLogo className="[&>span]:hidden md:[&>span]:block" iconClassName="w-7 h-7 md:w-8 md:h-8" forceLight={true} />
          </div>

          {/* Navigation Items */}
          <nav className="flex md:block gap-2 md:space-y-1 px-2 md:px-3 pb-2 md:pb-0 overflow-x-auto mobile-scroll-snap">
            {[
              { id: 'overview', label: 'Command center', icon: Server, enabled: !!parsedData },
              { id: 'import', label: 'Import evidence', icon: Database, enabled: true },
              { id: 'flows', label: 'Flow explorer', icon: Layers, enabled: !!parsedData },
              { id: 'protocols', label: 'Protocol intelligence', icon: Globe, enabled: !!parsedData },
              { id: 'signals', label: 'Signals & observations', icon: ShieldCheck, enabled: !!parsedData },
              { id: 'capture-overview', label: 'Capture overview', icon: Compass, enabled: !!parsedData },
              { id: 'timeline', label: 'Incident timeline', icon: Activity, enabled: !!parsedData },
              { id: 'report', label: 'Report builder', icon: FileText, enabled: !!parsedData },
              { id: 'academy', label: 'Packet Academy', icon: BookOpen, enabled: true },
            ].map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  disabled={!item.enabled}
                  onClick={() => {
                    if (item.id === 'flows') setRelatedFlowScopeIds(null);
                    setActiveTab(item.id as TabType);
                  }}
                  className={`relative flex-none md:flex-auto min-w-[124px] md:min-w-0 md:w-full flex items-center gap-2.5 md:gap-3 px-3 md:px-3.5 py-2 md:py-2.5 text-xs font-medium rounded-lg transition-all text-left cursor-pointer group ${
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
                    <span className="absolute left-0 top-2 bottom-2 w-1 bg-[#38bdf8] rounded-r-md hidden md:block" />
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
                  <span className="truncate">{item.label}</span>
                  {!item.enabled && (
                    <Lock size={10} className="ml-auto text-slate-500/40" />
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Workspace Footer Actions */}
        <div className="hidden md:block p-4 border-t border-[#1e293b]/40 space-y-3 text-[10px] text-slate-400 font-medium bg-[#051022]/40">
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
        <div className="md:hidden px-2 pb-2 text-[10px] text-slate-400 font-medium bg-[#051022]/40 border-t border-[#1e293b]/40">
          <div className="flex items-center justify-between gap-2 pt-1.5">
            {parsedData ? (
              <button
                onClick={handleResetData}
                className="h-7 px-3 text-slate-300 hover:text-red-400 bg-transparent hover:bg-red-500/10 border border-slate-800 hover:border-red-500/20 rounded-lg text-[10px] font-medium tracking-wide transition-all cursor-pointer flex items-center justify-center gap-1.5"
              >
                Clear evidence
              </button>
            ) : (
              <span>Session: <strong className="text-amber-500 font-semibold">Volatile</strong></span>
            )}
            <span className="ml-auto">Version: <strong className="text-slate-300 font-mono">v1.1.0</strong></span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0 min-h-0">
        
        {/* Top Evidence Bar */}
        <header className="min-h-12 bg-shell/80 backdrop-blur-md border-b border-border-subtle px-3 sm:px-6 py-2 sm:py-0 flex flex-col sm:flex-row sm:items-center justify-between gap-2 shrink-0 select-none transition-colors duration-150 z-20">
          <div className="flex items-center gap-1.5 sm:gap-3 text-xs text-text-muted font-normal min-w-0 w-full sm:w-auto overflow-x-auto mobile-scroll-snap">
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
                  <InfoPopover content="Raw PCAP/PCAPNG files are decoded locally in a bounded browser parser. Supported text exports are sent to the parsing endpoint." align="left" />
                </div>

                <span className="h-3 w-[1px] bg-border-subtle/60 shrink-0" />

                {/* 3. AI assessment N/A */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <Sparkles size={12} className="text-text-muted shrink-0" />
                  <span className="text-text-muted font-normal hidden md:inline">AI assessments:</span>
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
                  <InfoPopover content="Active evidence is held in application memory and cleared on refresh or reset. Some review-status preferences may persist locally." align="left" />
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
                  <InfoPopover content="Raw PCAP/PCAPNG files are decoded locally in a bounded browser parser. Supported text exports are sent to the parsing endpoint." align="left" />
                </div>

                <span className="h-3 w-[1px] bg-border-subtle/60 shrink-0" />

                {/* 3. Included AI-assisted assessments */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <Sparkles size={12} className="text-purple-400 shrink-0" />
                  <span className="text-text-muted font-normal hidden md:inline">Included assessments:</span>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 text-[10.5px] font-bold uppercase tracking-wide">
                    {investigations.filter(record => record.includedInReport).length}
                  </span>
                  <InfoPopover content="Only successful evidence-scoped assessments that you explicitly include are added to the report draft. Inclusion does not confirm an inference." align="left" />
                </div>

                <span className="h-3 w-[1px] bg-border-subtle/60 shrink-0 hidden sm:inline" />

                {/* 4. Retention */}
                <div className="flex items-center gap-1.5 shrink-0 hidden sm:flex">
                  <Clock size={12} className="text-text-muted shrink-0" />
                  <span className="text-text-muted font-normal hidden lg:inline">Retention:</span>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-500 border border-amber-500/20 text-[10.5px] font-bold uppercase tracking-wide">
                    Volatile
                  </span>
                  <InfoPopover content="Active evidence is held in application memory and cleared on refresh or reset. Some review-status preferences may persist locally." align="left" />
                </div>
              </>
            )}
          </div>

          {/* Right actions sequence: Theme toggle → Build report → local capture decode */}
          <div className="flex items-center justify-between sm:justify-end gap-1.5 sm:gap-2 shrink-0 w-full sm:w-auto">
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
                <span className="hidden sm:inline">Build Incident Report</span>
                <span className="sm:hidden">Report</span>
                <ArrowRight size={11} />
              </button>
            )}

            {/* Capture processing boundary */}
            <div className="h-8 px-2 bg-status-success-bg border border-status-success/25 rounded-lg text-[10px] text-status-success font-semibold hidden sm:flex items-center gap-1 select-none">
              <Lock size={10} className="text-status-success" />
              <span className="hidden xs:inline">Local Capture Decode</span>
            </div>
          </div>
        </header>

        {/* Tab workspace window with standard responsive layout */}
        <div ref={workspaceScrollRef} className="flex-1 min-h-0 overflow-y-auto px-3 sm:px-6 md:px-8 py-4 sm:py-6 bg-canvas transition-colors duration-150">
          <div className="max-w-[1440px] mx-auto w-full">
            {parsedData && shouldShowGuidedJourney(parsedData.evidence.parseMode, guideSession) && (
              <GuidedSampleJourney
                progress={deriveJudgePathProgress({
                  evidenceLoaded: true,
                  signalSelected: guideSession?.signalSelected || false,
                  investigationIncluded: investigations.some(record => record.selectedEvidenceId === parsedData.evidence.id && record.includedInReport),
                  reportVisited: guideSession?.reportVisited || false,
                })}
                onDismiss={() => setGuideSession(previous => previous ? { ...previous, dismissed: true } : previous)}
                onNavigate={(destination: JudgePathDestination) => setActiveTab(destination)}
              />
            )}
            {renderActiveContent()}
          </div>
        </div>
      </main>
    </div>
  );
}
