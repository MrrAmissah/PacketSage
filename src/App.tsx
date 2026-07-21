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
  Compass,
  Menu,
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
import ArchitectureRoadmap from './components/ArchitectureRoadmap';
import CaptureOverview from './components/CaptureOverview';
import GuidedSampleJourney from './components/GuidedSampleJourney';
import ContextualSpotlightTour from './components/ContextualSpotlightTour';
import { setCaptureOverviewInclusion } from './lib/captureOverview';
import {
  createJudgePathSession,
  deriveGeneralInvestigationStatus,
  deriveJudgePathProgress,
  findGuidedInvestigationSignal,
  shouldShowGuidedJourney,
  type GuidedSignalAction,
  type JudgePathAction,
  type JudgePathDestination,
  type JudgePathSession,
} from './lib/judgePath';
import { createReportDetailsSession, type ReportDetailsRecord } from './lib/reportDetails';
import {
  GUIDED_TOUR_COMPLETION_VALUE,
  GUIDED_TOUR_STORAGE_KEY,
  createGuidedTourSession,
  deriveGuidedTourWorkflowIndex,
  replayGuidedTourSession,
  shouldShowGuidedTour,
  type GuidedTourSession,
} from './lib/guidedTour';

type TabType = 'overview' | 'import' | 'flows' | 'protocols' | 'signals' | 'capture-overview' | 'timeline' | 'report' | 'academy' | 'architecture';
type ThemeMode = 'light' | 'dark' | 'system';

export default function App() {
  const [activeTab, setActiveTab] = useState<TabType>('import');
  const [parsedData, setParsedData] = useState<ParsedResult | null>(null);
  const [investigations, setInvestigations] = useState<InvestigationRecord[]>([]);
  const [captureOverview, setCaptureOverview] = useState<CaptureOverviewRecord | null>(null);
  const [selectedFlow, setSelectedFlow] = useState<FlowSummary | null>(null);
  const [relatedFlowScopeIds, setRelatedFlowScopeIds] = useState<string[] | null>(null);
  const [timelineFocusEventId, setTimelineFocusEventId] = useState<string | null>(null);
  const [reportDetails, setReportDetails] = useState<ReportDetailsRecord | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [signalStatusOverrides, setSignalStatusOverrides] = useState<Record<string, SignalReviewStatus>>({});
  const [guideSession, setGuideSession] = useState<JudgePathSession | null>(null);
  const [guidedSignalAction, setGuidedSignalAction] = useState<GuidedSignalAction | null>(null);
  const [guidedTourSession, setGuidedTourSession] = useState<GuidedTourSession | null>(null);
  const [assessmentWorkspaceSignalId, setAssessmentWorkspaceSignalId] = useState<string | null>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const workspaceScrollRef = React.useRef<HTMLDivElement>(null);
  const recommendedGuidedSignal = React.useMemo(() => parsedData
    ? findGuidedInvestigationSignal(parsedData.evidence.parseMode, parsedData.signals, parsedData.flows, parsedData.events)
    : null, [parsedData]);
  const currentInvestigationRecords = React.useMemo(() => investigations
    .filter(record => record.selectedEvidenceId === parsedData?.evidence.id), [investigations, parsedData?.evidence.id]);
  const completedInvestigationSignalIds = React.useMemo(() => currentInvestigationRecords
    .map(record => record.signalId), [currentInvestigationRecords]);
  const includedInvestigationSignalIds = React.useMemo(() => currentInvestigationRecords
    .filter(record => record.includedInReport)
    .map(record => record.signalId), [currentInvestigationRecords]);
  const hasIncludedInvestigation = includedInvestigationSignalIds.length > 0;
  const guidedTourWorkflowIndex = React.useMemo(() => deriveGuidedTourWorkflowIndex({
    parseMode: parsedData?.evidence.parseMode || '',
    evidenceIdentity: parsedData?.evidence.id || null,
    recommendedSignalId: recommendedGuidedSignal?.id || null,
    selectedSignalId: guideSession?.selectedSignalId || null,
    completedInvestigationSignalIds,
    includedInvestigationSignalIds,
    assessmentWorkspaceSignalId,
  }), [parsedData?.evidence.parseMode, parsedData?.evidence.id, recommendedGuidedSignal?.id, guideSession?.selectedSignalId, completedInvestigationSignalIds, includedInvestigationSignalIds, assessmentWorkspaceSignalId]);
  const guidedProgress = React.useMemo(() => deriveJudgePathProgress({
    evidenceLoaded: Boolean(parsedData),
    recommendedSignalId: recommendedGuidedSignal?.id || null,
    selectedSignalId: guideSession?.selectedSignalId || null,
    completedInvestigationSignalIds,
    includedInvestigationSignalIds,
    reportVisitedAfterInclusion: guideSession?.reportVisitedAfterInclusion || false,
  }), [parsedData, recommendedGuidedSignal?.id, guideSession?.selectedSignalId, guideSession?.reportVisitedAfterInclusion, completedInvestigationSignalIds, includedInvestigationSignalIds]);
  const investigationStatus = React.useMemo(() => (
    parsedData?.evidence.parseMode === 'demo' && recommendedGuidedSignal
      ? guidedProgress.status
      : deriveGeneralInvestigationStatus({
        evidenceLoaded: Boolean(parsedData),
        signalCount: parsedData?.signals.length || 0,
        hasFlows: Boolean(parsedData?.flows.length),
        hasEvents: Boolean(parsedData?.events.length),
        selectedSignalId: guideSession?.selectedSignalId || null,
        completedInvestigationSignalIds,
        includedInvestigationSignalIds,
        reportVisitedAfterInclusion: guideSession?.reportVisitedAfterInclusion || false,
      })
  ), [parsedData, recommendedGuidedSignal, guidedProgress.status, guideSession?.selectedSignalId, guideSession?.reportVisitedAfterInclusion, completedInvestigationSignalIds, includedInvestigationSignalIds]);
  
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
    if (activeTab === 'report' && hasIncludedInvestigation) {
      setGuideSession(previous => previous ? { ...previous, reportVisitedAfterInclusion: true } : previous);
    }
  }, [activeTab, parsedData?.evidence.id, hasIncludedInvestigation]);

  const finishGuidedTour = React.useCallback(() => {
    try {
      localStorage.setItem(GUIDED_TOUR_STORAGE_KEY, GUIDED_TOUR_COMPLETION_VALUE);
    } catch {
      // The tour still closes when browser preference storage is unavailable.
    }
    setGuidedTourSession(previous => previous ? { ...previous, active: false } : previous);
  }, []);

  const handleDataParsed = (data: ParsedResult) => {
    let tourCompletionPreference: string | null = null;
    try {
      tourCompletionPreference = localStorage.getItem(GUIDED_TOUR_STORAGE_KEY);
    } catch {
      // Treat unavailable preference storage as a fresh session.
    }
    setParsedData(data);
    setReportDetails(createReportDetailsSession(data.evidence.id));
    setInvestigations(clearInvestigationRecords());
    setCaptureOverview(null);
    setSignalStatusOverrides({});
    setSelectedFlow(null);
    setRelatedFlowScopeIds(null);
    setTimelineFocusEventId(null);
    setGuideSession(createJudgePathSession(data.evidence.id));
    setGuidedSignalAction(null);
    setGuidedTourSession(createGuidedTourSession(data.evidence.parseMode, data.evidence.id, tourCompletionPreference));
    setAssessmentWorkspaceSignalId(null);
    setActiveTab('overview'); // Take them to command center automatically
  };

  const handleResetData = () => {
    if (confirm("Are you sure you want to clear current forensic evidence? All volatile packet and log tables will be deleted.")) {
      setParsedData(null);
      setReportDetails(null);
      setInvestigations(clearInvestigationRecords());
      setCaptureOverview(null);
      setSignalStatusOverrides({});
      setSelectedFlow(null);
      setRelatedFlowScopeIds(null);
      setTimelineFocusEventId(null);
      setGuideSession(null);
      setGuidedSignalAction(null);
      setGuidedTourSession(null);
      setAssessmentWorkspaceSignalId(null);
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
    if (includedInReport) {
      setGuideSession(previous => previous ? { ...previous, reportVisitedAfterInclusion: false } : previous);
    }
  };

  const handleSignalSelected = React.useCallback((signalId: string) => {
    setGuideSession(previous => previous ? { ...previous, selectedSignalId: signalId } : previous);
  }, []);

  const handleGuidedSignalActionHandled = React.useCallback((requestId: number) => {
    setGuidedSignalAction(previous => previous?.requestId === requestId ? null : previous);
  }, []);

  const handleAssessmentWorkspaceChange = React.useCallback((signalId: string | null) => {
    setAssessmentWorkspaceSignalId(signalId);
  }, []);

  const handleReplayGuidedTour = React.useCallback(() => {
    if (parsedData?.evidence.parseMode !== 'demo' || !recommendedGuidedSignal) return;
    setActiveTab('signals');
    setGuidedSignalAction(previous => ({
      signalId: recommendedGuidedSignal.id,
      focusTarget: 'signal-list',
      requestId: (previous?.requestId || 0) + 1,
    }));
    setGuidedTourSession(previous => replayGuidedTourSession(
      parsedData.evidence.id,
      (previous?.requestId || 0) + 1,
    ));
  }, [parsedData?.evidence.id, parsedData?.evidence.parseMode, recommendedGuidedSignal]);

  const handleTourDisplayStepChange = React.useCallback((stepIndex: number) => {
    if (stepIndex === 0 && recommendedGuidedSignal) {
      setGuidedSignalAction(previous => ({
        signalId: recommendedGuidedSignal.id,
        focusTarget: 'signal-list',
        requestId: (previous?.requestId || 0) + 1,
      }));
      return;
    }
    if (stepIndex >= 3 || !assessmentWorkspaceSignalId) return;
    setGuidedSignalAction(previous => ({
      signalId: assessmentWorkspaceSignalId,
      focusTarget: 'assessment-summary',
      requestId: (previous?.requestId || 0) + 1,
    }));
  }, [assessmentWorkspaceSignalId, recommendedGuidedSignal]);

  const handleTimelineFocusHandled = React.useCallback(() => {
    setTimelineFocusEventId(null);
  }, []);

  const guidedJourneyVisible = parsedData
    ? shouldShowGuidedJourney(parsedData.evidence.parseMode, guideSession)
    : false;
  const commandCenterReplay = parsedData?.evidence.parseMode === 'demo' && !guidedJourneyVisible
    ? handleReplayGuidedTour
    : undefined;

  const handleInvestigationStatusAction = (action: JudgePathAction) => {
    setActiveTab(action.destination as TabType);
    if (action.destination !== 'signals' || action.id === 'review-observed-signals') return;
    const signalId = action.id === 'review-recommended-signal'
      ? recommendedGuidedSignal?.id
      : guideSession?.selectedSignalId || recommendedGuidedSignal?.id;
    if (!signalId) return;
    setGuidedSignalAction(previous => ({
      signalId,
      focusTarget: action.id === 'review-recommended-signal' ? 'signal-detail' : 'investigation',
      requestId: (previous?.requestId || 0) + 1,
    }));
  };

  const handleTourReviewSignal = React.useCallback(() => {
    if (!recommendedGuidedSignal) return;
    setActiveTab('signals');
    setGuideSession(previous => previous
      ? { ...previous, selectedSignalId: recommendedGuidedSignal.id }
      : previous);
    setGuidedSignalAction(previous => ({
      signalId: recommendedGuidedSignal.id,
      focusTarget: 'investigation',
      requestId: (previous?.requestId || 0) + 1,
    }));
  }, [recommendedGuidedSignal]);

  const handleTourOpenAssessment = React.useCallback(() => {
    if (!recommendedGuidedSignal) return;
    setActiveTab('signals');
    setGuidedSignalAction(previous => ({
      signalId: recommendedGuidedSignal.id,
      focusTarget: 'open-assessment',
      requestId: (previous?.requestId || 0) + 1,
    }));
  }, [recommendedGuidedSignal]);

  const renderActiveContent = () => {
    const availableFlows = parsedData?.flows || [];
    const visibleFlows = relatedFlowScopeIds === null
      ? availableFlows
      : resolveRelatedFlows(relatedFlowScopeIds, availableFlows);

    switch (activeTab) {
      case 'overview':
        return <CommandCenter data={parsedData} investigationStatus={investigationStatus} onPrimaryAction={handleInvestigationStatusAction} onReplayTour={commandCenterReplay} onNavigate={(tab) => {
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
            signals={parsedData?.signals || []}
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
            selectedSignalId={guideSession?.selectedSignalId || null}
            recommendedSignalId={recommendedGuidedSignal?.id || null}
            guidedSignalAction={guidedSignalAction}
            onGuidedSignalActionHandled={handleGuidedSignalActionHandled}
            onInvestigationCompleted={handleInvestigationCompleted}
            onInvestigationInvalidated={handleInvestigationInvalidated}
            onInvestigationInclusionChange={handleInvestigationInclusion}
            onSignalSelected={handleSignalSelected}
            onAssessmentWorkspaceChange={handleAssessmentWorkspaceChange}
            onNavigateToEvent={(eventId) => {
              setTimelineFocusEventId(eventId);
              setActiveTab('timeline');
            }}
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
            focusedEventId={timelineFocusEventId}
            onFocusedEventHandled={handleTimelineFocusHandled}
            onNavigateToFlows={(relatedFlows) => {
              setRelatedFlowScopeIds(relatedFlows.map(flow => flow.id));
              setSelectedFlow(relatedFlows[0] || null);
              setActiveTab('flows');
            }}
          />
        );
      case 'report':
        return <ReportBuilder data={parsedData} investigations={investigations} captureOverview={captureOverview} reportDetails={reportDetails} onReportDetailsChange={setReportDetails} signalStatusOverrides={signalStatusOverrides} />;
      case 'academy':
        return <LearningMode hasEvidence={!!parsedData} parsedData={parsedData} />;
      case 'architecture':
        return <ArchitectureRoadmap />;
      default:
        return <CommandCenter data={parsedData} investigationStatus={investigationStatus} onPrimaryAction={handleInvestigationStatusAction} onReplayTour={commandCenterReplay} onNavigate={(tab) => {
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
          <div className="flex items-center justify-between px-3 md:px-5 pb-2 md:pb-4 border-b border-[#1e293b]/40">
            <PacketSageLogo className="[&>span]:hidden md:[&>span]:block" iconClassName="w-7 h-7 md:w-8 md:h-8" forceLight={true} />
            <button type="button" onClick={() => setMobileNavOpen(open => !open)} aria-expanded={mobileNavOpen} aria-controls="primary-navigation" aria-label={mobileNavOpen ? 'Close primary navigation' : 'Open primary navigation'} className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-xs font-semibold text-white md:hidden"><Menu aria-hidden="true" size={14} /><span>{activeTab === 'overview' ? 'Command center' : activeTab === 'import' ? 'Import evidence' : activeTab === 'flows' ? 'Flow explorer' : activeTab === 'protocols' ? 'Protocol intelligence' : activeTab === 'signals' ? 'Signals & observations' : activeTab === 'capture-overview' ? 'Capture overview' : activeTab === 'timeline' ? 'Incident timeline' : activeTab === 'report' ? 'Report builder' : activeTab === 'architecture' ? 'Architecture spec' : 'Packet Academy'}</span></button>
          </div>

          {/* Navigation Items */}
          <nav id="primary-navigation" aria-label="Primary navigation" className={`${mobileNavOpen ? 'grid' : 'hidden'} grid-cols-1 gap-1 px-2 pb-2 md:block md:space-y-1 md:px-3 md:pb-0`}>
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
              { id: 'architecture', label: 'Architecture spec', icon: Terminal, enabled: true },
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
                    setMobileNavOpen(false);
                  }}
                  aria-current={isActive ? 'page' : undefined}
                  className={`relative min-w-0 w-full flex items-center gap-2.5 md:gap-3 px-3 md:px-3.5 py-2 md:py-2.5 text-xs font-medium rounded-lg transition-all text-left cursor-pointer group ${
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
        <header data-testid="workspace-status-header" className="min-h-12 bg-shell/80 backdrop-blur-md border-b border-border-subtle px-3 sm:px-6 py-2 grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 xl:gap-x-6 gap-y-2 shrink-0 select-none transition-colors duration-150 z-20">
          <div data-testid="evidence-status-strip" className="flex flex-wrap items-center gap-x-2 sm:gap-x-2.5 xl:gap-x-3 gap-y-1.5 text-xs text-text-muted font-normal min-w-0 w-full">
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

                <span aria-hidden="true" className="hidden 2xl:block h-3 w-px bg-border-subtle/60 shrink-0" />

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

                <span aria-hidden="true" className="hidden 2xl:block h-3 w-px bg-border-subtle/60 shrink-0" />

                {/* 3. AI assessment N/A */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <Sparkles size={12} className="text-text-muted shrink-0" />
                  <span className="text-text-muted font-normal hidden md:inline">AI assessments:</span>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-surface-muted border border-border-subtle/50 text-text-muted text-[10.5px] font-semibold tracking-wide uppercase select-none">
                    N/A
                  </span>
                </div>

                <span aria-hidden="true" className="hidden 2xl:block h-3 w-px bg-border-subtle/60 shrink-0" />

                {/* 4. Retention */}
                <div data-testid="header-retention" className="flex items-center gap-1.5 shrink-0">
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
                  <span
                    data-testid="evidence-filename"
                    role="status"
                    tabIndex={0}
                    aria-label={`Loaded evidence: ${parsedData.evidence.name}`}
                    aria-describedby="workspace-evidence-filename-tooltip"
                    className="group relative inline-flex min-w-0 max-w-[clamp(7rem,10vw,12rem)] items-center gap-1.5 rounded-md border border-accent-primary/20 bg-accent-soft px-2.5 py-0.5 text-[10.5px] font-mono font-bold text-accent-primary focus:outline-none focus:ring-2 focus:ring-accent-primary focus:ring-offset-1"
                  >
                    <span aria-hidden="true" className="min-w-0 truncate">{parsedData.evidence.name}</span>
                    <span id="workspace-evidence-filename-tooltip" role="tooltip" data-testid="evidence-filename-tooltip" className="pointer-events-none invisible absolute left-0 top-full z-50 mt-2 max-w-[min(22rem,calc(100vw-2rem))] break-all rounded-md border border-border-subtle bg-surface px-2.5 py-2 text-left font-sans text-[10px] font-medium leading-relaxed text-text-primary opacity-0 shadow-lg transition-opacity group-hover:visible group-hover:opacity-100 group-focus-visible:visible group-focus-visible:opacity-100">
                      Full filename: {parsedData.evidence.name}
                    </span>
                  </span>
                </div>

                <span aria-hidden="true" className="hidden 2xl:block h-3 w-px bg-border-subtle/60 shrink-0" />

                {/* 2. Parser / Decoder */}
                <div className="flex items-center gap-1.5 min-w-0 shrink-0">
                  <Cpu size={12} className="text-blue-400 shrink-0" />
                  <span className="text-text-muted font-normal hidden sm:inline">Parser:</span>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-blue-500/10 text-blue-400 border border-blue-500/20 text-[10.5px] font-bold uppercase tracking-wide">
                    {parsedData.evidence.parseMode}
                  </span>
                  <InfoPopover content="Raw PCAP/PCAPNG files are decoded locally in a bounded browser parser. Supported text exports are sent to the parsing endpoint." align="left" />
                </div>

                <span aria-hidden="true" className="hidden 2xl:block h-3 w-px bg-border-subtle/60 shrink-0" />

                {/* 3. Included AI-assisted assessments */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <Sparkles size={12} className="text-purple-400 shrink-0" />
                  <span className="text-text-muted font-normal hidden xl:inline">Included assessments:</span>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 text-[10.5px] font-bold uppercase tracking-wide">
                    {investigations.filter(record => record.includedInReport).length}
                  </span>
                  <InfoPopover content="Only successful evidence-scoped assessments that you explicitly include are added to the report draft. Inclusion does not confirm an inference." align="left" />
                </div>

                <span aria-hidden="true" className="hidden 2xl:block h-3 w-px bg-border-subtle/60 shrink-0" />

                {/* 4. Retention */}
                <div data-testid="header-retention" className="flex items-center gap-1.5 shrink-0">
                  <Clock size={12} className="text-text-muted shrink-0" />
                  <span className="text-text-muted font-normal hidden 2xl:inline">Retention:</span>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-500 border border-amber-500/20 text-[10.5px] font-bold uppercase tracking-wide">
                    Volatile
                  </span>
                  <InfoPopover content="Active evidence is held in application memory and cleared on refresh or reset. Some review-status preferences may persist locally." align="left" />
                </div>
              </>
            )}
          </div>

          {/* Right actions sequence: Theme toggle → Build report → local capture decode */}
          <div data-testid="header-actions" className="relative z-10 flex w-full min-w-0 shrink-0 flex-nowrap items-center justify-between gap-1.5 bg-shell/80 sm:w-auto sm:min-w-max sm:justify-end sm:gap-2 sm:border-l sm:border-border-subtle/60 sm:pl-4 xl:pl-6">
            {/* Theme toggle */}
            <div data-testid="theme-selector" className="flex h-8 shrink-0 items-center rounded-lg border border-border-subtle bg-surface-muted p-0.5">
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
                    aria-label={`Use ${t.label.toLowerCase()} theme`}
                    aria-pressed={isSelected}
                    className={`flex items-center gap-1 px-1.5 py-0.5 rounded-md transition-all text-[11px] font-medium cursor-pointer h-7 ${
                      isSelected
                        ? 'bg-surface text-accent-primary shadow-sm font-semibold'
                        : 'text-text-muted hover:text-text-primary font-normal'
                    }`}
                  >
                    <Icon size={11} />
                    <span className="hidden 2xl:inline">{t.label}</span>
                  </button>
                );
              })}
            </div>

            {/* Build report CTA */}
            {activeTab !== 'report' && (
              <button
                data-testid="build-report-action"
                disabled={!parsedData}
                onClick={() => parsedData && setActiveTab('report')}
                className={`h-8 px-2.5 text-[11px] font-semibold rounded-lg transition-all flex items-center gap-1 shadow-sm ${
                  parsedData
                    ? 'bg-accent-primary hover:bg-accent-primary-hover text-white cursor-pointer'
                    : 'bg-surface-muted text-text-muted border border-border-subtle cursor-not-allowed opacity-60'
                }`}
                title={!parsedData ? "Please import evidence to build an incident report" : undefined}
              >
                <span className="hidden xl:inline">Build Incident Report</span>
                <span className="xl:hidden">Report</span>
                <ArrowRight size={11} />
              </button>
            )}

            {/* Capture processing boundary */}
            <div data-testid="local-capture-status" role="status" aria-label="Local capture decoding is active" title="Raw capture decoding remains local to this browser" className="flex h-8 shrink-0 items-center gap-1 rounded-lg border border-status-success/25 bg-status-success-bg px-2 text-[10px] font-semibold text-status-success select-none">
              <Lock size={10} className="text-status-success" />
              <span className="hidden 2xl:inline">Local Capture Decode</span>
            </div>
          </div>
        </header>

        {/* Tab workspace window with standard responsive layout */}
        <div ref={workspaceScrollRef} className="flex-1 min-h-0 overflow-y-auto px-3 sm:px-6 md:px-8 py-4 sm:py-6 bg-canvas transition-colors duration-150">
          <div className="max-w-[1440px] mx-auto w-full">
            {parsedData && guidedJourneyVisible && (
              <GuidedSampleJourney
                progress={guidedProgress}
                onDismiss={() => {
                  setGuideSession(previous => previous ? { ...previous, dismissed: true } : previous);
                  finishGuidedTour();
                }}
                onNavigate={(destination: JudgePathDestination) => setActiveTab(destination)}
                onPrimaryAction={handleInvestigationStatusAction}
                onReplayTour={handleReplayGuidedTour}
              />
            )}
            {renderActiveContent()}
          </div>
        </div>
      </main>
      {guidedTourWorkflowIndex !== null
        && activeTab !== 'report'
        && shouldShowGuidedTour(guidedTourSession, parsedData?.evidence.parseMode || '', parsedData?.evidence.id || null) && (
          <ContextualSpotlightTour
            workflowIndex={guidedTourWorkflowIndex}
            replay={guidedTourSession?.replay || false}
            requestId={guidedTourSession?.requestId || 0}
            onDismiss={finishGuidedTour}
            onComplete={finishGuidedTour}
            onDisplayStepChange={handleTourDisplayStepChange}
            onReviewSignal={handleTourReviewSignal}
            onOpenAssessment={handleTourOpenAssessment}
          />
        )}
    </div>
  );
}
