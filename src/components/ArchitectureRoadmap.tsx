import React from 'react';
import { 
  Layers, 
  CheckCircle2, 
  Circle, 
  AlertCircle, 
  Cpu, 
  GitMerge, 
  ShieldCheck, 
  Database,
  ArrowRight,
  Server,
  Sparkles,
  Lock,
  FileText,
  Table,
  Shield,
  Clock,
  Terminal,
  ChevronRight,
  HardDrive,
  Workflow,
  Monitor
} from 'lucide-react';
import InfoPopover from './InfoPopover';

export default function ArchitectureRoadmap() {
  return (
    <div id="architecture-roadmap-workspace" className="space-y-8 font-sans max-w-7xl mx-auto pb-12">
      
      {/* 1) ARCHITECTURE HERO BANNER */}
      <div className="p-6 rounded-2xl border border-accent-primary/20 bg-accent-soft relative overflow-hidden shadow-xs">
        {/* Subtle background decoration */}
        <div className="absolute top-0 right-0 w-64 h-64 bg-accent-primary/5 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none" />
        
        <div className="space-y-4 relative z-10">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-accent-primary/10 text-accent-primary border border-accent-primary/10">
                Core Blueprint
              </span>
              <span className="text-[11px] font-semibold text-text-muted font-mono">v1.2.0-spec</span>
            </div>
            <h2 className="text-xl md:text-2xl font-bold tracking-tight text-text-primary">
              Forensic Platform Architecture
            </h2>
            <p className="text-xs md:text-sm text-text-secondary leading-relaxed max-w-4xl">
              Technical specifications mapping the telemetry pipeline, parsing mechanics, and heuristic engines of PacketSage. 
              This blueprint details our active browser-side evaluation model and the path to enterprise-grade production infrastructure.
            </p>
          </div>

          {/* 4 Compact System-State Tiles */}
          <div className="pt-2 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
            {[
              {
                label: "Current Mode",
                value: "Browser Sandbox",
                desc: "Client-side workspace runtime",
                icon: <Monitor size={14} className="stroke-[2.5]" />,
                colorClass: "bg-blue-600 text-white dark:bg-blue-500 border-transparent"
              },
              {
                label: "Retention",
                value: "Volatile Memory Only",
                desc: "Cleared on session refresh",
                icon: <Clock size={14} className="stroke-[2.5]" />,
                colorClass: "bg-amber-500 text-white dark:bg-amber-400 border-transparent"
              },
              {
                label: "Parser Model",
                value: "Demo Decoder",
                desc: "In-memory structured schemas",
                icon: <Cpu size={14} className="stroke-[2.5]" />,
                colorClass: "bg-blue-600 text-white dark:bg-blue-500 border-transparent"
              },
              {
                label: "Production Path",
                value: "Target Decoder Workers",
                desc: "Proposed containerized binaries",
                icon: <Server size={14} className="stroke-[2.5]" />,
                colorClass: "bg-purple-600 text-white dark:bg-purple-500 border-transparent"
              }
            ].map((tile, idx) => (
              <div key={idx} className="p-3.5 bg-surface rounded-xl border border-border-subtle flex items-start gap-3 shadow-xs">
                <div className={`p-2 rounded-lg shrink-0 mt-0.5 flex items-center justify-center ${tile.colorClass}`}>
                  {tile.icon}
                </div>
                <div className="space-y-0.5 min-w-0">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted block">
                    {tile.label}
                  </span>
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span className="text-[12px] font-bold text-text-primary block truncate">
                      {tile.value}
                    </span>
                    {tile.value === 'Browser Sandbox' && (
                      <InfoPopover content="Imported evidence is held in browser/session memory. AI-assisted investigation sends only a bounded packet of exact evidence referenced by the selected signal through the server-side proxy." align="right" />
                    )}
                    {tile.value === 'Demo Decoder' && (
                      <InfoPopover content="Demo Decoder supports structured sample and exported evidence parsing in the browser workspace. Full native binary PCAP decoding is a planned production target." align="right" />
                    )}
                    {tile.value === 'Target Decoder Workers' && (
                      <InfoPopover content="The planned production path integrates agent-less cloud logging, VPC flow logs, and centralized SIEM ingestion pipelines for real-time monitoring. This functionality is not active in sandbox mode." align="right" />
                    )}
                  </div>
                  <span className="text-[10px] text-text-secondary block truncate">
                    {tile.desc}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 2) CURRENT VS PRODUCTION ARCHITECTURE */}
      <div className="space-y-3">
        <div className="space-y-0.5">
          <h3 className="text-sm font-bold text-text-primary uppercase tracking-wider">System Operating Models</h3>
          <p className="text-xs text-text-muted">A technical comparison of the instant sandbox runtime versus full-scale cluster deployment</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Card 1: Current Sandbox */}
          <div className="p-5 bg-surface rounded-2xl border border-border-subtle flex flex-col justify-between shadow-xs relative">
            <div className="absolute top-4 right-4 text-[10px] font-bold font-mono text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded-md border border-emerald-500/20">
              ACTIVE
            </div>
            
            <div className="space-y-4">
              <div className="flex items-center gap-2 border-b border-border-subtle pb-3">
                <div className="p-1.5 bg-emerald-500/10 text-emerald-500 rounded-lg">
                  <Cpu size={16} />
                </div>
                <h4 className="text-xs font-bold text-text-primary uppercase tracking-wider">Current Sandbox Architecture</h4>
              </div>

              <div className="space-y-3">
                {[
                  {
                    title: "Browser-Side UI Workspace",
                    desc: "Interactive analysis console running strictly in the client frame, utilizing standard UI event loops.",
                    icon: <Layers size={13} className="text-emerald-500 mt-0.5" />
                  },
                  {
                    title: "In-Memory Ephemeral Staging",
                    desc: "Evidence, packets, and extracted parameters are stored temporarily in browser RAM state tables.",
                    icon: <Database size={13} className="text-emerald-500 mt-0.5" />
                  },
                  {
                    title: "Structured Log Parsing",
                    desc: "Fast front-end decoders normalize structured JSON, CSV, and PCAP logs into a standard schema.",
                    icon: <GitMerge size={13} className="text-emerald-500 mt-0.5" />
                  },
                  {
                    title: "Heuristic Rules Evaluation",
                    desc: "Real-time client checks for DNS tunnels, plain-text passwords, and active beaconing anomalies.",
                    icon: <ShieldCheck size={13} className="text-emerald-500 mt-0.5" />
                  },
                  {
                    title: "Evidence-scoped investigation",
                    desc: "The server proxy assesses one selected signal using its bounded, exact evidence packet.",
                    icon: <Sparkles size={13} className="text-emerald-500 mt-0.5" />
                  }
                ].map((item, idx) => (
                  <div key={idx} className="flex gap-2.5 items-start text-xs">
                    <span className="mt-0.5 shrink-0">{item.icon}</span>
                    <div className="space-y-0.5">
                      <strong className="text-text-primary font-semibold">{item.title}</strong>
                      <p className="text-text-secondary text-[11px] leading-relaxed">{item.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Card 2: Production Target */}
          <div className="p-5 bg-surface rounded-2xl border border-border-subtle flex flex-col justify-between shadow-xs relative">
            <div className="absolute top-4 right-4 text-[10px] font-bold font-mono text-purple-500 bg-purple-500/10 px-2 py-0.5 rounded-md border border-purple-500/20">
              TARGET
            </div>

            <div className="space-y-4">
              <div className="flex items-center gap-2 border-b border-border-subtle pb-3">
                <div className="p-1.5 bg-purple-500/10 text-purple-500 rounded-lg">
                  <Server size={16} />
                </div>
                <h4 className="text-xs font-bold text-text-primary uppercase tracking-wider">Production Architecture</h4>
              </div>

              <div className="space-y-3">
                {[
                  {
                    title: "Planned Ingress Gateway",
                    desc: "Proposed buffered edge proxy to receive, integrity-check, and store multi-gigabyte forensic capture files.",
                    icon: <HardDrive size={13} className="text-purple-500 mt-0.5" />
                  },
                  {
                    title: "Planned Decoder Pods",
                    desc: "Proposed isolated worker microservices running native compiled parser binaries (TShark, Zeek, Suricata) for capture processing.",
                    icon: <Terminal size={13} className="text-purple-500 mt-0.5" />
                  },
                  {
                    title: "Planned Broker Service",
                    desc: "Proposed decoupled scheduler orchestrating concurrent packet reassembly, extraction, and indexing.",
                    icon: <Workflow size={13} className="text-purple-500 mt-0.5" />
                  },
                  {
                    title: "Planned Normalization Pipeline",
                    desc: "Proposed high-throughput pipeline unifying binary telemetry events into normalized timelines and flow records.",
                    icon: <Layers size={13} className="text-purple-500 mt-0.5" />
                  },
                  {
                    title: "Proposed Persistent Storage",
                    desc: "Proposed role-guarded PostgreSQL (Cloud SQL) with standalone volatile Redis caching to store shared reports and audits.",
                    icon: <Database size={13} className="text-purple-500 mt-0.5" />
                  }
                ].map((item, idx) => (
                  <div key={idx} className="flex gap-2.5 items-start text-xs">
                    <span className="mt-0.5 shrink-0">{item.icon}</span>
                    <div className="space-y-0.5">
                      <strong className="text-text-primary font-semibold">{item.title}</strong>
                      <p className="text-text-secondary text-[11px] leading-relaxed">{item.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 3) DATA FLOW & PROCESSING PIPELINE */}
      <div className="space-y-3">
        <div className="space-y-0.5">
          <h3 className="text-sm font-bold text-text-primary uppercase tracking-wider">Data Flow & Processing Pipeline</h3>
          <p className="text-xs text-text-muted">High-level telemetry ingestion, parsing, threat matching, and output cycle</p>
        </div>

        <div className="p-5 bg-surface rounded-2xl border border-border-subtle shadow-sm">
          <div className="flex flex-col xl:flex-row gap-4 xl:gap-2 items-stretch justify-between">
            {[
              {
                id: '01',
                title: "Evidence Intake",
                desc: "Secure upload or simulation of raw forensic evidence into local storage stream buffers.",
                icon: <Database size={16} />,
                status: "Client runtime",
                statusClass: "bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/10"
              },
              {
                id: '02',
                title: "Decoder Parsing",
                desc: "Adapters map raw metadata structure and packets into unified, query-ready flow arrays.",
                icon: <GitMerge size={16} />,
                status: "Sandbox parser",
                statusClass: "bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/10"
              },
              {
                id: '03',
                title: "Heuristic Engine",
                desc: "Multi-point rules evaluate DNS query length, protocol entropy, plain credentials, and anomalies.",
                icon: <ShieldCheck size={16} />,
                status: "Rule engine active",
                statusClass: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/10"
              },
              {
                id: '04',
                title: "AI-assisted investigation",
                desc: "Server-side GPT-5.6 proxy assesses one signal using only its exact validated evidence packet.",
                icon: <Sparkles size={16} />,
                status: "AI proxy active",
                statusClass: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/10"
              },
              {
                id: '05',
                title: "Report Outputs",
                desc: "Generates export-clean Markdown incident dossiers, print views, and timeline audits.",
                icon: <FileText size={16} />,
                status: "Report builder active",
                statusClass: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/10"
              }
            ].map((stage, idx, arr) => (
              <React.Fragment key={stage.id}>
                <div className="flex-1 min-w-0 bg-canvas p-4 rounded-xl border border-border-subtle/80 flex flex-col justify-between space-y-3 shadow-xs">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="p-2 bg-surface rounded-lg text-accent-primary border border-border-subtle/60 shrink-0">
                        {stage.icon}
                      </div>
                      <span className="font-mono text-xs font-bold text-text-muted">{stage.id}</span>
                    </div>
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-1.5">
                        <h4 className="text-xs font-bold text-text-primary tracking-tight">{stage.title}</h4>
                        {stage.title === 'AI-assisted investigation' && (
                          <InfoPopover content="AI-assisted investigation uses a server-side proxy and bounded normalized evidence packets. Raw packet payloads and capture bytes are excluded." align="right" />
                        )}
                      </div>
                      <p className="text-[11px] text-text-secondary leading-relaxed">{stage.desc}</p>
                    </div>
                  </div>
                  <span className={`text-[9px] font-bold uppercase tracking-wider py-0.5 px-2 rounded-md border w-fit block ${stage.statusClass}`}>
                    {stage.status}
                  </span>
                </div>
                
                {idx < arr.length - 1 && (
                  <div className="flex items-center justify-center py-1 xl:py-0 shrink-0 select-none">
                    <ChevronRight size={18} className="text-text-muted rotate-90 xl:rotate-0 stroke-[1.5]" />
                  </div>
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      </div>

      {/* 4) SECURITY & PRIVACY BOUNDARIES */}
      <div className="space-y-3">
        <div className="space-y-0.5">
          <h3 className="text-sm font-bold text-text-primary uppercase tracking-wider">Security & Privacy Guardrails</h3>
          <p className="text-xs text-text-muted">Built-in design patterns keeping raw intellectual captures fully contained and secure</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            {
              title: "Local Volatile Memory",
              desc: "Incoming capture telemetry stays in browser memory during the session and is cleared completely on reload.",
              icon: <Clock size={16} className="text-accent-primary" />
            },
            {
              title: "No Raw Packet Upload",
              desc: "Raw packet files are not stored, indexed, or uploaded by PacketSage to cloud storage in sandbox mode.",
              icon: <Lock size={16} className="text-accent-primary" />
            },
            {
              title: "Passive Defensive Analysis",
              desc: "PacketSage performs passive analysis on loaded evidence and does not initiate active network probes or live traffic scans.",
              icon: <Shield size={16} className="text-accent-primary" />
            },
            {
              title: "Isolated Parsing Target",
              desc: "Proposed production decoder workers are designed to execute in isolated, network-restricted containers to process binary structures safely.",
              icon: <Server size={16} className="text-accent-primary" />
            }
          ].map((item, idx) => (
            <div key={idx} className="p-4 bg-surface rounded-2xl border border-border-subtle space-y-2.5 shadow-xs flex flex-col justify-start">
              <div className="p-2 bg-accent-soft text-accent-primary border border-accent-primary/5 rounded-xl w-fit">
                {item.icon}
              </div>
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-text-primary">{item.title}</h4>
                <p className="text-[11px] text-text-secondary leading-normal">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 5) TECHNOLOGY COMPONENTS MATRIX */}
      <div className="space-y-3">
        <div className="space-y-0.5">
          <h3 className="text-sm font-bold text-text-primary uppercase tracking-wider">Technology Components Matrix</h3>
          <p className="text-xs text-text-muted">Current stack implementation mapped against production-grade system targets</p>
        </div>

        <div className="bg-surface rounded-2xl border border-border-subtle overflow-hidden shadow-xs">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-raised border-b border-border-subtle">
                  <th className="p-3.5 font-bold text-text-primary uppercase tracking-wider text-[10px] w-1/4">System Layer</th>
                  <th className="p-3.5 font-bold text-text-primary uppercase tracking-wider text-[10px] w-3/8">Current Implementation</th>
                  <th className="p-3.5 font-bold text-text-primary uppercase tracking-wider text-[10px] w-3/8">Production Target</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/60">
                {[
                  {
                    layer: "UI / Presentation",
                    current: "React / TypeScript / Vite / Tailwind custom layout",
                    target: "React / TS running inline WebAssembly client-side decoders"
                  },
                  {
                    layer: "Decoding & Parsing",
                    current: "In-memory structured normalizers for JSON/TSV/CSV/demo PCAP metadata",
                    target: "Isolated decoder workers using tools such as TShark, Zeek, or Suricata where appropriate"
                  },
                  {
                    layer: "Correlation Rules",
                    current: "Client-side heuristic detection suites and risk calculation",
                    target: "High-throughput rules service correlating cross-flow hashes"
                  },
                  {
                    layer: "AI Processing",
                    current: "Evidence-grounded investigation plus a separate optional bounded capture overview",
                    target: "Isolated AI proxy with redaction, audit logs, and policy controls"
                  },
                  {
                    layer: "Data Retention",
                    current: "Transient browser/session state",
                    target: "Encrypted case storage with access controls and audit trails"
                  }
                ].map((row, idx) => (
                  <tr key={idx} className="hover:bg-canvas/45 transition-colors">
                    <td className="p-3.5 font-bold text-text-primary whitespace-nowrap">{row.layer}</td>
                    <td className="p-3.5 text-text-secondary leading-relaxed font-mono text-[11px]">{row.current}</td>
                    <td className="p-3.5 text-text-muted leading-relaxed font-mono text-[11px]">{row.target}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* 6) DEVELOPMENT ROADMAP */}
      <div className="space-y-3">
        <div className="space-y-0.5">
          <h3 className="text-sm font-bold text-text-primary uppercase tracking-wider">PacketSage Development Roadmap</h3>
          <p className="text-xs text-text-muted">Sequential milestone phases on our evolutionary path to an enterprise workstation</p>
        </div>

        <div className="space-y-4">
          {[
            {
              id: 1,
              stage: "Stage 1 — Active",
              title: "Forensic Sandbox Workstation",
              status: "Active",
              statusClass: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20",
              desc: "Active browser-side workspace enabling in-memory normalization, deterministic signal review, evidence-grounded investigation, a separate optional capture overview, and explicit report inclusion.",
              deliverables: ["In-memory structured schema normalization", "Deterministic evidence relationships", "Evidence-only timeline and report generator", "Separated server-side investigation and capture-overview proxies"]
            },
            {
              id: 2,
              stage: "Stage 2 — Planned",
              title: "Planned Binary PCAP Decoders",
              status: "Planned",
              statusClass: "bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20",
              desc: "Proposed containerized decoder services leveraging native compiled parsing libraries (TShark, Zeek, Suricata) in restricted cloud runtime environments.",
              deliverables: ["Proposed binary PCAP stream ingestion", "Planned containerized Zeek/TShark workers", "Target multi-gigabyte parsing broker", "Flow-sequence raw offset indices"]
            },
            {
              id: 3,
              stage: "Stage 3 — Planned",
              title: "Proposed Case Storage & Auth",
              status: "Planned",
              statusClass: "bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20",
              desc: "Proposed integration of client-authenticated persistence layers, including secure Firestore databases or PostgreSQL stores to allow persistent case management.",
              deliverables: ["Planned secure client session authentication", "Proposed encrypted case database schemas", "Shared incident report storage targets", "Audited collaborative case notes"]
            },
            {
              id: 4,
              stage: "Stage 4 — Future Target",
              title: "Future Security Hardening & Sync",
              status: "Future Target",
              statusClass: "bg-slate-500/10 text-text-muted border border-border-subtle/80",
              desc: "Future operational compliance controls and passive external threat intelligence lookup connectors to augment extracted IP indicators with global C2 catalogs.",
              deliverables: ["Planned threat intelligence MISP connector", "Proposed passive greyNoise lookup check", "Autonomous indicator reputation scoring", "Operational workflow webhook outputs"]
            }
          ].map((phase) => (
            <div key={phase.id} className="p-5 bg-surface rounded-2xl border border-border-subtle flex flex-col md:flex-row gap-5 shadow-xs relative overflow-hidden">
              {/* Left stage tag block */}
              <div className="md:w-1/4 shrink-0 space-y-2">
                <span className={`text-[10px] font-bold uppercase tracking-wider px-2.5 py-1 rounded-md border inline-block ${phase.statusClass}`}>
                  {phase.stage}
                </span>
                <h4 className="text-sm font-bold text-text-primary tracking-tight">{phase.title}</h4>
              </div>
              
              {/* Right content details */}
              <div className="flex-1 space-y-3">
                <p className="text-xs text-text-secondary leading-relaxed">
                  {phase.desc}
                </p>
                <div className="space-y-1.5">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted block">Core Deliverables:</span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {phase.deliverables.map((item, idx) => (
                      <div key={idx} className="flex items-center gap-2 text-xs text-text-secondary">
                        <CheckCircle2 size={12} className="text-accent-primary shrink-0 stroke-[2]" />
                        <span>{item}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
