import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Clock,
  Cloud,
  Code2,
  Compass,
  Cpu,
  Database,
  FileCheck2,
  FileText,
  Fingerprint,
  GitMerge,
  HardDrive,
  Layers,
  Lock,
  Monitor,
  Network,
  Server,
  Shield,
  ShieldCheck,
  Sparkles,
  Workflow,
} from 'lucide-react';
import {
  INVESTIGATION_TIMEOUT_MS,
  MAX_CAPTURE_BYTES,
  MAX_CAPTURE_PACKETS,
  MAX_INVESTIGATION_EVENTS,
  MAX_INVESTIGATION_FLOWS,
  MAX_INVESTIGATION_PROTOCOL_RECORDS,
  MAX_INVESTIGATION_REQUEST_BYTES,
  MAX_PARSED_RECORDS,
  MAX_REQUEST_BYTES,
  MAX_TEXT_CHARACTERS,
} from '../lib/limits';
import { MAX_REPORT_TIMELINE_EVENTS, PACKETSAGE_REPORT_VERSION } from '../lib/report';
import InfoPopover from './InfoPopover';

interface ArchitectureItem {
  title: string;
  description: string;
  icon: LucideIcon;
}

interface PipelineStage extends ArchitectureItem {
  id: string;
  status: string;
  statusClass: string;
}

const browserResponsibilities: ArchitectureItem[] = [
  {
    title: 'Interactive React workspace',
    description: 'React 19, TypeScript, Vite 6 and Tailwind CSS 4 render every investigation surface in the browser.',
    icon: Monitor,
  },
  {
    title: 'Bounded native capture decoding',
    description: 'PCAP and PCAPNG bytes are decoded locally for supported Ethernet, IPv4/IPv6, TCP, UDP, ICMP and basic DNS metadata.',
    icon: Cpu,
  },
  {
    title: 'Deterministic evidence model',
    description: 'Normalization, stable IDs, occurrence indexing, exact relationships, flow grouping and deterministic signals operate on the current case.',
    icon: Fingerprint,
  },
  {
    title: 'Volatile case and report state',
    description: 'Evidence, review decisions, AI results, report identity and inclusion choices are held in React memory and clear with the session.',
    icon: Database,
  },
];

const serverResponsibilities: ArchitectureItem[] = [
  {
    title: 'Text-evidence parsing',
    description: 'The /api/parse boundary validates and normalizes supported CSV, Suricata, Zeek, TShark JSON and strict text evidence.',
    icon: Code2,
  },
  {
    title: 'Evidence-grounded Investigation',
    description: 'The /api/investigate proxy sends one validated, bounded signal packet to GPT-5.6 with strict structured output and store: false.',
    icon: Sparkles,
  },
  {
    title: 'Optional Capture Overview',
    description: 'The separate /api/analyze proxy sends a redacted, bounded whole-capture summary to Gemini for orientation without evidence citations.',
    icon: Compass,
  },
  {
    title: 'Credential and error boundary',
    description: 'Provider credentials remain in server environment variables; schema checks, timeouts and client-safe errors protect the browser boundary.',
    icon: Lock,
  },
];

const pipelineStages: PipelineStage[] = [
  {
    id: '01',
    title: 'Evidence intake',
    description: 'Authorized capture, export, pasted record or generated sample enters the appropriate bounded path.',
    icon: HardDrive,
    status: 'Browser entry',
    statusClass: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/15',
  },
  {
    id: '02',
    title: 'Decode & normalize',
    description: 'Binary captures stay local; supported text is validated by the parser endpoint. Both produce one normalized schema.',
    icon: GitMerge,
    status: 'Split boundary',
    statusClass: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/15',
  },
  {
    id: '03',
    title: 'Correlate evidence',
    description: 'Stable IDs, exact relationships and deterministic rules drive flows, protocols, signals and the timeline.',
    icon: ShieldCheck,
    status: 'Deterministic',
    statusClass: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/15',
  },
  {
    id: '04',
    title: 'Investigate a signal',
    description: 'An operator may request a bounded assessment with validated citations and separated observation, inference and uncertainty.',
    icon: Sparkles,
    status: 'Explicit action',
    statusClass: 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-500/15',
  },
  {
    id: '05',
    title: 'Orient to the capture',
    description: 'An optional, separate whole-capture overview supports learning and triage but never becomes observed evidence.',
    icon: Compass,
    status: 'Optional context',
    statusClass: 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/15',
  },
  {
    id: '06',
    title: 'Build the report',
    description: 'Reviewed findings and explicitly included AI results compile into one preview, Markdown and print/PDF document.',
    icon: FileText,
    status: 'Explicit inclusion',
    statusClass: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/15',
  },
];

const trustBoundaries: ArchitectureItem[] = [
  {
    title: 'Raw-capture boundary',
    description: 'PCAP/PCAPNG bytes and packet payloads remain outside both AI requests. Capture files are decoded in browser memory and are not stored by PacketSage.',
    icon: Shield,
  },
  {
    title: 'Exact provenance',
    description: 'Relationships and cited navigation use parser-established IDs only. Unsupported model citations are removed without substitution.',
    icon: Network,
  },
  {
    title: 'Trust separation',
    description: 'Deterministic observations, model inference, uncertainty and contextual overview text remain distinct in the UI and report.',
    icon: Layers,
  },
  {
    title: 'Request isolation',
    description: 'AbortController cancellation plus monotonic request identity prevents stale, duplicate or out-of-order results from changing the current case.',
    icon: Activity,
  },
  {
    title: 'Explicit report handoff',
    description: 'No AI output enters a report automatically. Each retained result records provider, model, schema, creation time, evidence identity and inclusion state.',
    icon: FileCheck2,
  },
  {
    title: 'Honest failure',
    description: 'Malformed input, unsupported captures and upstream failures return bounded errors without packet reflection, stack traces or fabricated fallback findings.',
    icon: Lock,
  },
];

const implementationMatrix = [
  {
    layer: 'Presentation',
    current: 'React 19 + TypeScript + Vite 6 + Tailwind CSS 4',
    boundary: 'Single-session browser workspace; responsive primary navigation and print-specific report rendering',
  },
  {
    layer: 'Binary capture parsing',
    current: 'Browser-side PCAP/PCAPNG metadata decoder',
    boundary: `${MAX_CAPTURE_BYTES / 1024 / 1024} MiB capture and ${MAX_CAPTURE_PACKETS.toLocaleString()} packet limits; no stream reassembly, decryption or payload reconstruction`,
  },
  {
    layer: 'Text parsing',
    current: 'Serverless /api/parse using bundled deterministic adapters',
    boundary: `${MAX_TEXT_CHARACTERS.toLocaleString()} characters, ${MAX_PARSED_RECORDS.toLocaleString()} records and ${MAX_REQUEST_BYTES / 1024 / 1024} MiB request-body ceiling`,
  },
  {
    layer: 'Signal investigation',
    current: 'Server-side GPT-5.6 proxy with strict schema and store: false',
    boundary: `${MAX_INVESTIGATION_REQUEST_BYTES / 1024} KiB packet; ${MAX_INVESTIGATION_FLOWS} flows, ${MAX_INVESTIGATION_EVENTS} events and ${MAX_INVESTIGATION_PROTOCOL_RECORDS} protocol records; ${INVESTIGATION_TIMEOUT_MS / 1_000}-second timeout`,
  },
  {
    layer: 'Capture orientation',
    current: 'Separate Gemini overview proxy with model provenance',
    boundary: '180,000-character request; bounded record groups; contextual and citation-free',
  },
  {
    layer: 'Reporting',
    current: 'Deterministic in-browser report model, Preview, Markdown and print/PDF',
    boundary: `Up to ${MAX_REPORT_TIMELINE_EVENTS} timeline rows; only reviewed findings and explicitly included retained AI results`,
  },
  {
    layer: 'Retention & identity',
    current: 'Volatile React case state with source SHA-256 where applicable',
    boundary: 'No accounts, persistent cases or chain-of-custody system; only theme preference persists locally',
  },
];

const deliveryStages = [
  {
    stage: 'Stage 1',
    title: 'Trustworthy evidence foundation',
    description: 'Deterministic evidence IDs, honest findings, bounded PCAP/PCAPNG decoding, limits and safe errors.',
    deliverables: ['Native capture metadata decoding', 'Stable flow and evidence identity', 'Exact parser relationships', 'No fabricated fallback findings'],
  },
  {
    stage: 'Stage 2',
    title: 'Evidence-grounded Investigation',
    description: 'One-signal evidence packets, structured assessment output, citation validation and exact cited-flow navigation.',
    deliverables: ['Observation and inference separation', 'Citation allow-list validation', 'Concurrency isolation', 'Safe retry and failure states'],
  },
  {
    stage: 'Stage 3',
    title: 'Trustworthy case-to-report lifecycle',
    description: 'Explicit inclusion, model provenance and an optional Capture Overview kept separate from evidence-linked investigation.',
    deliverables: ['Independent AI result state', 'Explicit report handoff', 'Contextual overview boundary', 'Provider/model disclosure'],
  },
  {
    stage: 'Stage 4A',
    title: 'Judge-ready investigation workflow',
    description: 'Guided evidence journey, restored evidence-rich visual surfaces, full assessment review and professional report output.',
    deliverables: ['Guided sample progression', 'Connected incident timeline', 'Full assessment workspace', 'Professional report identity and PDF'],
  },
];

const deferredCapabilities: ArchitectureItem[] = [
  {
    title: 'Persistent case management',
    description: 'Authentication, durable case storage, multi-user collaboration and audit history are not implemented.',
    icon: Database,
  },
  {
    title: 'Large-capture worker tier',
    description: 'Isolated decoder workers and object storage may extend the bounded browser decoder, but are not part of the current runtime.',
    icon: Server,
  },
  {
    title: 'Enterprise policy gateway',
    description: 'Central redaction policy, organization-level provider controls and retained request audit logs remain future work.',
    icon: Cloud,
  },
  {
    title: 'External intelligence integrations',
    description: 'PacketSage does not currently enrich indicators with threat-intelligence feeds or launch active network checks.',
    icon: Workflow,
  },
];

function ResponsibilityList({ items, tone }: { items: ArchitectureItem[]; tone: 'emerald' | 'blue' }) {
  const iconClass = tone === 'emerald' ? 'text-emerald-500' : 'text-blue-500';
  return (
    <div className="space-y-3">
      {items.map(({ title, description, icon: Icon }) => (
        <div key={title} className="flex items-start gap-2.5 text-xs">
          <Icon size={14} aria-hidden="true" className={`${iconClass} mt-0.5 shrink-0`} />
          <div className="space-y-0.5">
            <strong className="font-semibold text-text-primary">{title}</strong>
            <p className="text-[11px] leading-relaxed text-text-secondary">{description}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

export function ArchitectureRoadmap() {
  return (
    <div id="architecture-roadmap-workspace" className="mx-auto max-w-7xl space-y-8 pb-12 font-sans">
      <header className="relative overflow-hidden rounded-2xl border border-accent-primary/20 bg-accent-soft p-6 shadow-xs">
        <div aria-hidden="true" className="pointer-events-none absolute -mr-20 -mt-20 right-0 top-0 h-64 w-64 rounded-full bg-accent-primary/5 blur-3xl" />
        <div className="relative z-10 space-y-4">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-accent-primary/10 bg-accent-primary/10 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-accent-primary">
                Current implementation
              </span>
              <span className="font-mono text-[11px] font-semibold text-text-muted">{PACKETSAGE_REPORT_VERSION} · Stage 4A build</span>
            </div>
            <h1 className="text-xl font-bold tracking-tight text-text-primary md:text-2xl">PacketSage Architecture Spec</h1>
            <p className="max-w-4xl text-xs leading-relaxed text-text-secondary md:text-sm">
              The implemented evidence pipeline, processing boundaries, trust controls and explicitly deferred production capabilities. Current behavior is separated from future targets throughout this view.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-3.5 pt-2 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { label: 'Workspace', value: 'Browser session', detail: 'React state · volatile case', icon: Monitor, tone: 'bg-blue-600 dark:bg-blue-500' },
              { label: 'Capture decoder', value: 'Browser-local', detail: `${MAX_CAPTURE_BYTES / 1024 / 1024} MiB · ${MAX_CAPTURE_PACKETS.toLocaleString()} packets`, icon: Cpu, tone: 'bg-emerald-600 dark:bg-emerald-500' },
              { label: 'Text parser', value: 'Serverless API', detail: 'Validated normalized output', icon: Code2, tone: 'bg-amber-500 dark:bg-amber-400' },
              { label: 'AI boundary', value: 'Two separate paths', detail: 'Signal investigation · overview', icon: Sparkles, tone: 'bg-purple-600 dark:bg-purple-500' },
            ].map(({ label, value, detail, icon: Icon, tone }) => (
              <div key={label} className="flex items-start gap-3 rounded-xl border border-border-subtle bg-surface p-3.5 shadow-xs">
                <div className={`${tone} mt-0.5 flex shrink-0 items-center justify-center rounded-lg p-2 text-white`}>
                  <Icon size={14} aria-hidden="true" className="stroke-[2.5]" />
                </div>
                <div className="min-w-0 space-y-0.5">
                  <span className="block text-[10px] font-bold uppercase tracking-wider text-text-muted">{label}</span>
                  <span className="block text-[12px] font-bold text-text-primary">{value}</span>
                  <span className="block text-[10px] text-text-secondary">{detail}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </header>

      <section aria-labelledby="runtime-boundaries-title" className="space-y-3">
        <div className="space-y-0.5">
          <h2 id="runtime-boundaries-title" className="text-sm font-bold uppercase tracking-wider text-text-primary">Current runtime boundaries</h2>
          <p className="text-xs text-text-muted">What executes in the operator’s browser and what crosses a server boundary</p>
        </div>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <article className="relative rounded-2xl border border-border-subtle bg-surface p-5 shadow-xs">
            <span className="absolute right-4 top-4 rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-600 dark:text-emerald-400">BROWSER</span>
            <div className="mb-4 flex items-center gap-2 border-b border-border-subtle pb-3">
              <div className="rounded-lg bg-emerald-500/10 p-1.5 text-emerald-500"><Monitor size={16} aria-hidden="true" /></div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">Local workspace</h3>
            </div>
            <ResponsibilityList items={browserResponsibilities} tone="emerald" />
          </article>

          <article className="relative rounded-2xl border border-border-subtle bg-surface p-5 shadow-xs">
            <span className="absolute right-4 top-4 rounded-md border border-blue-500/20 bg-blue-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-blue-600 dark:text-blue-400">SERVER</span>
            <div className="mb-4 flex items-center gap-2 border-b border-border-subtle pb-3">
              <div className="rounded-lg bg-blue-500/10 p-1.5 text-blue-500"><Server size={16} aria-hidden="true" /></div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary">Serverless and provider proxies</h3>
              <InfoPopover content="Supported text evidence crosses the parsing boundary. AI providers receive only their separate bounded metadata inputs; raw capture bytes and packet payloads are excluded from both model paths." align="right" />
            </div>
            <ResponsibilityList items={serverResponsibilities} tone="blue" />
          </article>
        </div>
      </section>

      <section aria-labelledby="pipeline-title" className="space-y-3">
        <div className="space-y-0.5">
          <h2 id="pipeline-title" className="text-sm font-bold uppercase tracking-wider text-text-primary">Evidence-to-report pipeline</h2>
          <p className="text-xs text-text-muted">Observed records remain authoritative as optional AI capabilities branch from bounded inputs</p>
        </div>
        <div className="rounded-2xl border border-border-subtle bg-surface p-5 shadow-sm">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-6" aria-label="PacketSage evidence processing pipeline">
            {pipelineStages.map((stage, index) => {
              const Icon = stage.icon;
              return (
                <article key={stage.id} className="relative flex min-w-0 flex-col justify-between space-y-3 rounded-xl border border-border-subtle/80 bg-canvas p-4 shadow-xs">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="rounded-lg border border-border-subtle/60 bg-surface p-2 text-accent-primary"><Icon size={16} aria-hidden="true" /></div>
                      <span className="font-mono text-xs font-bold text-text-muted">{stage.id}</span>
                    </div>
                    <div className="space-y-0.5">
                      <h3 className="text-xs font-bold tracking-tight text-text-primary">{stage.title}</h3>
                      <p className="text-[11px] leading-relaxed text-text-secondary">{stage.description}</p>
                    </div>
                  </div>
                  <span className={`block w-fit rounded-md border px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider ${stage.statusClass}`}>{stage.status}</span>
                  {index < pipelineStages.length - 1 && (
                    <ArrowRight aria-hidden="true" size={16} className="absolute -right-3 top-1/2 z-10 hidden -translate-y-1/2 text-text-muted xl:block" />
                  )}
                </article>
              );
            })}
          </div>
        </div>
      </section>

      <section aria-labelledby="trust-title" className="space-y-3">
        <div className="space-y-0.5">
          <h2 id="trust-title" className="text-sm font-bold uppercase tracking-wider text-text-primary">Evidence and AI trust controls</h2>
          <p className="text-xs text-text-muted">Controls implemented in the current code path—not aspirational security claims</p>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {trustBoundaries.map(({ title, description, icon: Icon }) => (
            <article key={title} className="rounded-2xl border border-border-subtle bg-surface p-4 shadow-xs">
              <div className="w-fit rounded-xl border border-accent-primary/5 bg-accent-soft p-2 text-accent-primary"><Icon size={16} aria-hidden="true" /></div>
              <h3 className="mt-2.5 text-xs font-bold text-text-primary">{title}</h3>
              <p className="mt-1 text-[11px] leading-relaxed text-text-secondary">{description}</p>
            </article>
          ))}
        </div>
      </section>

      <section aria-labelledby="matrix-title" className="space-y-3">
        <div className="space-y-0.5">
          <h2 id="matrix-title" className="text-sm font-bold uppercase tracking-wider text-text-primary">Implementation and bounds</h2>
          <p className="text-xs text-text-muted">Technology, execution location and enforced limits in the current build</p>
        </div>
        <div className="overflow-hidden rounded-2xl border border-border-subtle bg-surface shadow-xs">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-border-subtle bg-raised">
                  <th className="w-1/5 p-3.5 text-[10px] font-bold uppercase tracking-wider text-text-primary">System layer</th>
                  <th className="w-2/5 p-3.5 text-[10px] font-bold uppercase tracking-wider text-text-primary">Current implementation</th>
                  <th className="w-2/5 p-3.5 text-[10px] font-bold uppercase tracking-wider text-text-primary">Enforced boundary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/60">
                {implementationMatrix.map(row => (
                  <tr key={row.layer} className="transition-colors hover:bg-canvas/45">
                    <th scope="row" className="whitespace-nowrap p-3.5 font-bold text-text-primary">{row.layer}</th>
                    <td className="p-3.5 text-[11px] leading-relaxed text-text-secondary">{row.current}</td>
                    <td className="p-3.5 text-[11px] leading-relaxed text-text-muted">{row.boundary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section aria-labelledby="delivery-title" className="space-y-3">
        <div className="space-y-0.5">
          <h2 id="delivery-title" className="text-sm font-bold uppercase tracking-wider text-text-primary">Implemented delivery stages</h2>
          <p className="text-xs text-text-muted">The Build Week sequence now represented in this codebase</p>
        </div>
        <div className="space-y-4">
          {deliveryStages.map(stage => (
            <article key={stage.stage} className="flex flex-col gap-5 overflow-hidden rounded-2xl border border-border-subtle bg-surface p-5 shadow-xs md:flex-row">
              <div className="shrink-0 space-y-2 md:w-1/4">
                <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
                  <CheckCircle2 size={12} aria-hidden="true" /> {stage.stage} · Implemented
                </span>
                <h3 className="text-sm font-bold tracking-tight text-text-primary">{stage.title}</h3>
              </div>
              <div className="flex-1 space-y-3">
                <p className="text-xs leading-relaxed text-text-secondary">{stage.description}</p>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {stage.deliverables.map(item => (
                    <div key={item} className="flex items-center gap-2 text-xs text-text-secondary">
                      <CheckCircle2 size={12} aria-hidden="true" className="shrink-0 text-accent-primary" />
                      <span>{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section aria-labelledby="deferred-title" className="space-y-3">
        <div className="space-y-0.5">
          <h2 id="deferred-title" className="text-sm font-bold uppercase tracking-wider text-text-primary">Explicitly deferred architecture</h2>
          <p className="text-xs text-text-muted">Potential production extensions that the current interface must not imply are available</p>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {deferredCapabilities.map(({ title, description, icon: Icon }) => (
            <article key={title} className="rounded-2xl border border-dashed border-border-subtle bg-surface p-4 shadow-xs">
              <div className="flex items-center justify-between gap-3">
                <div className="w-fit rounded-xl border border-border-subtle bg-surface-muted p-2 text-text-muted"><Icon size={16} aria-hidden="true" /></div>
                <span className="rounded-md border border-border-subtle bg-surface-muted px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-text-muted">Not implemented</span>
              </div>
              <h3 className="mt-2.5 text-xs font-bold text-text-primary">{title}</h3>
              <p className="mt-1 text-[11px] leading-relaxed text-text-secondary">{description}</p>
            </article>
          ))}
        </div>
      </section>

      <aside className="flex items-start gap-3 rounded-2xl border border-status-warning/20 bg-status-warning-bg/10 p-4 text-xs text-text-secondary">
        <Clock size={16} aria-hidden="true" className="mt-0.5 shrink-0 text-status-warning" />
        <div>
          <h2 className="font-bold text-text-primary">Operational interpretation</h2>
          <p className="mt-1 leading-relaxed">
            PacketSage is a passive, single-session defensive analysis workspace—not a live sensor, malware detector, persistent evidence vault or chain-of-custody system. Network metadata and AI assistance support analyst review; they do not independently prove intent, compromise or root cause.
          </p>
        </div>
      </aside>

    </div>
  );
}

export default ArchitectureRoadmap;
