import type { ParsedResult } from './parser.js';
import type {
  InvestigationRecord,
  CaptureOverviewRecord,
  SignalReviewStatus,
  SuspiciousSignal,
} from '../types.js';
import { includedInvestigationRecords } from './investigationRecords.js';
import { includedCaptureOverview } from './captureOverview.js';
import { formatEndpoint } from './ports.js';
import {
  reportDetailsForEvidence,
  type ReportDetails,
  type ReportDetailsRecord,
} from './reportDetails.js';

export const MAX_REPORT_TIMELINE_EVENTS = 100;
export const PACKETSAGE_REPORT_VERSION = 'v1.1.0';

export interface ReportFinding {
  title: string;
  severity: SuspiciousSignal['severity'];
  signalId: string;
  relatedFlowIds: string[];
  relatedEventIds: string[];
}

export interface ReportTimelineEvent {
  id: string;
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  signalIds: string[];
}

export interface ReportRecommendation {
  action: string;
  reason?: string;
  source: string;
}

export interface ReportModel {
  details: ReportDetails;
  generation: {
    generatedAt: string;
    timeZone: string;
    status: 'Draft';
    packetSageVersion: string;
  };
  evidence: {
    name: string;
    identity: string;
    type: string;
    parseMode: string;
    checksum: string;
    earliestRecordedEvent: string | null;
    latestRecordedEvent: string | null;
  };
  executiveSummary: string;
  counts: {
    events: number;
    flows: number;
    signals: number;
    reviewedFindings: number;
    includedAssessments: number;
  };
  findings: ReportFinding[];
  timeline: ReportTimelineEvent[];
  timelineTruncated: boolean;
  assessments: InvestigationRecord[];
  contextualOverview: CaptureOverviewRecord | null;
  recommendations: ReportRecommendation[];
}

export interface ReportBuildOptions {
  reportDetails?: ReportDetailsRecord | null;
  generatedAt?: string;
  timeZone?: string;
}

function orderedUnique(values: readonly string[]): string[] {
  return Array.from(new Set(values));
}

export const formatReportEndpoint = formatEndpoint;

function statusFor(
  signal: SuspiciousSignal,
  overrides: Readonly<Record<string, SignalReviewStatus>>,
): SignalReviewStatus {
  return overrides[signal.id] || signal.status || 'Needs review';
}

export function evidenceChecksumLabel(data: ParsedResult): string {
  if (data.evidence.parseMode === 'demo' || data.evidence.checksumStatus === 'demo-not-applicable') {
    return 'Not applicable — generated demonstration dataset';
  }
  if (data.evidence.checksumStatus === 'calculated' && /^[a-f0-9]{64}$/.test(data.evidence.sha256 || '')) {
    return data.evidence.sha256 as string;
  }
  return 'Not calculated';
}

function safeGenerationTime(value: string | undefined): string {
  if (!value) return new Date().toISOString();
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : new Date().toISOString();
}

function explicitTimeZone(generatedAt: string, requestedTimeZone: string | undefined): string {
  const timeZone = requestedTimeZone || 'UTC';
  try {
    const zonePart = new Intl.DateTimeFormat('en-US', {
      timeZone,
      timeZoneName: 'longOffset',
    }).formatToParts(new Date(generatedAt)).find(part => part.type === 'timeZoneName')?.value || 'GMT';
    const offset = zonePart === 'GMT' ? 'UTC+00:00' : zonePart.replace('GMT', 'UTC');
    return `${timeZone} (${offset})`;
  } catch {
    return 'UTC (UTC+00:00)';
  }
}

function exactRelatedEventIds(
  signal: SuspiciousSignal,
  flowMap: ReadonlyMap<string, ParsedResult['flows'][number]>,
): string[] {
  const viaFlows = (signal.relatedFlowIds || [])
    .flatMap(flowId => flowMap.get(flowId)?.relatedEvents || []);
  return orderedUnique([...(signal.relatedEventIds || []), ...viaFlows]);
}

export function buildReportModel(
  data: ParsedResult,
  records: readonly InvestigationRecord[],
  signalStatusOverrides: Readonly<Record<string, SignalReviewStatus>> = {},
  captureOverview: CaptureOverviewRecord | null = null,
  options: ReportBuildOptions = {},
): ReportModel {
  const assessments = includedInvestigationRecords(records, data.evidence.id);
  const contextualOverview = includedCaptureOverview(captureOverview, data.evidence.id);
  const flowMap = new Map(data.flows.map(flow => [flow.id, flow]));
  const signalEventIds = new Map(data.signals.map(signal => [signal.id, exactRelatedEventIds(signal, flowMap)]));
  const eventSignalIds = new Map<string, string[]>();
  signalEventIds.forEach((eventIds, signalId) => {
    eventIds.forEach(eventId => eventSignalIds.set(eventId, [...(eventSignalIds.get(eventId) || []), signalId]));
  });
  const reviewedSignals = data.signals.filter(signal => statusFor(signal, signalStatusOverrides) === 'Added to report');
  const findings = reviewedSignals.map(signal => ({
    title: signal.title,
    severity: signal.severity,
    signalId: signal.id,
    relatedFlowIds: [...(signal.relatedFlowIds || [])],
    relatedEventIds: signalEventIds.get(signal.id) || [],
  }));

  const sortedEvents = [...data.events].sort((left, right) => (
    left.timestamp.localeCompare(right.timestamp) || left.id.localeCompare(right.id)
  ));
  const timeline = sortedEvents.slice(0, MAX_REPORT_TIMELINE_EVENTS).map(event => ({
    id: event.id,
    timestamp: event.timestamp,
    source: formatReportEndpoint(event.sourceIp, event.sourcePort, event.sourcePortState),
    destination: formatReportEndpoint(event.destinationIp, event.destinationPort, event.destinationPortState),
    protocol: event.service || event.protocol,
    length: event.length,
    signalIds: eventSignalIds.get(event.id) || [],
  }));

  const recommendations: ReportRecommendation[] = [];
  assessments.forEach(record => {
    record.assessment.nextSteps.forEach(step => recommendations.push({
      action: step.action,
      reason: step.reason,
      source: `AI-assisted assessment for signal ${record.signalId}`,
    }));
  });
  reviewedSignals.forEach(signal => {
    if (signal.recommendedDefensiveCheck.trim()) {
      recommendations.push({
        action: signal.recommendedDefensiveCheck,
        source: `Reviewed signal ${signal.id}`,
      });
    }
  });

  const counts = {
    events: data.events.length,
    flows: data.flows.length,
    signals: data.signals.length,
    reviewedFindings: findings.length,
    includedAssessments: assessments.length,
  };
  const generatedAt = safeGenerationTime(options.generatedAt);
  const detailsRecord = reportDetailsForEvidence(options.reportDetails, data.evidence.id);

  return {
    details: detailsRecord.details,
    generation: {
      generatedAt,
      timeZone: explicitTimeZone(generatedAt, options.timeZone),
      status: 'Draft',
      packetSageVersion: PACKETSAGE_REPORT_VERSION,
    },
    evidence: {
      name: data.evidence.name,
      identity: data.evidence.id,
      type: data.evidence.type,
      parseMode: data.evidence.parseMode,
      checksum: evidenceChecksumLabel(data),
      earliestRecordedEvent: sortedEvents[0]?.timestamp || null,
      latestRecordedEvent: sortedEvents.at(-1)?.timestamp || null,
    },
    executiveSummary: `${data.evidence.name} (${data.evidence.type}) contains ${counts.events} parsed events, ${counts.flows} flows, and ${counts.signals} signals. This report draft includes ${counts.reviewedFindings} reviewed findings and ${counts.includedAssessments} explicitly included AI-assisted assessments. Inferences remain unconfirmed until independently validated.`,
    counts,
    findings,
    timeline,
    timelineTruncated: sortedEvents.length > MAX_REPORT_TIMELINE_EVENTS,
    assessments,
    contextualOverview,
    recommendations,
  };
}

function ids(values: readonly string[]): string {
  return values.length ? values.map(value => `\`${value}\``).join(', ') : 'None referenced';
}

function markdownValue(value: string): string {
  return value ? value.replace(/\|/g, '\\|').replace(/\r?\n/g, '<br>') : 'Not provided';
}

export function reportToMarkdown(report: ReportModel): string {
  let markdown = `# PacketSage\n\n**NETWORK EVIDENCE REPORT — DRAFT**\n\n`;
  markdown += `## Report identity\n\n- Investigator / Prepared by: ${markdownValue(report.details.investigator)}\n- Role or unit: ${markdownValue(report.details.roleOrUnit)}\n- Organization: ${markdownValue(report.details.organization)}\n- Case or reference ID: ${markdownValue(report.details.caseReferenceId)}\n- Report scope / notes: ${markdownValue(report.details.scopeNotes)}\n\n`;
  markdown += `## Report metadata\n\n- Generated: ${report.generation.generatedAt}\n- Timezone: ${report.generation.timeZone}\n- Status: ${report.generation.status}\n- PacketSage version: ${report.generation.packetSageVersion}\n\n`;
  markdown += `## Evidence identity\n\n- Filename: ${report.evidence.name}\n- Evidence identity: \`${report.evidence.identity}\`\n- Type: ${report.evidence.type}\n- Parse mode: ${report.evidence.parseMode}\n- SHA-256: ${report.evidence.checksum}\n- Earliest recorded event: ${report.evidence.earliestRecordedEvent || 'No recorded events'}\n- Latest recorded event: ${report.evidence.latestRecordedEvent || 'No recorded events'}\n- Event count: ${report.counts.events}\n- Flow count: ${report.counts.flows}\n- Signal count: ${report.counts.signals}\n- Reviewed-finding count: ${report.counts.reviewedFindings}\n- Included-assessment count: ${report.counts.includedAssessments}\n- Contextual-overview inclusion: ${report.contextualOverview ? 'Included' : 'Not included'}\n\n`;
  markdown += `## Executive summary\n\n${report.executiveSummary}\n\n`;
  markdown += `## Findings\n\n`;
  if (!report.findings.length) markdown += `No reviewed findings have been added to this report draft.\n\n`;
  report.findings.forEach(finding => {
    markdown += `### ${finding.title}\n\n- Severity: ${finding.severity}\n- Signal ID: \`${finding.signalId}\`\n- Related flow IDs: ${ids(finding.relatedFlowIds)}\n- Related event IDs: ${ids(finding.relatedEventIds)}\n\n`;
  });
  markdown += `## Timeline\n\n`;
  if (!report.timeline.length) markdown += `No timeline events were available in the selected evidence.\n\n`;
  if (report.timeline.length) {
    markdown += `| Recorded time / Evidence ID | Source → Destination | Protocol / Size | Linked observations |\n`;
    markdown += `| --- | --- | --- | --- |\n`;
    report.timeline.forEach(event => {
      markdown += `| ${event.timestamp}<br>\`${event.id}\` | ${event.source} → ${event.destination} | ${event.protocol}<br>${event.length} bytes | ${ids(event.signalIds)} |\n`;
    });
  }
  if (report.timelineTruncated) markdown += `\nTimeline truncated to ${MAX_REPORT_TIMELINE_EVENTS} of ${report.counts.events} events.\n`;
  markdown += `\n## Contextual overview\n\n`;
  if (!report.contextualOverview) {
    markdown += `No capture overview has been explicitly included.\n\n`;
  } else {
    const overview = report.contextualOverview;
    markdown += `### Capture overview — contextual note\n\n`;
    markdown += `**Contextual orientation — not evidence-linked.** This section contains no evidence citations.\n\n`;
    markdown += `Provider: ${overview.provider}; Model: ${overview.model}; Schema: ${overview.schemaVersion}; Generated: ${overview.createdAt}; Capture identity: ${overview.captureIdentity}.\n\n`;
    markdown += `${overview.result.executiveSummary}\n\n`;
    markdown += `#### Traffic-pattern explanation\n\n${overview.result.whatHappened}\n\n`;
    markdown += `#### Beginner perspective\n\n${overview.result.beginnerExplanation}\n\n`;
    markdown += `#### Technical perspective\n\n${overview.result.technicalExplanation}\n\n`;
    markdown += `#### Analyst triage questions\n\n${overview.result.analystQuestions}\n\n`;
    markdown += `#### Limitations\n\n${overview.result.limitations}\n\n`;
  }
  markdown += `## AI-assisted investigation assessments\n\n`;
  if (!report.assessments.length) markdown += `No AI-assisted assessments have been explicitly included in this report draft.\n\n`;
  report.assessments.forEach(record => {
    markdown += `### ${record.packet.signal.title}\n\n- Signal ID: \`${record.signalId}\`\n- Packet identity: \`${record.packetIdentity}\`\n- Provider: ${record.provider}\n- Model: ${record.model}\n- Schema: ${record.schemaVersion}\n- Generated: ${record.createdAt}\n- Evidence identity: ${record.selectedEvidenceId}\n\n${record.assessment.summary}\n\n`;
    markdown += `#### Observed evidence\n\n`;
    record.assessment.observedEvidence.forEach(item => {
      markdown += `- ${item.statement} Evidence IDs: ${ids(item.evidenceIds)}\n`;
    });
    markdown += `\n#### Analyst inference — Not confirmed\n\n`;
    record.assessment.inferences.forEach(item => {
      markdown += `- [${item.confidence} confidence] ${item.statement} Evidence IDs: ${ids(item.evidenceIds)}\n`;
    });
    markdown += `\n#### Uncertainty / missing evidence — Not confirmed\n\n`;
    record.assessment.uncertainties.forEach(item => { markdown += `- ${item}\n`; });
    markdown += `\n#### Recommended next investigative steps\n\n`;
    record.assessment.nextSteps.forEach(item => { markdown += `- ${item.action} — ${item.reason}\n`; });
    markdown += `\n`;
  });
  markdown += `## Case-specific recommendations\n\n`;
  if (!report.recommendations.length) return markdown + `No case-specific recommendations have been added to this report draft.\n`;
  report.recommendations.forEach(item => {
    markdown += `- ${item.action}${item.reason ? ` — ${item.reason}` : ''} Source: ${item.source}.\n`;
  });
  return markdown;
}
