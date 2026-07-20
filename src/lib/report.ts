import type { ParsedResult } from './parser.js';
import type {
  InvestigationRecord,
  SignalReviewStatus,
  SuspiciousSignal,
} from '../types.js';
import { includedInvestigationRecords } from './investigationRecords.js';

export const MAX_REPORT_TIMELINE_EVENTS = 100;

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
  evidence: {
    name: string;
    type: string;
    parseMode: string;
    checksum: string;
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
  recommendations: ReportRecommendation[];
}

function orderedUnique(values: readonly string[]): string[] {
  return Array.from(new Set(values));
}

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
): ReportModel {
  const assessments = includedInvestigationRecords(records, data.evidence.id);
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
    source: `${event.sourceIp}:${event.sourcePort}`,
    destination: `${event.destinationIp}:${event.destinationPort}`,
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

  return {
    evidence: {
      name: data.evidence.name,
      type: data.evidence.type,
      parseMode: data.evidence.parseMode,
      checksum: evidenceChecksumLabel(data),
    },
    executiveSummary: `${data.evidence.name} (${data.evidence.type}) contains ${counts.events} parsed events, ${counts.flows} flows, and ${counts.signals} signals. This report draft includes ${counts.reviewedFindings} reviewed findings and ${counts.includedAssessments} explicitly included AI-assisted assessments. Inferences remain unconfirmed until independently validated.`,
    counts,
    findings,
    timeline,
    timelineTruncated: sortedEvents.length > MAX_REPORT_TIMELINE_EVENTS,
    assessments,
    recommendations,
  };
}

function ids(values: readonly string[]): string {
  return values.length ? values.map(value => `\`${value}\``).join(', ') : 'None referenced';
}

export function reportToMarkdown(report: ReportModel): string {
  let markdown = `# PacketSage evidence report draft\n\n`;
  markdown += `## Evidence\n\n- Name: ${report.evidence.name}\n- Type: ${report.evidence.type}\n- Parse mode: ${report.evidence.parseMode}\n- SHA-256: ${report.evidence.checksum}\n\n`;
  markdown += `## Executive summary\n\n${report.executiveSummary}\n\n`;
  markdown += `## Findings\n\n`;
  if (!report.findings.length) markdown += `No reviewed findings have been added to this report draft.\n\n`;
  report.findings.forEach(finding => {
    markdown += `### ${finding.title}\n\n- Severity: ${finding.severity}\n- Signal ID: \`${finding.signalId}\`\n- Related flow IDs: ${ids(finding.relatedFlowIds)}\n- Related event IDs: ${ids(finding.relatedEventIds)}\n\n`;
  });
  markdown += `## Timeline\n\n`;
  if (!report.timeline.length) markdown += `No timeline events were available in the selected evidence.\n\n`;
  report.timeline.forEach(event => {
    markdown += `- ${event.timestamp} — \`${event.id}\` — ${event.source} → ${event.destination} — ${event.protocol} — ${event.length} bytes — Signals: ${ids(event.signalIds)}\n`;
  });
  if (report.timelineTruncated) markdown += `\nTimeline truncated to ${MAX_REPORT_TIMELINE_EVENTS} of ${report.counts.events} events.\n`;
  markdown += `\n## AI-assisted investigation assessments\n\n`;
  if (!report.assessments.length) markdown += `No AI-assisted assessments have been explicitly included in this report draft.\n\n`;
  report.assessments.forEach(record => {
    markdown += `### ${record.packet.signal.title}\n\n- Signal ID: \`${record.signalId}\`\n- Packet identity: \`${record.packetIdentity}\`\n\n${record.assessment.summary}\n\n`;
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
