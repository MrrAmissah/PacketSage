import type { ParsedResult } from './parser';
import type { PacketEvent } from '../types';

export function commandCenterLimitation(parseMode: ParsedResult['evidence']['parseMode']): string {
  if (parseMode === 'demo') return 'Generated sample records are provided for demonstration and do not represent a real incident.';
  if (parseMode === 'pcap') return 'PCAP/PCAPNG output is limited to metadata supported by the bounded browser decoder; payload content is not interpreted here.';
  if (parseMode === 'txt') return 'Pasted text accepts only the documented strict grammar; a source port omitted from an accepted record remains unknown.';
  return 'Displayed fields are limited to metadata present in the supported imported export format.';
}

export function observedEventDescription(event: PacketEvent): string {
  return event.info.trim() || `${event.protocol} record from ${event.sourceIp} to ${event.destinationIp}`;
}

export type CommandCenterDestination = 'signals' | 'flows' | 'protocols' | 'timeline' | 'import';

export function commandCenterNextActions(data: ParsedResult): Array<{ destination: CommandCenterDestination; label: string }> {
  const actions: Array<{ destination: CommandCenterDestination; label: string }> = [];
  if (data.signals.length) actions.push({ destination: 'signals', label: 'Review observed signals' });
  if (data.flows.length) actions.push({ destination: 'flows', label: 'Inspect decoded flows' });
  if (data.dns.length || data.http.length || data.tls.length || data.protocolStats.length) actions.push({ destination: 'protocols', label: 'Review protocol metadata' });
  if (data.events.length) actions.push({ destination: 'timeline', label: 'Review the observed timeline' });
  if (!actions.length) actions.push({ destination: 'import', label: 'Import evidence with supported records' });
  return actions;
}

export function recordedHostnames(data: Pick<ParsedResult, 'dns' | 'http' | 'tls'>): string[] {
  const unsupportedPlaceholders = new Set(['', 'unknown', 'encrypted', 'host', 'domain', 'query.domain']);
  return Array.from(new Set([
    ...data.dns.map(record => record.query),
    ...data.http.map(record => record.host),
    ...data.tls.map(record => record.sni),
  ].filter(value => !unsupportedPlaceholders.has(value.trim().toLowerCase()))));
}
