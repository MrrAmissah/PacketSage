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

export function recordedHostnames(data: Pick<ParsedResult, 'dns' | 'http' | 'tls'>): string[] {
  const unsupportedPlaceholders = new Set(['', 'unknown', 'encrypted', 'host', 'domain', 'query.domain']);
  return Array.from(new Set([
    ...data.dns.map(record => record.query),
    ...data.http.map(record => record.host),
    ...data.tls.map(record => record.sni),
  ].filter(value => !unsupportedPlaceholders.has(value.trim().toLowerCase()))));
}
