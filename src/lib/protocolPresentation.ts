import type { DnsRecord, HttpRecord, ProtocolStat, TlsRecord } from '../types';

export interface ProtocolInventoryItem {
  id: string;
  label: string;
  recordCount: number;
  packetCount: number | null;
  byteCount: number | null;
  percentage: number | null;
  explanation: string;
}

export interface ProtocolFlag {
  id: string;
  type: 'DNS' | 'HTTP' | 'TLS';
  label: string;
  detail: string;
}

export function buildProtocolInventory(
  stats: readonly ProtocolStat[],
  dns: readonly DnsRecord[],
  http: readonly HttpRecord[],
  tls: readonly TlsRecord[],
): ProtocolInventoryItem[] {
  const inventory = stats.map((stat, index) => ({
    id: `stat:${stat.protocol}:${index}`,
    label: stat.protocol,
    recordCount: stat.count,
    packetCount: stat.count,
    byteCount: stat.byteCount,
    percentage: stat.percentage,
    explanation: stat.explanation,
  }));
  const labels = new Set(stats.map(stat => stat.protocol.toUpperCase()));
  const metadata = [
    { label: 'DNS', records: dns, explanation: 'Decoded DNS metadata records.' },
    { label: 'HTTP', records: http, explanation: 'Decoded HTTP metadata records.' },
    { label: 'TLS', records: tls, explanation: 'Decoded TLS metadata records.' },
  ];
  metadata.forEach(({ label, records, explanation }) => {
    if (!records.length || labels.has(label) || (label === 'TLS' && [...labels].some(value => value.startsWith('TLS')))) return;
    inventory.push({
      id: `metadata:${label}`,
      label,
      recordCount: records.length,
      packetCount: null,
      byteCount: null,
      percentage: null,
      explanation,
    });
  });
  return inventory;
}

export function buildProtocolFlags(
  dns: readonly DnsRecord[],
  http: readonly HttpRecord[],
  tls: readonly TlsRecord[],
): ProtocolFlag[] {
  const flags: ProtocolFlag[] = [];
  dns.forEach((record, index) => {
    if (record.riskLevel === 'info' && record.rcode === 'NOERROR') return;
    flags.push({
      id: record.id || `dns:${index}`,
      type: 'DNS',
      label: record.query || 'DNS record',
      detail: `Recorded RCODE ${record.rcode || 'not recorded'}; source risk label ${record.riskLevel}.`,
    });
  });
  http.forEach((record, index) => {
    if (record.riskLevel === 'info') return;
    flags.push({
      id: record.id || `http:${index}`,
      type: 'HTTP',
      label: `${record.method || 'Method not recorded'} ${record.host || 'host not recorded'}${record.uri || ''}`,
      detail: `Source risk label ${record.riskLevel}.`,
    });
  });
  tls.forEach((record, index) => {
    if (record.riskLevel === 'info') return;
    flags.push({
      id: record.id || `tls:${index}`,
      type: 'TLS',
      label: record.sni || 'SNI not recorded',
      detail: `Source risk label ${record.riskLevel}.`,
    });
  });
  return flags;
}
