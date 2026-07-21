import type { PortState } from '../types.js';

const PORTLESS_PROTOCOLS = /^(?:ICMP(?:V6)?|IP|IP-\d+|IPV[46] FRAGMENT)$/i;

export function isPortlessProtocol(protocol: string): boolean {
  return PORTLESS_PROTOCOLS.test(protocol.trim());
}

export function portStateFor(protocol: string, explicitlySupplied: boolean): PortState {
  if (isPortlessProtocol(protocol)) return 'not-applicable';
  return explicitlySupplied ? 'observed' : 'unknown';
}

export function formatEndpoint(ip: string, port: number, state: PortState): string {
  if (state === 'not-applicable') return ip;
  const address = ip.includes(':') ? `[${ip}]` : ip;
  if (state === 'unknown') return `${address}:unknown`;
  return `${address}:${port}`;
}

/**
 * Preserve established identities for ordinary observed non-zero ports while
 * distinguishing every formerly ambiguous zero-valued state.
 */
export function portIdentityPart(port: number, state: PortState): number | string {
  return state === 'observed' && port !== 0 ? port : `${state}:${port}`;
}

export function portFlowKey(port: number, state: PortState): string {
  return String(portIdentityPart(port, state));
}
