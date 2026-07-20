import type { SuspiciousSignal } from '../types';

export function selectPresentedSignals(signals: SuspiciousSignal[]): SuspiciousSignal[] {
  return signals.map(signal => ({ ...signal }));
}
