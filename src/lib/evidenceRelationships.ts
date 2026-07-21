import type { FlowSummary, PacketEvent, SuspiciousSignal } from '../types';

function orderedUnique<T extends { id: string }>(items: readonly T[]): T[] {
  const seen = new Set<string>();
  return items.filter(item => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
}

/** Resolve only parser-established event IDs recorded on the flow. */
export function eventsForFlow(
  flow: FlowSummary,
  events: readonly PacketEvent[],
): PacketEvent[] {
  const eventMap = new Map(events.map(event => [event.id, event]));
  return orderedUnique((flow.relatedEvents || []).flatMap(id => {
    const event = eventMap.get(id);
    return event ? [event] : [];
  }));
}

/** Resolve only signal relationships that explicitly name the flow ID. */
export function signalsForFlow(
  flowId: string,
  signals: readonly SuspiciousSignal[],
): SuspiciousSignal[] {
  return signals.filter(signal => signal.relatedFlowIds?.includes(flowId));
}

/** Resolve only flow relationships that explicitly name the event ID. */
export function flowsForEvent(
  eventId: string,
  flows: readonly FlowSummary[],
): FlowSummary[] {
  return flows.filter(flow => flow.relatedEvents?.includes(eventId));
}

/** Resolve only signal relationships that explicitly name the event ID. */
export function signalsForEvent(
  eventId: string,
  signals: readonly SuspiciousSignal[],
): SuspiciousSignal[] {
  return signals.filter(signal => signal.relatedEventIds?.includes(eventId));
}

/** Full observed identity comparison for callers that already have two records. */
export function hasSameObservedFlowIdentity(event: PacketEvent, flow: FlowSummary): boolean {
  const forward = event.sourceIp === flow.sourceIp
    && event.sourcePort === flow.sourcePort
    && event.sourcePortState === flow.sourcePortState
    && event.destinationIp === flow.destinationIp
    && event.destinationPort === flow.destinationPort
    && event.destinationPortState === flow.destinationPortState;
  const reverse = event.sourceIp === flow.destinationIp
    && event.sourcePort === flow.destinationPort
    && event.sourcePortState === flow.destinationPortState
    && event.destinationIp === flow.sourceIp
    && event.destinationPort === flow.sourcePort
    && event.destinationPortState === flow.sourcePortState;
  return event.protocol === flow.protocol && (forward || reverse);
}
