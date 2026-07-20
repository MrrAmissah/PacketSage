import type { FlowSummary } from '../types.js';

export function resolveRelatedFlows(
  relatedFlowIds: readonly string[] | undefined,
  flows: readonly FlowSummary[],
): FlowSummary[] {
  if (!relatedFlowIds?.length || flows.length === 0) return [];

  const flowsById = new Map(flows.map(flow => [flow.id, flow]));
  const seen = new Set<string>();
  const relatedFlows: FlowSummary[] = [];

  relatedFlowIds.forEach(id => {
    if (seen.has(id)) return;
    seen.add(id);
    const flow = flowsById.get(id);
    if (flow) relatedFlows.push(flow);
  });

  return relatedFlows;
}
