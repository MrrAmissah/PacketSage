export interface InvestigationRequestContext {
  signalId: string;
  packetIdentity: string;
}

export interface InvestigationRequestToken extends InvestigationRequestContext {
  requestId: number;
  controller: AbortController;
}

export class InvestigationRequestCoordinator {
  private nextRequestId = 0;
  private activeRequest: InvestigationRequestToken | null = null;

  begin(context: InvestigationRequestContext): InvestigationRequestToken | null {
    if (
      this.activeRequest
      && this.activeRequest.signalId === context.signalId
      && this.activeRequest.packetIdentity === context.packetIdentity
    ) {
      return null;
    }

    this.invalidate();
    const token: InvestigationRequestToken = {
      ...context,
      requestId: ++this.nextRequestId,
      controller: new AbortController(),
    };
    this.activeRequest = token;
    return token;
  }

  invalidate(): void {
    this.activeRequest?.controller.abort();
    this.activeRequest = null;
  }

  settle(token: InvestigationRequestToken, current: InvestigationRequestContext | null): boolean {
    if (
      !current
      || this.activeRequest?.requestId !== token.requestId
      || this.activeRequest.signalId !== token.signalId
      || this.activeRequest.packetIdentity !== token.packetIdentity
      || current.signalId !== token.signalId
      || current.packetIdentity !== token.packetIdentity
    ) {
      return false;
    }

    this.activeRequest = null;
    return true;
  }
}

export function isInvestigationAbort(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

export type InvestigationRequestOutcome<T> =
  | { status: 'success'; value: T }
  | { status: 'failure'; error: unknown }
  | { status: 'ignored' };

export async function runInvestigationRequest<T>(
  coordinator: InvestigationRequestCoordinator,
  token: InvestigationRequestToken,
  currentContext: () => InvestigationRequestContext | null,
  work: () => Promise<T>,
): Promise<InvestigationRequestOutcome<T>> {
  try {
    const value = await work();
    return coordinator.settle(token, currentContext())
      ? { status: 'success', value }
      : { status: 'ignored' };
  } catch (error) {
    if (isInvestigationAbort(error) || !coordinator.settle(token, currentContext())) {
      return { status: 'ignored' };
    }
    return { status: 'failure', error };
  }
}
