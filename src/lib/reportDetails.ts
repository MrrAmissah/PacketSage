export const REPORT_DETAILS_SCHEMA_VERSION = '1' as const;

export interface ReportDetails {
  investigator: string;
  roleOrUnit: string;
  organization: string;
  caseReferenceId: string;
  scopeNotes: string;
}

export interface ReportDetailsRecord {
  schemaVersion: typeof REPORT_DETAILS_SCHEMA_VERSION;
  evidenceIdentity: string;
  details: ReportDetails;
}

export const EMPTY_REPORT_DETAILS: Readonly<ReportDetails> = Object.freeze({
  investigator: '',
  roleOrUnit: '',
  organization: '',
  caseReferenceId: '',
  scopeNotes: '',
});

const FIELD_LIMITS: Record<keyof ReportDetails, number> = {
  investigator: 160,
  roleOrUnit: 160,
  organization: 160,
  caseReferenceId: 160,
  scopeNotes: 2_000,
};

function boundedUserValue(value: unknown, maxLength: number): string {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

export function normalizeReportDetails(input: Partial<ReportDetails>): ReportDetails {
  return {
    investigator: boundedUserValue(input.investigator, FIELD_LIMITS.investigator),
    roleOrUnit: boundedUserValue(input.roleOrUnit, FIELD_LIMITS.roleOrUnit),
    organization: boundedUserValue(input.organization, FIELD_LIMITS.organization),
    caseReferenceId: boundedUserValue(input.caseReferenceId, FIELD_LIMITS.caseReferenceId),
    scopeNotes: boundedUserValue(input.scopeNotes, FIELD_LIMITS.scopeNotes),
  };
}

export function createReportDetailsSession(
  evidenceIdentity: string,
  details: Partial<ReportDetails> = {},
): ReportDetailsRecord {
  return {
    schemaVersion: REPORT_DETAILS_SCHEMA_VERSION,
    evidenceIdentity,
    details: normalizeReportDetails(details),
  };
}

export function reportDetailsForEvidence(
  record: ReportDetailsRecord | null | undefined,
  evidenceIdentity: string,
): ReportDetailsRecord {
  if (record?.schemaVersion === REPORT_DETAILS_SCHEMA_VERSION && record.evidenceIdentity === evidenceIdentity) {
    return createReportDetailsSession(evidenceIdentity, record.details);
  }
  return createReportDetailsSession(evidenceIdentity);
}

export function reportIdentityIncomplete(details: ReportDetails): boolean {
  return !details.investigator || !details.caseReferenceId;
}
