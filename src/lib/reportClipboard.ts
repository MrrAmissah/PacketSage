export interface ClipboardWriter {
  writeText(value: string): Promise<void>;
}

export type ReportClipboardResult =
  | { ok: true; message: 'Markdown copied.' }
  | { ok: false; message: 'Could not copy Markdown. Clipboard access was denied.' };

export async function writeReportMarkdown(
  clipboard: ClipboardWriter | undefined,
  markdown: string,
): Promise<ReportClipboardResult> {
  try {
    if (!clipboard) throw new Error('Clipboard unavailable');
    await clipboard.writeText(markdown);
    return { ok: true, message: 'Markdown copied.' };
  } catch {
    return { ok: false, message: 'Could not copy Markdown. Clipboard access was denied.' };
  }
}
