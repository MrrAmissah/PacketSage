# PacketSage Judge Demonstration Flow

This is the shortest truthful path through the production workflow. The bundled dataset is generated defensive-analysis evidence containing routine and review-worthy activity; it does not establish compromise, malware, command and control, credential theft, or exfiltration.

## Judge path

1. Open **Import evidence** and choose **Load guided investigation sample**.
2. Use the compact guide to open **Signals & observations**. The generated sample has 40 chronological events, 34 flows, 19 DNS records, one HTTP record, two TLS records, and 13 deterministic signals.
3. Select **Repeated outbound connections**. Review its exact related flow and event IDs, then run **Evidence-grounded Investigation**.
4. Inspect the four labelled assessment sections and open an exact cited flow. Return to the signal and explicitly include the assessment in the report.
5. Optionally open **Capture Overview**. Its bounded whole-capture orientation is contextual, not observed evidence, and remains excluded until **Include overview as contextual note** is chosen.
6. Open **Report Builder**. Confirm deterministic findings, contextual overview, AI-assisted assessments, timeline, recommendations, and model provenance remain separate. Exercise Preview, Copy Markdown, and Print / PDF.
7. Replace or clear the evidence and confirm retained AI output and report inclusion state are removed.

## Processing boundaries to explain

- Raw PCAP/PCAPNG files use the bounded browser-side native decoder. Supported text exports use the serverless parsing endpoint.
- Investigation sends only one selected signal's bounded normalized evidence packet, never capture bytes, raw packet payloads, or packet `info` text.
- Capture Overview sends a bounded summary for orientation and has no PacketSage evidence citations.
- Neither model output is automatically included in a report, and neither changes deterministic findings.
- Active case state is volatile and clears on refresh or reset; PacketSage performs no active scanning or live capture.
