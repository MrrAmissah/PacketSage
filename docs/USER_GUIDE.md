# PacketSage User Guide

Welcome to the PacketSage Forensic Sandbox. This guide walks you through the core workflows of importing evidence, inspecting network protocols, validating suspicious signals, generating AI analyst drafts, and exporting professional incident reports.

---

## 1. Getting Started: Ingesting Evidence

When you first open PacketSage, the workspace is blank, awaiting network logs. You have three primary ways to load evidence:

```
+---------------------------------------------------------------------------------+
|                                 CHOOSE INGEST METHOD                            |
+---------------------------------------------------------------------------------+
|                                                                                 |
|  [ 1. LOAD SAMPLE DATASET ]   --> Immediate simulation of multi-stage intrusion  |
|                                                                                 |
|  [ 2. DRAG & DROP EXPORTS ]  --> Drop Wireshark CSVs, Suricata JSONs, Zeek TSVs  |
|                                                                                 |
|  [ 3. PASTE RAW LOG LINES ]  --> Copy & paste text snippets directly            |
|                                                                                 |
+---------------------------------------------------------------------------------+
```

### 1.1 Ingesting the Sample Dataset (Recommended for First-Time Users)
For training or product demonstration:
1. Navigate to the **Import Evidence** tab.
2. Under "Load sample network incident dataset", click **Load sample dataset**.
3. The platform will immediately hydrate the workspace with a simulated multi-stage intrusion profile (including reconnaissance scanning, credential leaks, and persistent external beaconing).

### 1.2 Importing Authorized Logs
To analyze your own captures:
1. Export your network logs as text-based summaries (e.g., File -> Export Packet Dissections -> As CSV in Wireshark; or gather your Zeek or Suricata logs).
2. Confirm you have full authorization to analyze this data.
3. Drag-and-drop the files onto the dashed import dropzone, or click **Browse Files** to select them manually.

### 1.3 Using Paste Mode
If you have a quick text snippet or log clip:
1. Click the **Paste Logs** button inside the import section.
2. Paste your structured logs into the text input area.
3. Select the closest log format type from the dropdown, then click **Parse In-Memory**.

---

## 2. Inspecting the Ingestion Metrics

Once loaded, navigate to the **Command Center** to review high-level characteristics of the session:
* **Evidence Metadata**: Reviews total packet volume, timeline coverage, and capture file properties.
* **Volume Over Time**: Displays an interactive chart illustrating throughput trends and communication density.
* **Protocol Distribution**: Breaks down TCP, UDP, and ICMP ratios.
* **Critical Indicators**: Instantly highlights plaintext exposure rates and top-severity signals needing immediate review.

---

## 3. Detailed Forensic Inquiries

PacketSage provides separate deep-dive panels to isolate anomalies:

### 3.1 Analyzing Conversations in Flow Explorer
Reconstruct TCP and UDP conversations to map endpoints:
1. Open the **Flow Explorer** tab.
2. Use the **Search bar** to filter by IP addresses or specific ports.
3. Filter conversations using the **Risk** column to isolate suspicious endpoints.
4. Click any row to expand the Flow Detail Drawer, detailing duration, packet sizing ratios, and linked protocol events.

### 3.2 Examining Protocol Intelligence
Investigate application-layer protocol metadata:
* **DNS Records**: Look for anomalous domains, high-frequency queries, or unusual lookup types (like TXT records commonly abused for data exfiltration).
* **HTTP Traffic**: Inspect plain-text requests. Look for anomalous paths, suspicious User-Agents, and exposure of sensitive credentials.
* **TLS Metadata**: Examine SNI strings and certificate versions. Compare handshake details without active decryption to identify anomalous tunneling behaviors.

### 3.3 Validating Findings in Signals & Observations
The deterministic rules engine flags potential threats automatically:
1. Go to the **Signals & Observations** tab.
2. Select any flagged anomaly (e.g., "Abnormal DNS Beaconing Detected").
3. Investigate the details and evidence references provided.
4. If verified, click **Validate**. If it is standard traffic, click **Dismiss**.
5. Your verification state will synchronize with the **Report Builder** immediately.

---

## 4. Generating the AI Analyst Memo

To draft an executive summary of the incident:
1. Open the **AI Analyst Memo** tab.
2. Review the **Evidence Scope Sidebar** on the right to verify the exact telemetry metrics that will be compiled.
3. Click **Synthesize Narrative Memo**.
4. The server-side proxy will consult Gemini using redaction controls to draft:
   * An **Executive Analogy** translating complex network behaviors into simple, relatable scenarios.
   * A chronological **Reconstructed Timeline** detailing threat phases.
   * **Defensive Recommendations** listing practical containment steps.

---

## 5. Compiling and Exporting the Final Report

Assemble your investigation findings for stakeholders:
1. Navigate to the **Report Builder** tab.
2. Fill in the **Investigator Name** and confirm the **Incident Scope/Target**.
3. Enter your independent observations under **Analyst Validation Notes**.
4. Review the **Report Readiness panel** on the right side. Ensure key items are resolved to boost the readiness meter.
5. Under the Report Document editor, toggle optional sections (e.g., Recommendations, Technical Limitations).
6. Click **Print / Export PDF** in the top right. A print-optimized overlay will open, allowing you to save a clean, professional, styled paper or PDF record.

---

## 6. Ending Your Session

PacketSage keeps active evidence in the application session:
* **Clearing Workspace**: Click **Clear Data** or reload the page to clear active evidence and generated analysis from the workspace.
* **Local Preferences**: Some review-status preferences may remain in browser storage. Raw captures are decoded locally; supported text exports are sent to the parsing endpoint.
