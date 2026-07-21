# PacketSage User Guide

Welcome to the PacketSage Forensic Sandbox. This guide covers importing evidence, inspecting protocols, reviewing deterministic signals, running evidence-grounded investigation, optionally generating contextual orientation, and exporting a report draft.

---

## 1. Getting Started: Ingesting Evidence

When you first open PacketSage, the workspace is blank, awaiting network logs. You have three primary ways to load evidence:

```
+---------------------------------------------------------------------------------+
|                                 CHOOSE INGEST METHOD                            |
+---------------------------------------------------------------------------------+
|                                                                                 |
|  [ 1. LOAD GUIDED SAMPLE ]   --> Generated routine and review-worthy activity   |
|                                                                                 |
|  [ 2. DRAG & DROP EXPORTS ]  --> Drop Wireshark CSVs, Suricata JSONs, Zeek TSVs  |
|                                                                                 |
|  [ 3. PASTE STRICT EVENTS ]  --> One explicit structured event per line         |
|                                                                                 |
+---------------------------------------------------------------------------------+
```

### 1.1 Ingesting the Sample Dataset (Recommended for First-Time Users)
For training or product demonstration:
1. Navigate to the **Import Evidence** tab.
2. Under "Guided defensive-analysis sample", click **Load guided investigation sample**.
3. Follow the compact four-stage guide. The generated dataset contains routine and review-worthy metadata and does not establish an attack or compromise.

### 1.2 Importing Authorized Logs
To analyze your own captures:
1. Use a supported raw PCAP/PCAPNG capture or export structured CSV, JSON, Zeek, Suricata, or TShark evidence.
2. Confirm you have full authorization to analyze this data.
3. Drag-and-drop the files onto the dashed import dropzone, or click **Browse Files** to select them manually.

### 1.3 Using Paste Mode
If you have a quick text snippet or log clip:
1. Confirm authorization and focus the paste field.
2. Enter one event per line using `YYYY-MM-DDTHH:mm:ssZ SRC_IP -> DST_IP [src_port=N] dst_port=N protocol=TCP|UDP length=N`.
3. Timestamp, valid IPv4 endpoints, destination port, protocol, and length are required. Ports accept `0`–`65535`; an explicitly supplied `0` displays as observed port `0`, while an omitted source port displays as `unknown`.
4. Click **Submit pasted logs**. Incomplete, arbitrary, or malformed lines return a line-specific error and produce no partial evidence.

---

## 2. Inspecting the Ingestion Metrics

Once loaded, navigate to the **Command Center** to review high-level characteristics of the session:
* **Evidence Metadata**: Reviews total packet volume, timeline coverage, and capture file properties.
* **Observed Totals**: Displays normalized event, flow, endpoint, byte, signal, and reviewed-finding counts.
* **Protocol Statistics**: Lists only protocols and metadata records present in the loaded evidence.
* **Available Actions**: Offers next steps only for flows, signals, protocol records, or timeline events that actually exist.

---

## 3. Detailed Forensic Inquiries

PacketSage provides separate deep-dive panels to isolate anomalies:

### 3.1 Analyzing Conversations in Flow Explorer
Reconstruct TCP and UDP conversations to map endpoints:
1. Open the **Flow Explorer** tab.
2. Use the **Search bar** to filter by IP addresses or specific ports.
3. Filter conversations using the **Risk** column to isolate suspicious endpoints.
4. Open any row to inspect recorded endpoints, interval, counts, and only those events/signals connected by exact IDs. The drawer does not infer host aliases, encryption, or TCP state.

### 3.2 Examining Protocol Intelligence
Investigate application-layer protocol metadata:
* **DNS Records**: Review only decoded query, type, response, RCODE, client, and timestamp fields.
* **HTTP Traffic**: Review only decoded client, host, method, URI, status, and timestamp fields.
* **TLS Metadata**: Review only decoded client/server, SNI, version, fingerprint, and timestamp fields. Missing values appear as not recorded.

### 3.3 Validating Findings in Signals & Observations
The deterministic rules engine flags potential threats automatically:
1. Go to the **Signals & Observations** tab.
2. Select any flagged anomaly (e.g., "Abnormal DNS Beaconing Detected").
3. Investigate the details and evidence references provided.
4. If independently reviewed, click **Add finding to report**. If it is standard traffic, click **Dismiss noise**.
5. Your verification state will synchronize with the **Report Builder** immediately.

---

## 4. Running an AI-Assisted Investigation

1. Open **Signals & observations** and select a signal with exact related evidence.
2. Click **Investigate with AI** and review the four labelled assessment sections.
3. Verify exact evidence-ID citations and treat analyst inference as unconfirmed.
4. Click **Add AI-assisted assessment to report** only when the current assessment belongs in the draft.

---

## 5. Compiling and Exporting the Final Report

### Optional Capture Overview

Open **Capture Overview** to generate broad orientation from a bounded summary of the current capture. The overview is not observed evidence, has no evidence citations, and remains separate from the Evidence-grounded Investigation. Open **Technical details** to inspect provider, model, schema, and generation provenance. Use **Include overview as contextual note** only when that non-evidence-linked context belongs in the draft; changing or clearing evidence removes the prior overview.

Assemble your investigation findings for stakeholders:
1. Navigate to the **Report Builder** tab.
2. Confirm reviewed deterministic findings and explicitly included assessments are listed separately.
3. Check the contextual-overview inclusion state; it remains optional and is not evidence-linked.
4. Review the **Report readiness** status and exact evidence IDs.
5. Use **Preview**, **Copy Markdown**, or **Print / PDF**. Preview is a keyboard-contained dialog. Print/PDF hides the application shell and paginates the complete bounded report, including late timeline/provenance/limitations sections.

---

## 6. Understanding the Architecture

Open **Architecture spec** at any time, including before loading evidence, to inspect PacketSage’s current browser and server boundaries. The view documents the implemented evidence-to-report pipeline, enforced capture, parsing, investigation and reporting limits, completed delivery stages, trust controls, and capabilities that remain explicitly deferred. Provider and model details appear as technical architecture rather than primary workflow labels.

---

## 7. Ending Your Session

PacketSage keeps active evidence in the application session:
* **Clearing Workspace**: Click **Clear Data** or reload the page to clear active evidence and generated analysis from the workspace.
* **Local Preferences**: Theme preference may remain in browser storage. Active evidence, flow/event selection, generated AI results, and report inclusion state clear with evidence replacement/reset. Raw captures are decoded locally; supported text exports are sent to the parsing endpoint.
