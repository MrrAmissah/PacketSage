# PacketSage Public Demonstration Guide

This guide outlines a polished, end-to-end demonstration script and conversational talk track for presenting PacketSage to peers, instructors, or security stakeholders.

---

## Demo Structure Overview

| Step | Action | Core Screen | Focus Message |
| :--- | :--- | :--- | :--- |
| **1** | Open application | Ingest Panel | Blank slate workspace, privacy-first warning |
| **2** | Load Sample Dataset | Command Center | Instant decoding, multi-protocol dashboard |
| **3** | Flow Analysis | Flow Explorer | Interactive TCP/UDP reconstruction |
| **4** | Protocol Drilldown | Protocol Intel | DNS lookups, HTTP headers, TLS SNI metadata |
| **5** | Validate Signals | Signals & Obs | Deterministic rules engine & analyst interaction |
| **6** | Synthesize Memo | AI Analyst | Server-side proxy and evidence-bound narrative |
| **7** | Timeline & Report | Report Builder | Validation notes, readiness score, PDF print export |
| **8** | Future Roadmap | Architecture Spec | Sandbox boundaries & planned decoder workers |

---

## Step-by-Step Script & Talk Track

### Step 1: The Ephemeral Landing
* **Setup**: Ensure the application state is empty (reload if necessary) and display the **Import Evidence** panel.
* **Action**: Highlight the authorized-use notice and file dropzone.
* **Suggested Talk Track**:
  > *"We begin PacketSage as a blank slate. PacketSage is designed as a browser-side defensive workspace for analyzing network captures, log exports, and traffic telemetry. Notice the persistent warning here: PacketSage is built for defensive verification only. In sandbox mode, all parsing occurs in-memory, ensuring raw datasets are parsed ephemerally on the fly."*

### Step 2: Ingestion & In-Memory Hydration
* **Action**: Click the **Load sample dataset** button under the "Load sample network incident dataset" section. Once loaded, transition to the **Command Center**.
* **Suggested Talk Track**:
  > *"By clicking 'Load sample dataset', we immediately populate the in-memory workbench with a simulated multi-stage network compromise. In the Command Center, we get an instant, birds-eye view of the session: packet volume ratios, throughput curves, protocol breakdowns, and security alerts. Notice that the UI has adapted to the custom 'Cool Trust' design system, prioritizing typography, legibility, and information hierarchy without decorative distractions."*

### Step 3: Flow Reconstruction
* **Action**: Navigate to the **Flow Explorer** tab. Type `10.0.2.15` or a similar IP into the Search box, and expand the row of a flow with elevated risk (e.g., highlighting data volume or port anomaly).
* **Suggested Talk Track**:
  > *"Let's drill down into individual conversations. In the Flow Explorer, PacketSage acts as an interactive session-reconstitution grid. Unlike static raw text streams, we can search for specific host IPs, inspect port relationships, and review exact byte counts. If we expand a suspicious connection, we instantly see packet directionality, flow durations, and linked protocol events."*

### Step 4: Protocol Intelligence Deep-Dive
* **Action**: Navigate to the **Protocol Intelligence** tab. Click through the **DNS**, **HTTP**, and **TLS** sub-tabs, pointing out plain-text fields and certificate names.
* **Suggested Talk Track**:
  > *"Next, we look at application-layer protocol behaviors. In Protocol Intelligence, we separate traffic into distinct investigative rails. On the DNS tab, we can monitor query structures and domain resolutions. On the HTTP tab, we easily identify unencrypted HTTP requests, which represent immediate data exposure. Under TLS, we can capture handshake certificates and SNI domains, allowing us to inspect encrypted sessions without active decryption."*

### Step 5: Heuristics & Analyst Verification
* **Action**: Navigate to the **Signals & Observations** tab. Find an active indicator (such as "Plaintext Password In Transit" or "Abnormal DNS Beaconing Detected") and click **Validate** on one and **Dismiss** on another.
* **Suggested Talk Track**:
  > *"The platform includes a deterministic browser-side rules engine that matches flow behaviors against common defensive markers. Instead of presenting AI-generated guesses as facts, PacketSage relies on predictable rules first. As an analyst, I can inspect each signal's evidence and mark it as 'Validated' or 'Dismissed' to commit my decisions to the final report."*

### Step 6: Server-Side AI Interpretation
* **Action**: Go to the **AI Analyst Memo** tab and click **Synthesize Narrative Memo**. Point out the **Evidence Scope Sidebar** on the right as it finishes.
* **Suggested Talk Track**:
  > *"With our observations completed, we now generate an executive analysis. In the AI Analyst Memo tab, we call our server-side Gemini API proxy. Observe the Evidence Scope sidebar on the right: it strictly bounds Gemini to the ingested logs, preventing hallucinations. The model produces a readable summary, an executive analogy that explains complex technical anomalies in human terms, and explicit, defense-oriented containing steps."*

### Step 7: Incident Timeline and Report Generation
* **Action**: Open the **Incident Timeline** tab to display the chronological sequence of events. Then transition to the **Report Builder** tab. Enter your name in the investigator input, write some brief notes in the Analyst Notes field, toggle a section, and highlight the **Report Readiness** meter before clicking **Print / Export PDF**.
* **Suggested Talk Track**:
  > *"Before writing our report, we review the Incident Timeline to inspect chronological flow patterns. Then, inside the Report Builder, we compile our findings. The Report Readiness score evaluates our work—tracking evidence completeness, validator notes, and investigator names. When ready, clicking 'Print/Export' opens a clean, printer-friendly CSS stylesheet, stripping away navigation panels and rendering a formal PDF report ready for stakeholders."*

### Step 8: Architecture Spec & Wrap-up
* **Action**: Open the **Architecture Spec** tab. Scroll down to show the Stage 1 (Current Sandbox) versus Stage 2 (Planned Production Ingress microservices) comparison block.
* **Suggested Talk Track**:
  > *"Finally, we end in the Architecture Spec. We want to be completely honest about PacketSage's current limits. In Stage 1, we are running entirely in a volatile, local browser sandbox using text-based adapters. The roadmap details our planned Stage 2, which relocates parsing to distributed, sandboxed container services running native PCAP utilities like tshark and zeek. This ensures a transparent, highly professional security model for enterprise growth."*
