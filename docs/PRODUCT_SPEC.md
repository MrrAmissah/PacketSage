# PacketSage Product Specification

PacketSage is a defensive network forensics workspace and browser-side sandbox designed to support analysts, junior incident responders, security students, and SOC operators. It provides a structured environment for reviewing network capture exports, inspecting decoded flow telemetry, and correlating observed protocols, all backed by an evidence-bound, AI-assisted analysis workflow.

---

## 1. Product Overview & Core Positioning

PacketSage acts as a lightweight, interactive workstation that simplifies network log investigation and evidence correlation. By importing text-based packet logs, Wireshark CSVs, Suricata EVE logs, or Zeek summaries, users can reconstruct communications, isolate high-risk anomalies, and draft comprehensive investigation reports.

### Honest Positioning Boundaries
To ensure professional integrity and avoid overclaiming, PacketSage is defined by the following boundaries:
* **Defensive Analyst Workspace**: PacketSage is designed for defensive posture review and instructional forensics. It is **not** an active malware detector or breach containment system.
* **Instructional Sandbox**: It functions as a browser-side sandbox where all session telemetry and parsing happen in-memory. It is **not** a court-ready forensic evidence vault.
* **Evidence-Bound Assistant**: The AI-assisted memo generator is strictly constrained to the ingested dataset. It acts as a drafting helper and **does not** replace human validation, final judgment, or active incident scoping.
* **Planned Production Decoder**: In sandbox mode, parsing is conducted using structured text imports (such as Wireshark CSVs and parsed summaries). Full native binary `.pcap`/`.pcapng` decoding is a planned enterprise target and is clearly indicated as a future architectural extension.

---

## 2. Target Users

1. **Security Operations Center (SOC) Analysts**: Junior-to-mid level analysts seeking to quickly reconstruct conversation flows, analyze suspicious beaconing intervals, and draft incident narratives.
2. **Incident Responders & Forensic Students**: Security practitioners looking for a visual sandbox workspace to study protocol behavior, master network path reconstruction, and practice evidence-bound documentation.
3. **Security Educators**: Instructors who want a visual, zero-install, risk-free environment to teach network flow inspection, DNS/HTTP/TLS analysis, and structured report preparation.

---

## 3. Core Workflow

```
+------------------+     +-------------------+     +------------------+     +------------------+     +------------------+
| 1. IMPORT        | --> | 2. DECODE         | --> | 3. INSPECT       | --> | 4. EXPLAIN       | --> | 5. REPORT        |
| Load built-in    |     | Extract flows,    |     | Filter by risk,  |     | Generate         |     | Consolidate memo |
| sample or import |     | protocols, DNS &  |     | drill down on    |     | evidence-bound   |     | with validation  |
| authorized logs  |     | suspicious rules  |     | packets & hosts  |     | AI narrative     |     | notes & metadata |
+------------------+     +-------------------+     +------------------+     +------------------+     +------------------+
```

1. **Import**: The user loads authorized network evidence via drag-and-drop or pasting logs. For exploration or education, the built-in, pre-loaded sample dataset is available immediately.
2. **Decode**: Deterministic browser-side adapters parse and normalize the ingested text format (CSV, Suricata JSON, Zeek TSV, or TShark dumps) into a standard in-memory metadata schema.
3. **Inspect**: The analyst uses interactive views (Command Center, Flow Explorer, Protocol Intelligence, Suspicious Signals, and Incident Timeline) to examine anomalous connections, search specific host strings, and validate heuristic triggers.
4. **Investigate**: The analyst runs a bounded GPT-5.6 assessment for one signal and reviews observations, inference, uncertainty, next steps, and exact citations.
5. **Report**: The analyst explicitly includes selected validated assessments and reviewed findings, then previews or exports the evidence-grounded draft.

---

## 4. Main Product Modules

### 4.1 Command Center
The home dashboard and operations console of PacketSage. It gives an executive summary of the imported capture session, listing packet totals, active timeline ranges, protocol distributions (TCP, UDP, ICMP), cleartext exposure rates, and quick access to top-severity signals.

### 4.2 Import Evidence
A versatile ingestion panel allowing analysts to either load pre-packaged educational scenarios or import their own authorized logs. Supports drag-and-drop file ingestion, file-dialog selection, or direct copy-paste text buffers.

### 4.3 Flow Explorer
An interactive grid reconstructing TCP and UDP sessions. Analysts can inspect endpoint conversations, calculate exact bytes transferred, query specific IPs, filter by port numbers, and drill down on localized packet sequences.

### 4.4 Protocol Intelligence
A dedicated deep-dive inspector separating key web and network services:
* **DNS Log**: Captures records, lookup types (A, AAAA, TXT, MX), query domains, and responses.
* **HTTP Traffic**: Inspects plaintext requests, URIs, user agents, response codes, and payload references.
* **TLS Metadata**: Extracts Server Name Indications (SNI), TLS versions, and handshake details to study encrypted sessions without active decryption.

### 4.5 Signals & Observations
A deterministic rule engine that surfaces suspicious activity based on observed heuristics. Triggers include unusual port maps, high-density inbound scanning, abnormal beaconing intervals, and plaintext credential transmission. Analysts can mark these findings as "Validated" or "Dismissed" to synchronize with the Report Builder.

### 4.6 AI-Assisted Investigation
Invokes GPT-5.6 for one selected signal using only its bounded evidence packet. Structured observations, inference, uncertainty, next steps, and citations are validated before display.

### 4.7 Capture Overview
Optionally invokes Google Gemini with a bounded whole-capture summary for orientation, traffic-pattern explanation, learning perspectives, and triage questions. This capability is separate from Evidence-grounded Investigation: it cannot create findings, is never observed evidence, has no PacketSage evidence citations, and enters the report only through explicit contextual-note inclusion.

### 4.7 Incident Timeline
A clean, chronological timeline of reconstructed network events based on decoded packet timestamps. Features intuitive severity filtering, quick detail modals, and helps isolate the initial vector from subsequent lateral movements.

### 4.8 Report Builder
A structured document compiler that dynamically tracks report completeness. Computes a "Report Readiness Score" based on:
1. Investigator Name specification.
2. Ingested Evidence volume.
3. Explicitly included investigation assessments.
4. Scope/Target validation.
5. Analyst Validation Notes completion.
6. Optional section toggles (Limitations, Recommendations).
Features a print-optimized CSS layout for high-quality PDF exports.

### 4.9 Packet Academy
An instructional training suite containing guided multiple-choice challenges based on simulated capture profiles. It is designed to evaluate and sharpen defensive packet-analysis, reasoning, and evidence verification skills.

### 4.10 Architecture Spec
A transparent, visual system roadmap depicting the current sandbox workstation versus the planned production architecture. It defines system operating modes, data pipelines, and security controls, clarifying current browser limits.

---

## 5. Capabilities & Limitations

### Current Sandbox Capabilities
* **Interactive Visual Sandbox**: Clean, highly-polished interface utilizing the *Cool Trust* design language.
* **Deterministic Parsing**: Instant, local, in-memory structured parsing of normalized exports (CSV, TSV, JSON, raw logs).
* **Deterministic Rules**: Local rule matching for scan detection, cleartext warnings, and beaconing.
* **Security Redaction**: Local filters to replace raw authorization tokens and cleartext keys with redacted placeholders in the UI.
* **Interactive Education**: Built-in Academy with dynamic scoring and reasoning.

### Explicit Limitations
* **No Active Scanner**: PacketSage is a passive review workspace. It does **not** scan, probe, or run active network checks.
* **No Raw PCAP Storage**: Raw binary `.pcap`/`.pcapng` file ingestion is not handled in browser sandbox mode. File uploads are met with a friendly alert explaining the planned production ingestion architecture.
* **No Persistent Backend Database**: Data is held entirely in transient React and Express memory and is lost on page reload. Case management and user accounts are deferred to future production milestones.
* **AI-Assisted Assessment Only**: Model inference remains labelled and unconfirmed; inclusion in a report does not replace independent human verification.
