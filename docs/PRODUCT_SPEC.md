# PacketSage Product Specification

PacketSage is a defensive network forensics workspace and browser-side sandbox designed to support analysts, junior incident responders, security students, and SOC operators. It provides a structured environment for reviewing network capture exports, inspecting decoded flow telemetry, and correlating observed protocols, all backed by an evidence-bound, AI-assisted analysis workflow.

---

## 1. Product Overview & Core Positioning

PacketSage is a lightweight, interactive workstation for bounded network-evidence investigation and correlation. It accepts raw PCAP/PCAPNG captures and supported CSV, Suricata, Zeek, TShark, and text evidence.

### Honest Positioning Boundaries
To ensure professional integrity and avoid overclaiming, PacketSage is defined by the following boundaries:
* **Defensive Analyst Workspace**: PacketSage is designed for defensive posture review and instructional forensics. It is **not** an active malware detector or breach containment system.
* **Instructional Sandbox**: Active evidence and generated results live in volatile application state. Raw captures are decoded in bounded browser memory; supported text evidence uses the serverless parser. It is **not** a court-ready forensic evidence vault.
* **Evidence-Grounded Investigation**: One selected signal and its exact bounded relationships may be assessed. Model inference remains separate from observed evidence and requires explicit report inclusion.
* **Bounded Native Decoder**: `.pcap`/`.pcapng` decoding is implemented for supported link, network, transport, and basic DNS metadata. Unsupported or malformed input fails without synthetic evidence.

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
| Load generated  |     | Extract flows,    |     | Filter by risk,  |     | Request bounded  |     | Build explicit   |
| sample or import |     | protocols, DNS &  |     | drill down on    |     | evidence-bound   |     | with validation  |
| authorized logs  |     | suspicious rules  |     | packets & hosts  |     | AI narrative     |     | notes & metadata |
+------------------+     +-------------------+     +------------------+     +------------------+     +------------------+
```

1. **Import**: The user loads authorized network evidence via drag-and-drop or pasting logs. For exploration or education, the built-in, pre-loaded sample dataset is available immediately.
2. **Decode**: The bounded browser decoder handles supported PCAP/PCAPNG metadata; deterministic adapters normalize CSV, Suricata JSON, Zeek TSV, TShark JSON, and text evidence.
3. **Inspect**: The analyst uses Command Center, Flow Explorer, Protocol Intelligence, Signals & Observations, and Incident Timeline. Displayed facts come from normalized records; cross-view navigation requires exact parser-established IDs.
4. **Investigate**: The analyst runs a bounded GPT-5.6 assessment for one signal and reviews observations, inference, uncertainty, next steps, and exact citations.
5. **Report**: The analyst explicitly includes selected validated assessments and reviewed findings, then previews or exports the evidence-grounded draft.

---

## 4. Main Product Modules

### 4.1 Command Center
The home operations console lists only loaded evidence totals, present protocol statistics, deterministic signals, observed timeline records, evidence-backed hostnames, and next actions supported by the current dataset. Empty custom evidence does not inherit generated-sample claims.

### 4.2 Import Evidence
A versatile ingestion panel allowing analysts to load the generated educational scenario or import authorized evidence. Pasted events use the strict grammar `YYYY-MM-DDTHH:mm:ssZ SRC_IP -> DST_IP [src_port=N] dst_port=N protocol=TCP|UDP length=N`; ports accept `0`–`65535`, explicit zero remains observed, omitted source ports remain unknown, and ambiguous or malformed lines fail without partial evidence.

### 4.3 Flow Explorer
An interactive grid of normalized flow summaries. Analysts can filter observed endpoint, port, protocol, direction, risk, time, packet, and byte fields. Events resolve only through `flow.relatedEvents`; signals resolve only through exact `relatedFlowIds`. No host alias, connection state, or encryption result is inferred.

### 4.4 Protocol Intelligence
A dedicated deep-dive inspector separating key web and network services:
* **DNS Log**: Displays fields present in decoded DNS records and an honest empty state otherwise.
* **HTTP Traffic**: Displays fields present in decoded HTTP records and an honest empty state otherwise.
* **TLS Metadata**: Displays fields present in decoded TLS records and an honest empty state otherwise.

### 4.5 Signals & Observations
A deterministic rule engine surfaces review-worthy activity from observed metadata. Analysts explicitly add reviewed findings to the report or dismiss them as noise; running a model assessment does not change review state.

### 4.6 AI-Assisted Investigation
Invokes GPT-5.6 for one selected signal using only its bounded evidence packet. Structured observations, inference, uncertainty, next steps, and citations are validated before display.

### 4.7 Capture Overview
Optionally invokes Google Gemini with a bounded whole-capture summary for orientation, traffic-pattern explanation, learning perspectives, and triage questions. This capability is separate from Evidence-grounded Investigation: it cannot create findings, is never observed evidence, has no PacketSage evidence citations, and enters the report only through explicit contextual-note inclusion.

### 4.8 Incident Timeline
A chronological list of normalized events based on recorded timestamps. Event-to-flow and event-to-signal navigation uses only explicit IDs; shared IPs, partial tuples, prose, protocol labels, and temporary records cannot create a relationship.

### 4.9 Report Builder
A structured document compiler that exposes report readiness from reviewed deterministic findings and explicitly included investigation assessments. The optional contextual overview never makes a report evidence-ready on its own. Flows and events have no orphan inclusion controls. Preview is an accessible modal, Markdown is copyable, and print/PDF renders the full bounded document without the application shell.

### 4.10 Packet Academy
An instructional training suite containing guided multiple-choice challenges based on simulated capture profiles. It is designed to evaluate and sharpen defensive packet-analysis, reasoning, and evidence verification skills.

### 4.11 Architecture Spec
A product-facing technical blueprint of the implemented browser, serverless and model-provider boundaries. It documents the active evidence-to-report pipeline, enforced parsing and AI limits, completed delivery stages, trust controls, and explicitly deferred capabilities without presenting future architecture as current functionality.

---

## 5. Capabilities & Limitations

### Current Sandbox Capabilities
* **Interactive Visual Sandbox**: Clean, highly-polished interface utilizing the *Cool Trust* design language.
* **Deterministic Parsing**: Bounded native capture decoding plus normalized CSV, TSV, JSON, and text parsing with stable evidence relationships.
* **Deterministic Rules**: Local rule matching for scan detection, cleartext warnings, and beaconing.
* **Security Redaction**: Local filters to replace raw authorization tokens and cleartext keys with redacted placeholders in the UI.
* **Interactive Education**: Built-in Academy with dynamic scoring and reasoning.
* **Accessible Release Navigation**: Keyboard-operable primary rows/cards, a focus-managed Report Preview dialog, and a labelled compact menu that exposes every active route at approximately 390 px.

### Explicit Limitations
* **No Active Scanner**: PacketSage is a passive review workspace. It does **not** scan, probe, or run active network checks.
* **No Raw Capture Storage**: Supported raw `.pcap`/`.pcapng` files are decoded in bounded browser memory and are not persisted by PacketSage.
* **No Persistent Backend Database**: Data is held entirely in transient React and Express memory and is lost on page reload. Case management and user accounts are deferred to future production milestones.
* **AI-Assisted Assessment Only**: Model inference remains labelled and unconfirmed; inclusion in a report does not replace independent human verification.
