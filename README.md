# PacketSage

PacketSage is a defensive network forensics sandbox for reviewing packet exports, decoded telemetry, protocol behavior, evidence-linked observations, AI-assisted assessments, incident timelines, and report-ready investigation notes.

It is built for security analysts, incident responders, students, and SOC operators who need a structured workspace for passive packet review. PacketSage ingests raw PCAP/PCAPNG captures, text packet logs, Wireshark CSVs, Suricata EVE alerts, Zeek summaries, TShark JSON, and generated sample metadata, then reconstructs flows, highlights review-worthy observations, and helps draft evidence-bound reports.

## License & Use

PacketSage is proprietary and source-available, not open source. Public access to this repository is for transparency, review, portfolio, and collaboration screening only. Copying, redistribution, commercial use, hosted reuse, rebranding, or derivative products require prior written permission from the repository owner. See [LICENSE](./LICENSE) and [CONTRIBUTING.md](./CONTRIBUTING.md).

## Product Preview

<p align="center">
  <img src="./docs/assets/packetsage-import-evidence.png" alt="PacketSage Import Evidence screen for uploading authorized packet exports, loading a sample incident dataset, or pasting structured logs." width="96%" />
</p>

<p align="center">
  <img src="./docs/assets/packetsage-command-center.png" alt="PacketSage Command Center showing decoded packet evidence, protocol stats, signal counts, and investigation brief." width="47%" />
  <img src="./docs/assets/packetsage-report-builder.png" alt="PacketSage Report Builder showing report settings, evidence metadata, readiness checks, and export controls." width="47%" />
</p>

---

## 🚀 Core Positioning & Boundaries

To ensure professional forensic integrity, PacketSage operates on a strict **Evidence-First, AI-Second** engineering model. It is designed around the following boundaries:

* **Defensive Analyst Workspace**: PacketSage is designed for defensive posture review and instructional forensics. It is **not** an active malware detector or breach containment system.
* **Bounded Forensic Workspace**: Raw captures are decoded in browser memory; supported text exports use the parsing endpoint. It is **not** a court-ready forensic evidence vault.
* **Separated AI Roles**: Evidence-grounded investigation operates on one selected signal and exact citations. The optional Capture Overview operates on a bounded whole-capture summary for orientation only; it is never labelled as observed evidence.
* **Bounded Native Capture Decoder**: Browser-side `.pcap`/`.pcapng` decoding covers Ethernet and practical IPv4/IPv6 TCP, UDP, ICMP, and basic DNS metadata without stream reassembly, decryption, or payload reconstruction.

---

## 🛠️ Main Features & Functional Modules

1. **Command Center**: Summarizes only loaded evidence: normalized event, flow, endpoint, byte, protocol-record, signal, and reviewed-finding counts, plus evidence-appropriate next actions.
2. **Import Evidence**: Supports authorized file imports and a strict pasted-text grammar. Pasted records use `YYYY-MM-DDTHH:mm:ssZ SRC_IP -> DST_IP [src_port=N] dst_port=N protocol=TCP|UDP length=N`; omitted source ports remain unknown.
3. **Flow Explorer**: Searches normalized flows and resolves events through `flow.relatedEvents` and signals through exact `signal.relatedFlowIds`. It does not infer host identity or transport state.
4. **Protocol Intelligence**: Separate investigative rails for key network applications:
   * *DNS Log*: Displays only decoded DNS record fields and honest empty states.
   * *HTTP Traffic*: Displays only decoded HTTP record fields and honest empty states.
   * *TLS Metadata*: Displays only decoded TLS fields, including SNI/version/fingerprint when recorded, without decryption claims.
5. **Signals & Observations**: A deterministic rule engine surfaces review-worthy patterns. Analysts can add a reviewed finding to the report or dismiss it as noise.
6. **AI-Assisted Investigation**: Assesses one selected signal with GPT-5.6 using only its bounded, validated evidence packet. Assessments require explicit inclusion in a report draft.
7. **Capture Overview**: Optionally asks Google Gemini for broad orientation, traffic-pattern explanation, learning perspectives, and triage questions from a bounded summary. It remains separate from evidence-linked investigation and is excluded from reports by default.
8. **Incident Timeline**: Orders normalized events by recorded timestamp. Flow and signal navigation is enabled only for exact parser-established event relationships.
9. **Report Builder**: Compiles deterministic findings and explicitly included assessments. Flow/event report controls are intentionally absent. Print/PDF renders the complete bounded report without application chrome; a capture overview appears only through explicit contextual-note inclusion.
10. **Packet Academy**: An instructional training suite containing guided multiple-choice challenges based on simulated capture profiles to evaluate defensive reasoning skills.

---

## 📦 Standard Data Models (TypeScript)

* **UploadedEvidence**: Tracks properties of the imported log/packet bundle (name, size, parseMode, upload timestamp).
* **FlowSummary**: Reconstructs TCP/UDP sessions between source and destination endpoints, detailing timestamps, volumes, and calculated risk indicators.
* **DnsRecord / HttpRecord / TlsRecord**: Normalized protocol-specific structures containing queried domains, requested paths, response codes, and certificate SNIs.
* **SuspiciousSignal**: Deterministic indicators computed on-the-fly (e.g., cleartext credentials, unusual inbound ports, data transfer spikes, scan patterns).
* **InvestigationRecord**: Stores a validated, evidence-scoped assessment and its explicit report-inclusion state.
* **CaptureOverviewRecord**: Stores provider/model provenance, schema version, capture identity, generation time/state, and explicit contextual-note inclusion state.

---

## 🔒 Security & Privacy Model

* **Authorized Use Only**: Users must confirm authorization before importing custom logs. A pre-packaged simulated dataset is built-in for zero-credential training.
* **Processing Boundary**: Raw PCAP/PCAPNG captures are decoded locally. Supported text evidence is sent to the parsing endpoint; selected metadata may later be sent through the AI proxy.
* **Server-Side AI Proxy**: One selected signal and only its exact related normalized evidence are submitted to the server-side GPT-5.6 investigation endpoint.
  * Raw packet payloads and capture bytes are not transmitted to the proxy.
  * Returned citations are validated against the supplied evidence-ID set before display or report inclusion.
* **Capture Overview Boundary**: A separate server endpoint submits a bounded whole-capture summary to Google Gemini. Its output has no PacketSage evidence citations, cannot modify findings, and never enters the report automatically.
* **Passive Forensics**: PacketSage is purely passive. It does not perform active network port scans, host pings, or live interface sniffing.

---

## 💻 Running Locally

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment Variables
Create a `.env` file in the project root based on `.env.example`:
```env
OPENAI_API_KEY="your-openai-api-key"
GEMINI_API_KEY="your-gemini-api-key"
APP_URL="http://localhost:3000"
```
*(Do not prefix either credential with `VITE_`; both must remain server-only.)*

## AI use and provenance

* **GPT-5.6** generates the selected-signal Evidence-grounded Investigation from a bounded evidence packet. PacketSage validates its structured schema and removes unsupported citations without substitution.
* **Google Gemini** powers the optional Capture Overview from a bounded summary of the loaded capture. It provides orientation and learning perspectives, is not observed evidence, and is excluded from reports unless explicitly included as a contextual note.
* **OpenAI Codex** was used during implementation and review to inspect the repository, implement bounded parsing and trust controls, add regression tests, and run verification. Codex is not a runtime analyst, does not generate PacketSage findings, and is not part of the deployed evidence pipeline.
* Every retained runtime AI result records schema version, provider, model identifier, generation time/state, evidence or capture identity, and report-inclusion state. Provider details remain available through technical details and report provenance rather than serving as the primary feature label.

### 3. Run the Development Server
```bash
npm run dev
```

### 4. Access the Workspace
Open your browser and navigate to `http://localhost:3000`.

---

## 🗺️ Production Roadmap

* **Current forensic workstation**:
  - Ephemeral browser-side workspace, bounded native PCAP/PCAPNG decoder, text adapters, and deterministic rule engine.
  - Server-side GPT-5.6 evidence-scoped investigation.
  - Report Builder with print-clean layouts.
  - Built-in Packet Academy.
* **Potential large-capture extension**:
  - Isolated decoder workers may supplement, rather than replace, the current bounded browser decoder.
  - Secure Cloud Storage buckets with signed short-lived URLs.
* **Stage 3: Workspace Authorization & Case Management (Planned)**:
  - Multi-tenant Firebase Authentication and Firestore persistent case storage.
