# PacketSage Security & Privacy Model

This document outlines the security controls, data privacy principles, and operational boundaries governing PacketSage’s forensic sandbox architecture.

---

## 1. Defensive-Use & Authorization Scope

PacketSage is designed strictly for authorized, defensive-use network security operations.

### 1.1 Ingested Evidence Authorization
* **Mandatory Authorization**: Users are required to confirm they own, possess, or have obtained explicit authorization to inspect any network capture, log export, or packet flow metadata imported into the platform.
* **Consent Banner**: A persistent authorization and compliance notice is integrated into the Evidence Ingest dashboard.
* **Education Exception**: The built-in, pre-packaged sample dataset does not require authorization or active credentials as it is a simulated dataset created exclusively for instructional and educational testing.

### 1.2 Passive Forensics Only
PacketSage operates as a purely passive review workstation.
* **No Network Scans**: The application does **not** perform active network checks, TCP port probing, IP pings, or domain scans.
* **No Live Sniffing**: It reads and visualizes historical capture files or log extracts. It does not bind to raw network interfaces, network sockets, or live capture streams on the host device.

---

## 2. In-Memory Volatile Retention Model

To minimize the security footprint of packet analyses, PacketSage uses an in-memory workspace with explicit processing boundaries:

* **Processing Boundary**: Raw PCAP/PCAPNG captures are decoded in browser memory. Supported text exports are sent to the serverless parsing endpoint.
* **Active Evidence State**: Parsed network records are held in the active application session; PacketSage does not claim zero retention by every infrastructure or model provider involved.
* **Clear Case / Session Reset**: Clicking "Clear Data" or reloading clears active evidence and generated analysis from React state. Some review-status preferences may persist in browser storage.

---

## 3. Server-Side AI Proxy & Redaction Controls

To enable AI-assisted incident description drafting without compromising sensitive payloads, PacketSage implements a server-side proxy and data-reduction pipeline:

```
+------------------+     +-------------------+     +-------------------------+     +------------------+
| Ingested Evidence | --> | Parser & Adapter  | --> | Redaction Controller    | --> | Server-Side AI   |
| Raw Wireshark,   |     | Normalizes packet |     | Selects exact evidence |     | GPT-5.6 Proxy    |
| Suricata, Zeek   |     | details in memory |     | filters payload details |     | (Selected logs)  |
+------------------+     +-------------------+     +-------------------------+     +------------------+
```

### 3.1 What is Shared with the AI Proxy
To investigate a signal, PacketSage sends only its bounded normalized evidence packet and exact relationships to the server-side GPT-5.6 endpoint.
* **No Raw Packet Payloads**: Capture bytes, packet payloads, and packet `info` fields are never transmitted to the model.
* **Provider Boundary**: The proxy sends selected metadata to the configured model provider. Operators must review the provider and hosting platform retention settings for their deployment.

The optional Capture Overview is a separate capability. It sends a fixed-limit summary of flows, protocol records, deterministic signal summaries, and protocol statistics to Google Gemini. It does not send capture bytes or raw packet payloads. Its response cannot create deterministic findings, is never treated as observed evidence, has no evidence citations, and is not added to a report unless the operator explicitly includes it as a contextual note.

Both runtime paths retain schema version, provider, model identifier, generation time/state, current evidence or capture identity, and report-inclusion state. Client request identity and cancellation prevent older overview or investigation responses from overwriting the current case.

### 3.2 Redaction Controls
Before sending distilled metadata to the server-side AI proxy, PacketSage applies browser-side redaction algorithms:
* **Authorization Headers**: Suspected credentials, API tokens, and JWT strings found in HTTP user agent headers or request lines are redacted and replaced with a default placeholder string (`[REDACTED_BY_CLIENT]`).
* **Payload Truncation**: Only structural headers are parsed; raw base64 or hexadecimal payload strings are truncated and omitted from AI query prompts.

---

## 4. Wording Boundaries & Preventing Overclaims

To ensure technical and professional honesty, the following guardrails are maintained across all user interfaces, tooltips, and document exports:

* **No Claims of Malware Detection**: PacketSage identifies suspicious patterns (e.g., unusual ports, repeating beaconing intervals, unencrypted transmissions) based on deterministic rules. It does **not** scan files, analyze binary signatures, or confirm the execution of specific malware strains.
* **No Claims of Forensic Certainty**: Packet and protocol evidence alone is never presented as absolute proof of compromise. The platform explicitly highlights that findings are "suspected indicators" and require independent analyst correlation and host-level log review.
* **No Claims of Court Readiness**: As an in-memory browser workstation without cryptographic integrity hashing, chain-of-custody tracking, or write-blocked raw disk integration, PacketSage is positioned as a defensive drafting sandbox rather than a court-certified system.
* **No Universal Storage Guarantees**: Tooltips and specifications avoid terms like "fully secure," "guaranteed privacy," or "zero external transmission" because selected metadata summaries must transit the AI proxy to compile the narrative memo.
