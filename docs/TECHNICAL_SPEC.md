# PacketSage Technical Specification

This document describes PacketSage’s current bounded browser workspace, serverless parsing and AI boundaries, and in-memory state models.

---

## 1. Technical Stack

PacketSage is built on a modern, robust, full-stack JavaScript/TypeScript architecture:

### 1.1 Frontend Architecture
* **Library/Framework**: React 19 with Vite.
* **Styling**: Tailwind CSS 4 with semantic CSS variables.
* **Animations**: Fluid layouts, entering fades, and interactive transitions using `motion` (imported from `motion/react`).
* **Icons**: Standard SVG vector icons imported from `lucide-react`.

### 1.2 Backend Architecture
* **Server Framework**: Node.js with Express.
* **Language**: TypeScript with type-stripping support.
* **Server Dev / Build**: `tsx` for direct TypeScript execution in development; `esbuild` for bundling the production server into a single CJS bundle (`dist/server.cjs`).
* **Model Integration**: The server-side `/api/investigate` endpoint calls GPT-5.6 with `process.env.OPENAI_API_KEY`, strict structured output, and bounded evidence packets. The separate `/api/analyze` endpoint calls Google Gemini with `process.env.GEMINI_API_KEY` for a bounded, citation-free whole-capture overview.

---

## 2. Evidence State & Normalization Model

All imported data is normalized into a standard, in-memory TypeScript schema.

The canonical definitions live in `src/types.ts`. `UploadedEvidence` records deterministic identity, source format, parse mode, status, retention wording, and checksum state. `PacketEvent` records timestamp, endpoints, ports, protocol, observed length, and a bounded decoded description. `FlowSummary` records the observed five-tuple, interval, counts, direction/risk labels, and exact `relatedEvents` IDs. DNS, HTTP, and TLS records carry optional IDs plus explicit `relatedEventIds`. `SuspiciousSignal` carries observed evidence, separately worded interpretation/limitations/checks, and optional exact `relatedFlowIds`/`relatedEventIds`. `InvestigationRecord` and `CaptureOverviewRecord` retain schema, provider, model, generation time/state, evidence identity, and explicit report-inclusion state.

---

## 3. Data Pipelines & Integration Flows

### 3.1 Sample Dataset Pipeline
For demonstration and training, a generated defensive-analysis dataset containing routine and review-worthy activity is packaged with PacketSage. **Load guided investigation sample** hydrates the same deterministic evidence state used by the normal workflow; it does not assert an intrusion or compromise.

### 3.2 File Upload & Copy-Paste Flow
When a user uploads or pastes a text-based packet capture export, PacketSage loops through registered parser adapters:
* **CSV Adapter**: Splits comma-separated values exported from Wireshark, identifying standard headers (Time, Source, Destination, Protocol, Length, Info).
* **Suricata EVE JSON Adapter**: Normalizes alerts, DNS queries, and flow data from JSON lines.
* **Zeek Log TSV Adapter**: Normalizes tab-separated Zeek logs (dns.log, conn.log, http.log).
* **TShark JSON Adapter**: Parses structured JSON extracts dumped via the command-line command `tshark -T json`.
* **Strict Text Adapter**: Accepts one event per line using `YYYY-MM-DDTHH:mm:ssZ SRC_IP -> DST_IP [src_port=N] dst_port=N protocol=TCP|UDP length=N`. Timestamp, valid IPv4 endpoints, destination port, protocol, and length are required. An omitted source port is stored as unknown (`0`) and rendered as `unknown`; incomplete or ambiguous lines fail with a line-specific error and produce no partial evidence.

Raw `.pcap`/`.pcapng` files are decoded in the browser with bounded container, packet-count, and byte-size limits. The current decoder supports Ethernet and practical IPv4/IPv6 TCP, UDP, ICMP, and basic DNS metadata; unsupported link types and malformed or truncated captures fail without synthetic evidence.

### 3.3 Signals & Verification Persistence
Signals are calculated by deterministic rule evaluators. **Add finding to report** and **Dismiss noise** update local review state; running an AI investigation alone never marks a signal as reviewed.

### 3.4 Exact Relationship Resolution
Flow Explorer resolves events only from `flow.relatedEvents` and signals only when `signal.relatedFlowIds` contains the exact flow ID. Incident Timeline resolves flows only when a flow's `relatedEvents` contains the event ID and signals only when `signal.relatedEventIds` contains it. Shared IPs, partial five-tuples, prose, protocol names, severity, and temporary IDs never create navigation relationships.

---

## 4. Synchronization & Rendering Architecture

### 4.1 Report Builder Sync
The Report Builder derives its document from parsed events, exact relationships, reviewed deterministic signals, explicitly included investigation records, and an independently included contextual overview. Flow and event inclusion controls are not part of the report model. Its readiness status indicates whether reviewed or explicitly included evidence-grounded content exists; optional overview text cannot make a report evidence-ready.

### 4.2 InfoPopover Engine (Fixed Viewport Clamping)
To solve clipping issues common to interactive dashboards (caused by tables, scroll containers, or page edges), the `InfoPopover` component uses a robust fixed-coordinate placement algorithm:
1. **Dynamic Measurement**: Triggers on-open layout calculation via `.getBoundingClientRect()`.
2. **Horizontal Viewport Clamping**: Clamps the horizontal coordinate between a viewport-safe margin to prevent left-side truncation on mobile, and right-side overflow on desktop.
3. **Vertical Collision Switching**: Detects if rendering above the trigger cuts off at the top of the browser window. If so, it automatically flips downwards (and vice versa).
4. **Listeners**: Binds scroll and resize listeners while open to maintain lock-on position. Includes window resize debounces and a clean-up lifecycle.

### 4.3 App Theming & Print Layouts
* **Theme**: Structured on Tailwind CSS utilizing CSS variables under the `@theme` block in `src/index.css`. The palette matches deep slates, cool navies, and high-contrast primary buttons.
* **Print Stylesheet**: Implements rigorous `@media print` CSS overrides. When exporting or printing reports:
  - The sidebar, primary navigation, guided journey, preview overlay, and interactive controls are hidden.
  - Fixed viewport heights and overflow clipping are reset so the complete bounded report paginates.
  - Evidence summary, checksum, reviewed findings, contextual overview, included assessments, citations, timeline, recommendations, provenance, and limitations print when available.
  - `npm run verify:pdf` drives the guided sample, generates a real PDF, checks its signature/text, verifies early and late report markers, confirms multiple timeline rows, and rejects application-shell labels.

### 4.4 Active Routes
The active workspace routes are Command center, Import evidence, Flow explorer, Protocol intelligence, Signals & observations, Capture overview, Incident timeline, Report builder, Packet Academy, and Architecture spec. Architecture spec is evidence-independent and remains available before a case is loaded. At narrow widths every route is exposed through a labelled keyboard-operable menu that keeps the active route visible.

### 4.5 Architecture Spec
The in-product Architecture spec is a current-state technical blueprint rather than a promise of unavailable infrastructure. It distinguishes browser responsibilities from serverless/provider boundaries, traces the evidence-to-report pipeline, displays enforced limits from the shared runtime constants where available, documents completed Build Week stages, and labels authentication, persistent case storage, large-capture workers, enterprise policy controls, and external intelligence integrations as not implemented.

---

## 5. Deployment & Build System

### 5.1 Local Server Dev
In development, the app runs using standard Vite middlewares nested inside Express:
```bash
npx tsx server.ts
```

### 5.2 Production Bundling
Because Node.js requires rigorous ES Module relative path resolutions, PacketSage compiles the backend using `esbuild`:
```bash
vite build && esbuild server.ts --bundle --platform=node --format=cjs --packages=external --sourcemap --outfile=dist/server.cjs
```
This produces a compiled, self-contained CommonJS backend file inside `dist/server.cjs` that safely resolves internal dependencies at build time and can be launched cleanly on standard containers:
```bash
node dist/server.cjs
```

---

## 6. Current Implementation vs. Planned Production Target

| Architectural Component | Current implementation | Possible future extension |
| :--- | :--- | :--- |
| **Parsing Location** | Raw captures in the bounded browser decoder; supported text via the serverless endpoint | Isolated workers for larger captures if required |
| **Parsing Engine** | Native PCAP/PCAPNG metadata decoder plus CSV, Suricata, Zeek, TShark and text adapters | Additional sandboxed decoders without weakening current bounds |
| **Data Payload Store** | Transient React and Express RAM | Encrypted Cloud Storage (GCS / S3) |
| **Case Retention** | Volatile (lost on page reload) | Durable database persistence (Firebase/Firestore) |
| **User Management** | None (Single Session Sandbox) | Multi-tenant Firebase Authentication |
| **AI Processing** | Separate server-side GPT-5.6 signal-investigation and Gemini capture-overview proxies | Isolated enterprise API gateway with organization policy and auditing |
