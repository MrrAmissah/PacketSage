# PacketSage Technical Specification

This document describes PacketSage’s current bounded browser workspace, serverless parsing and AI boundaries, and in-memory state models.

---

## 1. Technical Stack

PacketSage is built on a modern, robust, full-stack JavaScript/TypeScript architecture:

### 1.1 Frontend Architecture
* **Library/Framework**: React 18+ bootstrapped with Vite.
* **Styling**: Tailwind CSS utilizing the **Prince Product UI ("Cool Trust")** design language.
* **Animations**: Fluid layouts, entering fades, and interactive transitions using `motion` (imported from `motion/react`).
* **Icons**: Standard SVG vector icons imported from `lucide-react`.
* **Charts & Visualizations**: Interactive data rendering and protocol ratios built with `recharts` and `d3`.

### 1.2 Backend Architecture
* **Server Framework**: Node.js with Express.
* **Language**: TypeScript with type-stripping support.
* **Server Dev / Build**: `tsx` for direct TypeScript execution in development; `esbuild` for bundling the production server into a single CJS bundle (`dist/server.cjs`).
* **Model Integration**: The server-side `/api/investigate` endpoint calls GPT-5.6 with `process.env.OPENAI_API_KEY`, strict structured output, and bounded evidence packets. The separate `/api/analyze` endpoint calls Google Gemini with `process.env.GEMINI_API_KEY` for a bounded, citation-free whole-capture overview.

---

## 2. Evidence State & Normalization Model

All imported data is normalized into a standard, in-memory TypeScript schema.

```typescript
// Core Data Model Definitions
export interface UploadedEvidence {
  id: string;
  name: string;
  size: number;
  type: 'csv' | 'json' | 'tsv' | 'pasted' | 'sample';
  timestamp: string;
}

export interface FlowSummary {
  id: string;
  timestamp: string;
  duration: number;
  srcIp: string;
  srcPort: number;
  destIp: string;
  destPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'Unknown';
  bytesSent: number;
  bytesReceived: number;
  packets: number;
  riskScore: 'Low' | 'Medium' | 'High' | 'Critical';
  riskReason?: string;
}

export interface DnsRecord {
  timestamp: string;
  query: string;
  type: string;
  response: string;
}

export interface HttpRecord {
  timestamp: string;
  method: string;
  host: string;
  uri: string;
  userAgent: string;
  statusCode: number;
  contentType: string;
}

export interface TlsRecord {
  timestamp: string;
  sni: string;
  version: string;
  cipher?: string;
  fingerprint?: string;
}

export interface SuspiciousSignal {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: 'possible' | 'likely' | 'confirmed';
  type: 'scan' | 'cleartext' | 'beaconing' | 'protocol_mismatch';
  category: string;
  timestamp: string;
  flowId?: string;
  endpoint?: string;
  status: 'needs_review' | 'validated' | 'dismissed';
}
```

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

Raw `.pcap`/`.pcapng` files are decoded in the browser with bounded container, packet-count, and byte-size limits. The current decoder supports Ethernet and practical IPv4/IPv6 TCP, UDP, ICMP, and basic DNS metadata; unsupported link types and malformed or truncated captures fail without synthetic evidence.

### 3.3 Signals & Verification Persistence
Signals are calculated by deterministic rule evaluators. **Add finding to report** and **Dismiss noise** update local review state; running an AI investigation alone never marks a signal as reviewed.

---

## 4. Synchronization & Rendering Architecture

### 4.1 Report Builder Sync
The Report Builder derives its document from parsed events, exact relationships, reviewed deterministic signals, explicitly included investigation records, and an independently included contextual overview. Its readiness status indicates whether reviewed or explicitly included evidence-grounded content exists; optional overview text cannot make a report evidence-ready.

### 4.2 InfoPopover Engine (Fixed Viewport Clamping)
To solve clipping issues common to interactive dashboards (caused by tables, scroll containers, or page edges), the `InfoPopover` component uses a robust fixed-coordinate placement algorithm:
1. **Dynamic Measurement**: Triggers on-open layout calculation via `.getBoundingClientRect()`.
2. **Horizontal Viewport Clamping**: Clamps the horizontal coordinate between a viewport-safe margin to prevent left-side truncation on mobile, and right-side overflow on desktop.
3. **Vertical Collision Switching**: Detects if rendering above the trigger cuts off at the top of the browser window. If so, it automatically flips downwards (and vice versa).
4. **Listeners**: Binds scroll and resize listeners while open to maintain lock-on position. Includes window resize debounces and a clean-up lifecycle.

### 4.3 App Theming & Print Layouts
* **Theme**: Structured on Tailwind CSS utilizing CSS variables under the `@theme` block in `src/index.css`. The palette matches deep slates, cool navies, and high-contrast primary buttons.
* **Print Stylesheet**: Implements rigorous `@media print` CSS overrides. When exporting or printing reports:
  - Sidebar and navigation modules are automatically hidden (`print:hidden`).
  - Font sizes are standardized to clean, readable values.
  - Interactive controls (input borders, toggles, run-buttons) are hidden or flattened into standard text blocks to support high-quality PDF preservation.

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
| **AI Processing** | Server-side evidence-scoped GPT-5.6 proxy | Isolated enterprise API gateway with auditing |
