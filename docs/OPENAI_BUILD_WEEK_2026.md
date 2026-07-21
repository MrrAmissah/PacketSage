# PacketSage — OpenAI Build Week 2026 engineering record

This document is the authoritative record of the work completed for PacketSage during OpenAI Build Week 2026. It separates the pre-event product from the capabilities added or hardened during the event and records the review corrections that produced the final verified release.

## 1. Executive summary

[PacketSage](https://packetsage.vercel.app) is an evidence-grounded network investigation workspace that helps analysts use AI without allowing inference to masquerade as observed fact. It is entered in the **Developer Tools** category and is designed for security analysts, incident responders, SOC operators, students, educators and developers reviewing defensive network evidence.

| Final production fact | Verified value |
| --- | --- |
| Production | [packetsage.vercel.app](https://packetsage.vercel.app) |
| Source commit | `e2d13e59c4fbf8f32e687110af3a91386af5d2ee` |
| Production tag | `build-week-stage-4a.2-production` |
| Regression suite | 333/333 passing |
| Creator | Prince Kofi Frimpong Amissah — Creator and Developer |

Build Week changed PacketSage from a broad, memo-oriented browser workspace into a bounded investigation workflow with deterministic evidence identity, exact relationships, native capture metadata decoding, strict parsing, structured `gpt-5.6-sol` investigation, citation validation and explicit report inclusion. Separate post-release corrections made missing and portless transport evidence truthful throughout normalized records, AI packets and reports. The final release remains a deliberately bounded, volatile investigation workspace rather than a SIEM, autonomous analyst or forensic evidence vault.

## 2. Scope and methodology

PacketSage existed before Build Week, and work on an existing project was permitted. The repository was tagged immediately before the event work, then advanced through focused stages recorded in pull requests, merge commits, annotated production tags, regression suites and production verification.

This record uses those repository artifacts as its evidence. It distinguishes:

- functionality inspected at the pre-Build Week tag;
- capabilities added or materially hardened during Build Week;
- issues found through review and adversarial verification;
- corrections released after the main Stage 4A merge; and
- ideas deliberately deferred beyond the submission.

It does not quote unverified event rules, treat intermediate preview deployments as the public product or reinterpret future plans as shipped functionality.

## 3. Pre-Build Week baseline

The pre-event baseline is preserved by annotated tag `pre-build-week-2026` at commit `1ae014573fa3406feb3666f117b78a7404b8c0f6`.

Inspection of that tag confirms an existing React and Express browser workspace with:

- Import Evidence, Command Center, Flow Explorer, Protocol Intelligence, Signals & Observations, Incident Timeline, Report Builder, Packet Academy and Architecture Spec views;
- adapters for structured text and exported network telemetry;
- a generated demonstration dataset;
- deterministic signal presentation and local review controls;
- a server-side Gemini analysis route presented at the time as an AI analyst memo;
- an in-memory report workflow and print-oriented presentation; and
- a responsive application shell.

The baseline did **not** contain the current native PCAP/PCAPNG decoder, exact deterministic identity layer, selected-signal OpenAI investigation endpoint, validated evidence citations, retained two-model provenance, current guided investigation path, full assessment workspace or explicit three-state port provenance.

The tag's `package.json` contains no `npm test` command and the tagged tree contains no tracked test files. The exact active test total at the pre-Build Week tag was not preserved in the current documentation.

## 4. Build Week goals

The implementation was guided by a trust objective rather than by adding a general chatbot:

- replace broad AI analysis with bounded evidence packets;
- give normalized evidence stable identity and make relationships exact;
- prevent model inference from being presented as observation;
- retain operator control over report content and cost-generating actions;
- provide a coherent, accessible judge path through the real product; and
- verify parsing, deployment, model and report boundaries adversarially.

The governing principle was:

> Observed evidence, deterministic derivation, external context and AI inference remain visibly separate.

## 5. Milestone chronology

| Milestone | Production or merge reference | Tests | Outcome |
| --- | --- | ---: | --- |
| Pre-Build Week baseline | `pre-build-week-2026` / `1ae0145…` | Not preserved | Existing product baseline |
| Stage 1 | [PR #5](https://github.com/MrrAmissah/PacketSage/pull/5) / `03203ae…` | 13/13 | Deterministic evidence foundation and bounded native decoding |
| Stage 2 | [PR #6](https://github.com/MrrAmissah/PacketSage/pull/6) / `42c82b3…`; production `d6e8c07…` / `build-week-stage-2-production` | 52/52 | Bounded evidence packet and OpenAI investigation |
| Stage 3 | [PR #7](https://github.com/MrrAmissah/PacketSage/pull/7) / `47157fd…` / `build-week-stage-3-production` | 82/82 | Trusted report lifecycle and separate Capture Overview |
| Stage 4A | [PR #8](https://github.com/MrrAmissah/PacketSage/pull/8) / `6e56189…` / `build-week-stage-4a-production` | 285/285 | Judge path, full assessment workspace and professional report |
| Report-boundary hotfix | [PR #9](https://github.com/MrrAmissah/PacketSage/pull/9) / `68e36a8…` / `build-week-stage-4a.1-production` | 298/298 | Truthful rendering of omitted strict-text source ports |
| Explicit port provenance | [PR #10](https://github.com/MrrAmissah/PacketSage/pull/10) / `e2d13e5…` / `build-week-stage-4a.2-production` | 333/333 | `observed`, `unknown` and `not-applicable` transport evidence |

Stage 2 required three deployment correction commits after the PR merge before the production tag. This is why the Stage 2 PR merge (`42c82b35b1afc9140d281a678ae2a01ef62d38bf`) and its verified production commit (`d6e8c074f7c3887324b57f606f5cda744fb396dd`) are both recorded.

## 6. What existed before Build Week

The earlier product already established the visual and educational foundation: an evidence-import screen, dashboard, flow and protocol exploration, deterministic observations, a timeline, report drafting, an instructional academy, an architecture view and a bounded server-side Gemini capability. It was a useful passive-analysis sandbox, but its identity, relationship, AI and reporting boundaries needed stronger technical enforcement.

In particular, the baseline documentation described native capture decoding as planned, used broad “AI memo” language, coupled report content directly to an analysis result and lacked a regression command. Build Week did not merely rename those concepts; it replaced or hardened their underlying data paths and interaction contracts.

## 7. What Build Week added or hardened

### Deterministic evidence identities

Events, flows, DNS, HTTP, TLS and deterministic signals received canonical identities. Stable occurrence indexes preserve distinct repeated records without relying on array position or a random identifier. The implementation was regression-checked for repeatability across identical decodes and for simultaneous protocol records.

The IDs support application identity and navigation. They are not represented as cryptographic chain of custody, and collision impossibility is not claimed.

### Exact relationships

Parser-established ID sets became the sole authority for relationships between events, flows, protocol records and signals. Shared addresses, protocol names, prose, partial endpoint matches and demo-specific values do not create a relationship. Missing IDs remain unavailable; the interface does not substitute the first flow or a temporary record.

### Native PCAP and PCAPNG metadata decoding

Stage 1 added bounded browser-side capture decoding for the implemented Ethernet, IPv4/IPv6, TCP, UDP, ICMP and basic DNS paths. Review corrections added deterministic canonical IPv6 formatting, including `::`, `::1`, leftmost longest-run compression and stable endpoint use in direction, grouping and identity.

Malformed, truncated, unsupported and oversized inputs fail without synthetic evidence. The decoder does not perform TCP stream reassembly, decryption, payload reconstruction, full protocol dissection or host-compromise confirmation.

### Strict structured-text parsing

CSV, Suricata EVE JSON, Zeek TSV/log exports, TShark JSON and strict structured text pass through bounded server parsing. The strict grammar rejects incomplete or ambiguous lines without returning partial evidence. The final provenance release permits explicit transport ports from `0` through `65535`, preserves an omitted source port as unknown and keeps portless protocols free from fabricated suffixes.

### Evidence-grounded OpenAI investigation

Stage 2 introduced one deliberately selected deterministic signal as the entry point to a bounded investigation. Packet construction retains only the exact valid intersection of referenced flows, their exact events and protocol records with explicit surviving event relationships. Heuristic protocol matching was removed during complete-diff review.

The server endpoint validates the request and response, enforces record/text/byte limits, applies a 45-second timeout and uses `store: false`. Safe failures return a bounded retry state instead of raw provider errors, stack traces or a local fallback assessment.

### Citation validation

Every returned citation is intersected with the evidence IDs actually supplied to the model. Unsupported references are removed without substitution. Exact citation actions can open only the referenced current flow or event, and leaving that view restores normal unrestricted navigation.

### Cancellation and stale-response isolation

Each investigation uses a monotonic request identity, deterministic packet identity and `AbortController`. Evidence or signal changes invalidate active work. Success or failure is applied only when request, signal, evidence and packet identities still match. Stale, aborted, duplicate, retried and out-of-order completions cannot overwrite the current case; browser disconnects propagate cancellation upstream.

### Trusted report lifecycle

Deterministic findings require an explicit review decision. A retained OpenAI assessment requires separate explicit inclusion for the current evidence, signal and packet identity. The optional Capture Overview has its own contextual-note inclusion control. Neither model writes itself into the report, changes evidence or marks a deterministic finding reviewed.

Screen report, Preview, copied Markdown and Print/PDF consume the same report model. Imported source bytes or exact text can produce a SHA-256 digest; generated evidence uses an honest non-applicable state, and unavailable source material is labelled `Not calculated` rather than given an invented hash.

### Separate Capture Overview

The earlier Gemini capability was retained and repositioned as optional whole-capture orientation. It receives a separately bounded summary, remains citation-free and cannot create or modify deterministic findings. When included, it appears only as a labelled contextual report note that is not evidence-linked.

Capture Overview uses the configured server-side Gemini model, and each retained result records its actual provider and model provenance. A model observed during one dated deployment check is not treated as a permanent architecture promise.

### Full assessment workspace

Stage 4A added a focused workspace for a valid retained assessment matching the current evidence, selected signal and packet identity. It renders the validated response without regeneration, exposes exact referenced evidence, supports keyboard navigation and retains the compact signal context. Provider, model, schema, generation time, evidence identity and packet identity remain available in optional technical details and report provenance.

### Contextual judge path

The guided sample gained a four-step investigation path and a non-modal spotlight tour bound to real controls. It never calls either model automatically. Because provider use can incur cost, the operator can finish onboarding without AI and return later. Tour progress cannot create findings, include report content or fabricate assessment completion.

### Professional report and PDF verification

The report gained volatile operator-entered identity fields, truthful generation and evidence metadata, a restrained draft presentation, structured timeline columns and consistent model provenance. Print isolation excludes the application shell and guided tour while preserving late timeline and limitations content.

PDF automation exercises the actual guided workflow. At the final `.2` baseline the guided fixture produced four populated pages without an included assessment and six with one. Those counts are verification outcomes for a particular fixture and layout, not permanent product page-count guarantees.

### Responsive accessibility

Stage 4A corrected header density, information popover clipping, timeline card organization, exact target geometry, focus transfer and return, keyboard behavior, reduced-motion handling, report-preview focus trapping and 390 px overflow. The generated-sample tour remains optional and excludes custom evidence.

### Explicit port provenance

The final two releases corrected a subtle trust-boundary defect: numeric zero had represented an observed literal zero, an omitted transport value and a structurally portless record. The normalized model now records `observed`, `unknown` and `not-applicable` explicitly.

| Evidence condition | Canonical rendering |
| --- | --- |
| Observed nonzero port | `10.0.0.15:443` |
| Observed literal zero | `10.0.0.15:0` |
| Omitted or unknown port | `10.0.0.15:unknown` |
| Portless protocol | `10.0.0.15` |

Provenance participates in identity and grouping where an otherwise identical zero would be ambiguous. Existing guided-sample and ordinary observed nonzero identities remain stable. The same states reach the bounded OpenAI packet and are validated server-side.

## 8. GPT-5.6 runtime role

**Evidence-grounded Investigation** uses the verified server-side runtime **OpenAI / `gpt-5.6-sol`**. It receives:

- one deliberately selected deterministic signal;
- exact referenced flows and their supported events;
- supported protocol records carrying explicit relationships to surviving events;
- a bounded structured evidence packet with explicit port provenance; and
- no raw PCAP/PCAPNG bytes, packet payloads, packet `info` text or unrelated capture content.

The endpoint requires structured output rendered as:

1. Assessment summary;
2. Observed evidence;
3. Analyst inference;
4. Uncertainty / missing evidence; and
5. Recommended next investigative steps.

PacketSage validates the response schema and retains a citation only when it names an ID supplied in the evidence packet. The model cannot modify deterministic evidence, mark a signal reviewed, automatically include content in a report or create fallback findings. Each retained result records schema version, provider, actual model, generation time/state, evidence identity, packet identity and inclusion state.

## 9. Gemini runtime role

**Capture Overview** is a separate optional path for broad orientation, traffic-pattern explanation, beginner and technical perspectives and analyst triage questions. It is whole-capture context, not observed evidence or a second forensic opinion.

The overview receives a separately bounded summary and uses defense-in-depth summary redaction on the server path. It does not receive raw capture bytes or packet payloads, does not return PacketSage evidence citations and is never merged into the OpenAI assessment state. It enters a report only through **Include overview as contextual note**.

Capture Overview uses the configured server-side Gemini model, and each retained result records its actual provider and model provenance. PacketSage does not present the two models as consensus or mutual validation.

## 10. Codex collaboration

OpenAI Codex assisted the Build Week engineering process through:

- repository and architecture analysis;
- bounded implementation changes;
- regression-test development;
- pull-request and complete-diff review;
- adversarial trust-boundary and release audits;
- production, PDF, responsive and credential-boundary verification; and
- documentation inventory and factual reconciliation.

Concrete review outcomes included canonical IPv6 formatting, removal of unrelated-flow fallback, exact protocol-to-event provenance, stale-request isolation, report-only PDF output, tour synchronization, honest unknown-port rendering and explicit three-state port provenance.

Codex is not part of PacketSage's deployed runtime. It does not receive user evidence through the application and does not generate application findings or report content.

## 11. Evidence-integrity audits

PacketSage's maturity came partly from recording and correcting defects rather than hiding them:

| Finding | Correction |
| --- | --- |
| Fabricated demo signals and AI fallback findings could appear as evidence | Removed; failures now remain honest and empty |
| Identical visible records needed stable distinct identity | Added deterministic occurrence indexing |
| IPv6 zero compression could render malformed endpoints | Replaced with canonical eight-hextet formatting and loopback regressions |
| Related-flow navigation contained demo matching and first-flow fallback | Made exact `relatedFlowIds` the sole authority |
| Protocol records could enter an investigation through heuristic matching | Required explicit protocol-to-event relationships and surviving-ID intersection |
| Late, retried or out-of-order model responses could threaten state isolation | Added monotonic request and packet identity plus cancellation |
| Report controls could imply unsupported flow/event inclusion | Removed orphan controls; report inputs now match the real report model |
| Application UI could leak into Print/PDF output | Added report-only print isolation and PDF text gates |
| Spotlight geometry and report inclusion state could desynchronize | Bound progression and geometry to the current live target and current assessment |
| PDF spacing could create blank or near-empty trailing pages | Corrected print grouping and added page-population checks |
| Omitted strict-text source port displayed as observed `:0` | Released `.1` report-boundary hotfix rendering `:unknown` |
| A single numeric zero still represented three evidence meanings | Released `.2` required three-state port provenance across adapters, identity, UI, report and AI packet |

## 12. Rejected approaches

The project deliberately rejected or removed:

- fabricated local or canned fallback assessments;
- heuristic citation, protocol or relationship matching;
- automatic report inclusion;
- a generic evidence chat or orchestration framework during Build Week;
- model consensus or one provider “validating” another;
- unsupported compromise, malware or command-and-control conclusions;
- raw capture or payload transmission to a model route; and
- broad persistence, account or integration architecture before the bounded workflow was verified.

## 13. Intentionally deferred scope

The following work remains future-facing: Evidence Query over bounded normalized evidence, provenance-labelled external context, accounts and access control, durable cases, collaboration, SIEM/SOC integrations, large-capture workers, progressive parsing, custom deterministic rules, versioned report snapshots, cross-capture correlation, chain-of-custody workflows and private/on-premise deployment.

These were deferred to protect the evidence boundary, keep the submission path coherent and avoid presenting unverified architecture as current product behavior. See the [PacketSage roadmap](./ROADMAP.md).

## 14. Verification

The final production baseline passed:

- 333/333 regression tests;
- TypeScript lint;
- production build;
- `npm audit` and `npm audit --omit=dev` with zero reported vulnerabilities;
- PCAP and PCAPNG decoding regressions;
- strict valid/invalid text parsing and bounded API errors;
- standard, assessment-included, omitted-port and three-state PDF gates;
- report text checks for early and late content, repeated headers and application-shell exclusion;
- desktop and 390 px responsive/overflow checks;
- keyboard and focus behavior through investigation, citations, tour and Preview;
- browser bundle scans for server credential names, credential signatures and values;
- live `gpt-5.6-sol` structured investigation with valid retained citations;
- exact cited-flow/event navigation and restoration of unrestricted flow navigation; and
- production deployment verification at [packetsage.vercel.app](https://packetsage.vercel.app).

The browser, server and provider paths remained separate throughout verification: capture bytes were decoded in browser memory, supported text used `/api/parse`, and optional model requests used bounded derived data through their own server routes.

## 15. Production tags and release history

All listed tags are annotated, immutable historical references in the repository.

| Tag | Annotated tag object | Tagged commit | Purpose |
| --- | --- | --- | --- |
| `pre-build-week-2026` | `78ad272332d2c600721916fa0a4845376ed4f4dc` | `1ae014573fa3406feb3666f117b78a7404b8c0f6` | State before the Build Week submission period |
| `build-week-stage-2-production` | `2d085c8dea289ba6b5bc56e78058da0611e84b84` | `d6e8c074f7c3887324b57f606f5cda744fb396dd` | Deployed evidence-grounded investigation baseline |
| `build-week-stage-3-production` | `fc654aef1c6544b5caa8a82fc88c7b377cb3511c` | `47157fdcb0144c3ac6c24202c072f1e05c5c8105` | Two-model separation and trusted report lifecycle |
| `build-week-stage-4a-production` | `2cadc540e2e3aadfbe53dfe02209f52b85df5838` | `6e56189f096e52f12c236837cefb457f79a7c069` | Judge-ready investigation workspace |
| `build-week-stage-4a.1-production` | `1e70dd6fe7cba15f61a5da0e60228babb301152f` | `68e36a838b58e068ff9b24585a4e3ce2b5594193` | Strict-text unknown source-port report correction |
| `build-week-stage-4a.2-production` | `0d4a2ae61e82ad5367e0f85f56d084d7fb6f9b24` | `e2d13e59c4fbf8f32e687110af3a91386af5d2ee` | Explicit observed, unknown and not-applicable port provenance |

Stage 1 was merged at `03203ae9a134f35b3b073f7297a8274f1da0f020` without a separate production tag. Stage 2 was merged at `42c82b35b1afc9140d281a678ae2a01ef62d38bf` and reached its production tag after focused Vercel/runtime fixes. Stage 3, Stage 4A and the two provenance corrections were squash-merged at the commits shown above.

## 16. Submission metadata

| Field | Value |
| --- | --- |
| Project | PacketSage |
| Category | Developer Tools |
| Creator | Prince Kofi Frimpong Amissah |
| Public role | Creator and Developer |
| Repository | [github.com/MrrAmissah/PacketSage](https://github.com/MrrAmissah/PacketSage) |
| Production | [packetsage.vercel.app](https://packetsage.vercel.app) |
| Codex Feedback ID | `019f4e33-1bdf-72a3-9223-affd8b1546b6` |
| Final video URL | _To be added after recording_ |
| Final Devpost URL | _To be added after submission creation_ |

## 17. Known limitations

- Native capture decoding is intentionally bounded and does not provide TCP stream reassembly, decryption, payload reconstruction or full protocol dissection.
- PacketSage does not perform live capture, active scanning, containment or host-compromise confirmation.
- Active evidence, assessment, report and investigation state is volatile and clears when evidence is replaced or the session is reloaded. Limited interface preferences may persist locally. Hosting and model-provider retention policies remain external to PacketSage.
- There are no accounts, persistent cases, collaboration controls, SIEM integrations or large-capture background workers.
- Optional model routes depend on configured server-side provider access, network availability and provider behavior. Safe failure does not create a substitute assessment.
- Model output remains bounded assistance. It must not be treated as observed evidence, an autonomous decision or a replacement for analyst validation.
- PacketSage is proprietary and source-available, not open source or a court-ready forensic evidence vault.

Return to the [PacketSage README](../README.md) or review the [technical specification](./TECHNICAL_SPEC.md), [security and privacy model](./SECURITY_PRIVACY_MODEL.md), [user guide](./USER_GUIDE.md) and [roadmap](./ROADMAP.md).
