# PacketSage — Devpost AI disclosure

PacketSage separates deterministic packet analysis from two clearly bounded runtime AI capabilities.

## GPT-5.6

GPT-5.6 powers **Evidence-grounded Investigation** for one operator-selected signal. PacketSage constructs a bounded packet from exact parser-established relationships, excludes raw payloads and capture bytes, enforces structured observation/inference/uncertainty/next-step output, and validates every retained citation against the supplied evidence-ID set. An assessment enters a report only through explicit user inclusion.

## Google Gemini

Google Gemini powers the optional **Capture Overview**. It receives a fixed-limit summary of the loaded capture and supplies broad orientation, traffic-pattern explanation, beginner and technical perspectives, and analyst triage questions. Its output is not observed evidence, cannot change deterministic findings, is never merged with GPT-5.6 assessment state, and is excluded from reports by default. If explicitly included, it appears only as a labelled, non-evidence-linked contextual note with no evidence citations.

## OpenAI Codex

OpenAI Codex supported repository analysis, implementation, code review, regression-test development, and verification during the build. Codex is not part of PacketSage's deployed runtime, does not receive user captures through the application, and does not produce findings or report content.

## Provenance and trust

Every retained runtime AI result stores its schema version, provider, model identifier, generation time and state, current evidence or capture identity, and report-inclusion state. Normal product labels describe capabilities; provider/model details are disclosed in optional technical details and report provenance. Failures produce an honest Retry state with no canned or local fallback output, and stale or cancelled responses cannot replace results for newer evidence.

PacketSage's non-model evidence layer is deterministic: capture/text adapters normalize bounded records, deterministic IDs preserve identity, and cross-view navigation uses exact relationship IDs. GPT-5.6 is the only AI path allowed to return validated evidence citations. Gemini remains citation-free contextual orientation. Codex assisted engineering and verification only.
