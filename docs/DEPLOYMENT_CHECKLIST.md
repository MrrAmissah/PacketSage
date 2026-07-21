# PacketSage Deployment Checklist

This practical deployment guide ensures PacketSage remains robust, compliant, and production-ready.

---

## Phase 1: Pre-Deployment Build Checks

Before initiating any deployment or committing changes:

### 1.1 Code Quality & Static Analysis
* [ ] **Local Linter Run**: Execute the TypeScript compiler and linter checks locally to ensure syntax and imports are correct:
  ```bash
  npm run lint
  ```
* [ ] **Production Build Verification**: Run the full production builder to verify Vite and esbuild configurations compile cleanly:
  ```bash
  npm run build
  ```
* [ ] **No Unused Imports**: Verify there are no fatal dangling imports (especially in key components like `ReportBuilder` or `LearningMode`).

---

## Phase 2: Secrets & Environment Variable Configuration

Protect keys and ensure environment integrity:

### 2.1 Server-Side Secrets
* [ ] **Server-only AI credentials**: Configure `OPENAI_API_KEY` and `GEMINI_API_KEY` only in the hosting provider's server-side secret store.
  * *Critical Check*: Never expose either credential through a `VITE_`-prefixed variable.
  * *Critical Check*: Confirm the credential is not committed, logged, or bundled for the browser.

### 2.2 Client-Side Configurations
* [ ] **APP_URL**: Confirm that `APP_URL` is configured to point to the correct public address of your active server deployment.
* [ ] **Environment Mapping**: Ensure `.env.example` remains a clean template containing only non-sensitive placeholders.

---

## Phase 3: Repository & Version Control Sanitation

Keep the repository clean:

### 3.1 Exclusions
* [ ] **Gitignore Audits**: Confirm that no volatile or generated files are tracked in git:
  * `node_modules/`
  * `dist/`
  * `.env`
  * `.DS_Store`
  * `package-lock.json` (unless strictly pinned for dependency lock-down)
* [ ] **No Mock Infrastructure Logs**: Ensure no mock terminal text, container port configurations, or network ping metrics are hardcoded into the source code.

---

## Phase 4: Container Deployment (Cloud Run / Docker)

For container-ready environments:

### 4.1 Ingress & Port Settings
* [ ] **Port Binding**: Ensure the Express server binds strictly to port `3000` on interface `0.0.0.0` (required for container ingress routing).
* [ ] **Build Command**: Verify your container Dockerfile or environment uses the standard npm scripts:
  * Build: `npm run build`
  * Start: `npm run start` (launches compiled `dist/server.cjs`)

## Vercel Preview Deployment

For Vercel-hosted previews:

### 4B.1 Project Settings
* [ ] **Framework Preset**: Use Vite.
* [ ] **Install Command**: `npm ci`
* [ ] **Build Command**: `npm run build`
* [ ] **Output Directory**: `dist`
* [ ] **Production Branch**: `main`
* [ ] **Preview Source**: Deploy the current pull-request head; do not depend on a retired fixed Preview branch name.

### 4B.2 Serverless API Compatibility
* [ ] **API Runtime**: Vercel preview deployments use serverless functions for `/api/health`, `/api/parse`, `/api/investigate`, and `/api/analyze`.
* [ ] **Server-Side Secret Boundary**: `OPENAI_API_KEY` and `GEMINI_API_KEY` must be configured only as server-side Vercel environment variables for Preview and Production.
* [ ] **Client Environment Label**: `VITE_APP_ENV` may be set to `preview` for Preview deployments and `production` for Production deployments.
* [ ] **No Browser AI Key**: Do not create `VITE_OPENAI_API_KEY` or `VITE_GEMINI_API_KEY`.
* [ ] **AI Timeout Guard**: `/api/investigate` returns a client-safe timeout without generating fallback findings.
* [ ] **SPA Routing**: `vercel.json` rewrites non-file routes to `index.html` for client-side navigation while preserving API function routes.

---

## Phase 5: Post-Deployment Smoke Test & Verification

Once deployed, run these sequential verifications on the live instance:

### 5.1 Import Verification
1. Access the deployment URL.
2. Verify the **Import Evidence** panel renders and displays the authorized-use notice.
3. Click **Load guided investigation sample**.
4. Confirm data parses in under 2 seconds and redirects or activates the dashboard.

### 5.2 Heuristic & Signal Check
1. Go to the **Signals & Observations** tab.
2. Select an active signal and click **Add finding to report**.
3. Select another active signal and click **Dismiss noise**.
4. Navigate away and back, then verify the table row, detail rail, and Report Builder status column preserve the selected statuses.

### 5.3 AI-Assisted Investigation
1. Open **Signals & observations** and select a signal with exact related evidence.
2. Run **Investigate with AI**.
3. Confirm all four assessment sections render and citations open exact records.
4. Explicitly add the assessment to the report, then confirm it appears in Report Builder.

### 5.4 Report Compiler & Print Layouts
1. Go to the **Report Builder** tab.
2. Confirm report readiness reflects reviewed deterministic findings and explicitly included assessments.
3. Confirm Capture Overview remains a separately included contextual note and cannot make the report evidence-ready by itself.
4. Click **Print / PDF**.
5. Confirm the print view displays only the structured report, hiding application navigation headers and action controls.
6. Confirm browser/headless PDF output is not blank and contains the report title, evidence summary, separate findings and assessment sections, exact citations, provenance, and limitations.
7. Run `npm run verify:pdf -- <preview-url>` where the environment permits headless browser execution.

### 5.5 Accessibility and Narrow Navigation
1. At approximately 390 px, open the labelled primary-navigation menu and reach every active route without horizontal swiping.
2. Confirm the active route remains visible in the menu control.
3. Operate signal rows, flow rows, timeline cards, protocol cards, and Packet Academy modules with the keyboard.
4. Open Report Preview, confirm focus enters and remains in the named dialog, close with Escape, and confirm focus returns to Preview.

---

## Phase 6: Rollback Procedures

If issues are detected on the production deployment:

1. **Immediate Reversion**: Revert the hosting environment to the last known stable commit hash in your main or release branch.
2. **Key Rotation**: If exposure is suspected, immediately rotate the affected server-side `OPENAI_API_KEY` or `GEMINI_API_KEY` credential.
3. **Log Review**: Inspect standard standard-out/standard-error streams on your hosting provider to isolate relative path errors, missing modules, or API exceptions.
