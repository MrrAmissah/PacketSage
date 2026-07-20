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
* [ ] **GEMINI_API_KEY**: Ensure `GEMINI_API_KEY` is configured strictly in your hosting provider's secure Environment Variables dashboard (e.g., Cloud Run environment secrets, Vercel environment keys).
  * *Critical Check*: Never prefix `GEMINI_API_KEY` with `VITE_`. It must remain a server-side secret hidden from browser network inspections.
  * *Critical Check*: Confirm `GEMINI_API_KEY` is not committed or logged in any configuration files, scripts, or documentation.

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

## Phase 4B: Vercel Preview Deployment

For Vercel-hosted previews:

### 4B.1 Project Settings
* [ ] **Framework Preset**: Use Vite.
* [ ] **Install Command**: `npm install`
* [ ] **Build Command**: `npm run build`
* [ ] **Output Directory**: `dist`
* [ ] **Production Branch**: `main`
* [ ] **Preview Branch**: `release/packetsage-v1.1.0-public-demo`

### 4B.2 Serverless API Compatibility
* [ ] **API Runtime**: Vercel preview deployments use the serverless functions in `api/` for `/api/health`, `/api/parse`, and `/api/analyze`.
* [ ] **Server-Side Secret Boundary**: `GEMINI_API_KEY` must be configured only as a server-side Vercel environment variable for Preview and Production.
* [ ] **Client Environment Label**: `VITE_APP_ENV` may be set to `preview` for Preview deployments and `production` for Production deployments.
* [ ] **No Browser Gemini Key**: Do not create `VITE_GEMINI_API_KEY`.
* [ ] **AI Timeout Guard**: `/api/analyze` should return a client-safe `504` timeout without generating fallback findings.
* [ ] **SPA Routing**: `vercel.json` rewrites non-file routes to `index.html` for client-side navigation while preserving API function routes.

---

## Phase 5: Post-Deployment Smoke Test & Verification

Once deployed, run these sequential verifications on the live instance:

### 5.1 Import Verification
1. Access the deployment URL.
2. Verify the **Import Evidence** panel renders and displays the authorized-use notice.
3. Click **Load sample dataset**.
4. Confirm data parses in under 2 seconds and redirects or activates the dashboard.

### 5.2 Heuristic & Signal Check
1. Go to the **Signals & Observations** tab.
2. Select an active signal and click **Add to report**.
3. Select another active signal and click **Dismiss noise**.
4. Navigate away and back, then verify the table row, detail rail, and Report Builder status column preserve the selected statuses.

### 5.3 AI Analyst Integration
1. Open the **AI Analyst Memo** tab.
2. Click **Generate Forensic Incident Memo**.
3. Wait for the loading indicators.
4. Confirm the memo finishes with Gemini-backed output, or clearly reports the structured timeout fallback if Gemini exceeds the app-level guard.

### 5.4 Report Compiler & Print Layouts
1. Go to the **Report Builder** tab.
2. Check that the Report Readiness score correctly registers the validated signal and investigator details.
3. Add custom text to the Analyst Notes field.
4. Click **Print / Export PDF**.
5. Confirm the print overlay displays only the structured report, hiding application navigation headers and action controls.
6. Confirm browser/headless PDF output is not blank and contains the report title, evidence summary, findings table, analyst memo if linked, validation notes, and limitations.

---

## Phase 6: Rollback Procedures

If issues are detected on the production deployment:

1. **Immediate Reversion**: Revert the hosting environment to the last known stable commit hash in your main or release branch.
2. **Key Rotation**: If a key exposure is suspected, immediately rotate your `GEMINI_API_KEY` within the Google AI Studio or Cloud Console settings.
3. **Log Review**: Inspect standard standard-out/standard-error streams on your hosting provider to isolate relative path errors, missing modules, or API exceptions.
