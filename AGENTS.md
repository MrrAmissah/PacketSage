# Agent Custom Instructions: Prince Product UI Design System

This file defines the **Prince Product UI** design language, rules, tokens, and components for this project. The system automatically injects these instructions to guide all UI/UX edits, styling, and structural design choices.

---

# DESIGN LANGUAGE: "Prince Product UI"
**Feel:** Clean, modern, premium-but-quiet, structured, trustworthy, practical. Strong whitespace, readable cards, clear hierarchy. Ideal for fintech, cybersecurity, civic tools, dashboards, and reporting products.

---

## 1. CORE COLOR SKIN: "Cool Trust"
PacketSage utilizes the **Cool Trust** visual profile (cybersecurity / operations-console style):
- **Canvas:** `#0b0f19` (Deep Slate/Navy page background)
- **Panel / Card:** `#0f172a` (Slate-900 surface card)
- **Raised / Inset:** `#1e293b` (Zebra rows, inputs, chips)
- **Edge / Border:** `#1e293b` (Slate-800 subtle borders)
- **Edge Strong / High:** `#334155` (Emphasized border)
- **Fore (Primary text):** `#f1f5f9` (Light Slate)
- **Fore-2 (Secondary text):** `#cbd5e1` (Muted Slate)
- **Fore-3 (Muted text):** `#94a3b8` (Gray-400 helper/labels)
- **Accent:** `#0062f1` (Primary Action Blue)
- **Accent Dark:** `#0052d4` (Hover/active state)
- **Accent Soft:** `#1a2c4e` (Blue-900 tinted background)
- **Accent Sky:** `#2f95ea` (Lighter accent)
- **Navy Deep:** `#0c1d3a` (Deep operations-console header/sidebar/raised element)
- **Semantic Statuses:**
  - `success` / `ok`: `#10b981` (emerald)
  - `warning` / `warn`: `#f59e0b` (amber)
  - `danger` / `error`: `#ef4444` (rose)
  - `critical` / `review`: `#a855f7` (purple)

---

## 2. NON-NEGOTIABLE UI/UX RULES
1. **Card is the base unit:** Every card must use `rounded-2xl border border-edge bg-panel shadow-sm hover:shadow-md transition-all duration-200`. Use soft, low, navy-tinted shadows only. NEVER harsh black shadows.
2. **Consistent Radius System:** 
   - Controls/buttons: `rounded-lg` (8px)
   - Inputs / Small cards: `rounded-xl` (12px)
   - Default cards / Panels / Sidebars: `rounded-2xl` (16px)
   - Badges / Pills: `rounded-full` (9999px)
   - Special hero or document cards: `rounded-[1.2rem]` / `rounded-[28px]`
3. **Typography (Inter only):** Smooth tracking, high weight contrast. Eyebrow labels must be `text-[11px] font-bold uppercase tracking-[0.16em] text-fore-3` over a bold value. All numbers must use monospaced figures `tabular-nums`.
4. **Layout & Grid Strategy:** Collapses to single column on mobile, responsive sm/md/lg. Desktop dashboards lead with visual hierarchy: Header (title + subtitle + actions) -> Stat Cards -> Table/Visualizers.
5. **Color-Code Status Map:**
   - Slate: Neutral / Pending
   - Sky / Blue: Active / Info
   - Emerald / Teal: Success / Verified / Safe
   - Amber / Gold: Warning / Waiting
   - Rose: Error / Disputed
   - Purple / Violet: Critical Risk
6. **Assistive Notes & Calm Warnings:** Use a calm disclaimer or assist note (`rounded-xl border border-accent/20 bg-accent-soft px-4 py-3 text-xs leading-relaxed text-fore-3`) for system/AI limitations. Never print alarming red walls.
7. **Complete Async States:** Every asynchronous load must have 3 real states:
   - **Loading:** A skeleton layout matching the loaded card shape.
   - **Empty:** Centered icon, descriptive title, call-to-action, or specific next step.
   - **Error:** Reassuring alert box with a retry action.
8. **No Futuristic Cyber Decoration Clichés:** No unnecessary scanlines, HUD frames, glowing matrix rains, fake terminal logs, or system coordinates. Keep labels literal, professional, and clean.

---

## 3. COMPONENT CONVENTIONS

### AppShell & Nav
- Sticky header translucent: `bg-slate-950/80 backdrop-blur-md border-b border-slate-900`.
- Left-hand navigation highlights active tabs with an accent tint: `bg-accent/15 text-blue-400 font-semibold border-l-2 border-accent`.

### StatCards
- Minimum height `min-h-[112px]`. Includes an icon tile, an uppercase label, a big bold value, and a tiny sub-note with metadata.

### RiskCard / Assessment
- Thin top-accent bar colored by risk level (emerald, amber, rose, or purple).
- Weighted list of factors with clean mono offset tags (`+2`, `+5`).

### DataTables
- Rounded-xl layout with hidden overflow. Use `thead` on `bg-raised` (or `bg-navy` with white uppercase headers for reports). Table transitions into card-stack on small screens.

### Report Builder (ReportPreview)
- Print-clean view utilizing `@media print` directives to hide navigation, action buttons, and force standard clean typography for high-quality export or printing.

---

## 4. DESIGN TOKENS (Tailwind Theme Integration)
Add the token variables to the `@theme` declaration in CSS to expose roles (`bg-canvas`, `bg-panel`, `border-edge`, `text-fore`, `text-fore-2`, `text-fore-3`, `bg-accent`, etc.) to make styling consistent and re-skinnable.
