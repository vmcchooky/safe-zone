# Safe Zone UI/UX Redesign Brief

This redesign brief outlines the visual, interaction, and technical guidelines for refactoring the user interfaces of the Safe Zone system. It provides a cohesive plan to transition the existing user interfaces into a premium, calm, and lightweight design language without introducing heavy frameworks or breaking backend API contracts.

> **Current scope:** The primary React UI is now maintained under `ui/` and served at `/app/*`. The legacy template references in this brief are retained for compatibility work on `/dashboard`, `/block`, and their embedded assets under `internal/api/`.

---

## 1. Product Identity

**Safe Zone** is a local-first anti-phishing and safe browsing control system. It helps users inspect risky domains, block malicious destinations, monitor threat feed freshness, and operate a small self-hosted protection stack.

*   **Primary User**: Self-hosting technology operators, home laboratory administrators, and small-business network security managers who prioritize high-efficiency, privacy-preserving, and low-overhead protection.
*   **Main User Goals**:
    1.  Perform quick lexical and OSINT-linked hazard queries on suspicious domains.
    2.  Maintain threat feed sync health and inspect background automated agent states.
    3.  Manage client grouping definitions, device IP mappings, and custom whitelist/blacklist overrides.
    4.  Provide network clients with clear, non-alarmist block explanations when malicious requests are sinkholed.
*   **Emotional Tone**: 
    *   **Calm**: Soft colors, flat controls, and clear metrics. Avoid loud alerts, sirens, and alarmist graphics.
    *   **Secure**: High structural order, precise statistical reports, and transparent policy indicators that inspire operator trust.
    *   **Minimal**: Clear workspaces that reduce sensory noise. Layout elements should appear lightweight and highly efficient.
    *   **Operational**: Professional control console aesthetics. Focuses on data density and clear indicators rather than graphical fluff.
*   **What the Product Should NOT Feel Like**:
    *   **Not Cyberpunk / Hacker Aesthetic**: No glowing grid arrays, Matrix code rain, neon console fonts, or dark web silhouettes.
    *   **Not Noisy / Distracting**: No unnecessary background bubble animations, layout-shifting transitions, or colorful elements with low usability.
    *   **Not Fearmongering / Alarmist**: Redundant locks, exclamation graphics, and large crimson warnings are banned. Threat reports must be presented neutrally and factually.

---

## 2. Current User-Facing Surfaces

The following table lists every user-facing surface identified in the codebase and documented inside [docs/ui-inventory.md](file:///d:/Quorix/services/safe-zone/docs/ui-inventory.md):

| Surface | Source Files | Purpose | Main User Action | Data Displayed | Current Limitations |
| --- | --- | --- | --- | --- | --- |
| **Login Portal** | `internal/api/views/login.html` | Authenticate administrator sessions | Enter identity name and password, submit to initiate session cookie | Form controls, Connection statuses, Credentials input | Uses the shared embedded local CSS assets; visually disconnected from the custom CSS elements in the primary dashboard shell. |
| **Dashboard Shell** | `internal/api/views/dashboard.html` | Primary control console navigation container | Swap views via tab selectors, monitor health pills, trigger logouts | Service status indicators (`core-api`, `cache`, `rate limit`), overview metrics (Total, Safe, Suspicious, Malicious, Cache hits), Tab selections | Relies on generic emojis as navigation buttons; has custom floating canvas bubble graphics that clash with a calm utility theme. |
| **Domain Analyzer** | `internal/api/views/dashboard.html` | Input target domains for live threat scoring | Enter domain name, click "Analyze" or hit Enter, trigger forced OSINT checks | Query input field, Submission button, OSINT trigger button | Interactive states lack visual indicators; uses hardcoded inline styles in form tags. |
| **Risk Result Panel** | `internal/api/views/dashboard.html` | Renders domain verdicts, scores, and whitelisting panels | Type whitelisting reason, click "Allow / whitelist domain" button | Uppercase verdict string (`SAFE`, `SUSPICIOUS`, `MALICIOUS`), score (e.g. 85/100), reasons list, evidence details cards, operator whitelisting review form | Result layouts are plain bullet points; whitelisting buttons have no loading states; contains mixed Vietnamese locales in review panels. |
| **Telemetry Tab** | `internal/api/views/dashboard.html` | Review verdict distribution trends and historic queries | Change statistical range (24h/7d/30d), click pagination page buttons | Dynamic doughnut chart, total counts metrics, tabular query history (Domain, Verdict, Score, Source, Analyzed At, action links) | Chart.js visual slice colors are hardcoded as HEX strings in JavaScript; pagination uses simple links; tabular listings have poor responsive wrapping on small devices. |
| **Overrides Tab** | `internal/api/views/dashboard.html` | Manage global allowed and blocked domain lists | Add domain override (domain, action, reason), delete existing overrides | Input fields, Action overrides filter selections, list table displaying domain, action badge, reason, updated time, deletion buttons | Overrides lists use unstyled tables; form items utilize inline margin blocks; tables lack responsive scaling on mobile. |
| **Clients & Policies** | `internal/api/views/dashboard.html` | Configure policy groups, client mappings, and group rules | Create groups, modify parameters, select override scopes, add IP mappings, delete items | Group card details grid (categories list, strict settings), mappings tables, group overrides tabular list, popup edit modal form | Modal toggling relies on raw class insertions; forms feature complex inline grid settings; group cards display unstructured category details. |
| **System Health** | `internal/api/views/dashboard.html` | Inspect operational performance and manual agent overrides | View endpoint response average latencies, review background task schedules, trigger manual agent runs | Service health status indicators, latency metrics, task list arrays (State, Interval, Runs/Errors, Last Run, Next Run, Last Error) | Latencies are listed as raw integers without units; task tables overflow on narrow viewports; error strings are trimmed with no tooltips. |
| **Block Page Redirect** | `internal/api/views/block.html` | landing page shown when domains are blocked | Read blocking reason, fill false-positive ticket form (contact details, note), click submit | Warning eyebrow, blocked destination, requested path, blocking category, reason text, Request ID, support email, false-positive inputs | Visually dated compared to main dashboard; forms perform full-page browser redirects on submit instead of seamless AJAX fetches. |
| **Panic Recovery Page** | `internal/serve/http.go` | Fallback display returned during critical panics | View crash dumps, click "Quay Lại Dashboard" link to return to portal | HTTP 500 header, system panic description, monospace Go stack trace box | HTML is embedded as a raw string literal inside Go source code; page is entirely in Vietnamese ("Hệ Thống Gặp Sự Cố"), clashing with the dashboard's English. |

---

## 3. Target Design Direction: Calm Security Glass

The selected visual theme for the Safe Zone redesign is **Calm Security Glass**. This direction creates a high-contrast, clean, and modern dark interface that conveys stability, speed, and professionalism.

### Visual Elements to Include
*   **Dark Navy Security Atmosphere**: Set the baseline canvas background to a deep, dark indigo-navy tint (`#090d16` to `#0d121f`). This theme reduces eye strain and establishes a professional control console environment.
*   **Minimalism**: Maintain plenty of negative space. Remove decorative borders, decorative icons, and unnecessary dividers. Focus strictly on aligning telemetry and dashboard data cleanly.
*   **Glassmorphism**: Use translucent surfaces with soft borders (`rgba(255, 255, 255, 0.05)`) and background blurs (`backdrop-filter: blur(12px)`). This creates a premium layered feel.
*   **Soft Depth**: Stack elements logically using depth layers. Background panels appear flat, while overlay dialogs and active widgets have subtle shadows and highlights.
*   **Subtle Gradients**: Apply slow, wide gradients to cards and action panels to guide the user's attention. Avoid high-contrast color shifts.
*   **Clear Typography Hierarchy**: Use high-contrast headers, muted labels for captions, and highly legible monospace fonts for tabular records, code fragments, and domain strings.
*   **Tactile Interactions**: Inputs, buttons, and rows should respond instantly to mouse hovers and clicks with subtle outline glows, background changes, or slight vertical compressions.
*   **Calm Animations**: Restrict motion to visual transitions, such as slow tab switches (`fadeIn 0.2s`), soft alert fade-ins, and clean loading skeletons.
*   **Strong Risk-State Clarity**: Make risk levels unmistakable using consistent styling: green for safe, orange for suspicious, and red for malicious. Keep these highlights localized and clean.
*   **Operational Control Plane Feel**: Design interfaces to look like professional telemetry dashboards. Prioritize high data density and clean metrics over graphical embellishments.

### Visual Elements to AVOID
*   **No Cyberpunk / Hacker Aesthetic**: No matrix rains, gridlines, neon green accents, hazard stripes, or glowing crosshair decals.
*   **No Heavy Neon Glows**: Do not add glowing drop-shadows under text or inputs. Borders should remain clean.
*   **No Matrix Rain or Excessive Particles**: The background canvas particle animation must be disabled or replaced with static, soft dark gradients.
*   **No Fear-Based Warning Designs**: No warnings with flashing elements, generic exclamation icons, or screens saturated in bright red. Warnings must remain objective and informative.
*   **No Heavy Animation Libraries**: Animations must be implemented using native CSS transitions. Do not add heavy external animation libraries.
*   **No Large Frontend Frameworks**: Do not refactor the dashboard into React, Vue, Svelte, or Next.js. Keep the codebase lightweight by using vanilla JavaScript and HTML templates.

---

## 4. Visual Language

The visual language of the Calm Security Glass theme is defined by consistent colors, typography, shapes, and animations:

### Color Mood
```
Primary Canvas (Background) : Deep Indigo-Navy   -> HSL(225, 40%, 6%)   [#06080d]
Secondary Elevation Surfaces: Semi-Translucent   -> HSLA(220, 30%, 10%, 0.5)
Border Outlines             : Subtle Translucent -> HSLA(0, 0%, 100%, 0.06)
High-Contrast Text          : Pure White / Silver -> HSL(210, 20%, 95%)  [#eff1f5]
Muted Text Labels           : Slate Grey         -> HSL(215, 15%, 60%)  [#8a94a6]
System Accent Glow          : Ice Blue           -> HSL(210, 90%, 65%)  [#54a3ff]
System Accent Soft          : Soft Blue Glow     -> HSLA(210, 90%, 65%, 0.1)

Risk State: SAFE            : Emerald Green      -> HSL(150, 75%, 45%)  [#1dbf73]
Risk State: SAFE-SOFT       : Soft Emerald Tint  -> HSLA(150, 75%, 45%, 0.08)
Risk State: SUSPICIOUS      : Muted Amber        -> HSL(35, 85%, 50%)   [#df961a]
Risk State: SUSPICIOUS-SOFT : Soft Amber Tint    -> HSLA(35, 85%, 50%, 0.08)
Risk State: DANGER/MALICIOUS: Crimson Rose       -> HSL(345, 80%, 55%)  [#f23d6c]
Risk State: DANGER-SOFT     : Soft Crimson Tint  -> HSLA(345, 80%, 55%, 0.08)
Risk State: INFO            : Celestial Slate    -> HSL(200, 20%, 75%)  [#b3c0cc]
Risk State: INFO-SOFT       : Soft Celestial Tint-> HSLA(200, 20%, 75%, 0.08)
```

### Typography
*   **Baseline Fonts**:
    *   **Body & Headings**: `Inter`, `system-ui`, `-apple-system`, `BlinkMacSystemFont`, `sans-serif`. High readability at small sizes.
    *   **Monospace**: `Fira Code`, `SFMono-Regular`, `Consolas`, `monospace`. Reserved for domain inputs, JSON logs, tables, metrics, and network configurations.
*   **Sizing & Weights**:
    *   **Main Title / Hero**: `2.0rem` (bold, weight 700), tracking `-0.02em`.
    *   **Section Headers**: `1.15rem` (medium-bold, weight 600), tracking `-0.01em`.
    *   **Body text**: `0.85rem` (regular, weight 400), line-height `1.55`.
    *   **Muted Labels / Details**: `0.72rem` (medium-semibold, weight 600), tracking `0.06em`, forced uppercase.
    *   **Tabular / Monospace Code**: `0.8rem` (weight 450).
*   **Visual Treatment**: Keep headers white (`#ffffff`). Body and numeric values should use light grey (`#eff1f5`). Captions, labels, and table headers should use muted slate-grey (`#8a94a6`).

### Shape and Depth
*   **Border Radius**:
    *   **Outer Layout Shell**: `20px` border-radius for main containers.
    *   **Standard Cards / Modals**: `16px` border-radius.
    *   **Inputs / Action Buttons**: `10px` border-radius.
    *   **Status Pills / Badges**: `9999px` (fully rounded capsule pill).
*   **Glass Panels**: Apply `backdrop-filter: blur(12px) saturate(180%);` and `-webkit-backdrop-filter: blur(12px) saturate(180%);`. Outlines must remain thin (`1px solid rgba(255, 255, 255, 0.06)`).
*   **Dividers**: Avoid solid border lines. Use dashed borders (`1px dashed rgba(255, 255, 255, 0.06)`) or empty margin buffers.
*   **Shadows**: Use clean shadows instead of colored glows.
    *   **Standard card shadow**: `0 8px 30px 0 rgba(0, 0, 0, 0.4)`.
    *   **Overlay modal shadow**: `0 24px 60px 0 rgba(0, 0, 0, 0.6)`.

### Motion & Transitions
*   **Tab switches**: Smooth horizontal slide-ins using `transform: translateX(...)` combined with opacity fade-ins (`transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1)`).
*   **Hover effect**: Elements should scale slightly (`transform: translateY(-1px)`) and increase their outline border opacity from `0.06` to `0.14`.
*   **Active Click / Pressed**: Scale down slightly (`transform: scale(0.985) translateY(0.5px)`), and reduce hover shadows.
*   **Focus Outline**: Display an explicit focus outline using an ice-blue border (`1px solid var(--sz-accent)`) and a subtle blue shadow. Do not rely on default browser focus outlines.
*   **Loading state**: Use soft shimmering skeletons (`@keyframes shimmer`) fading between `0.05` and `0.15` opacity. Avoid spinning icons.
*   **Reduced-Motion Override**: Check for reduced motion settings (`@media (prefers-reduced-motion: reduce)`) to disable transforms, lasers, and shockwaves, falling back to simple opacity transitions.

### Interaction Feel
The interface should feel tactile, fast, and responsive:
*   Hovering over buttons, tab selectors, or tables should trigger immediate, subtle highlight changes.
*   Clicking should provide instant visual feedback (using scale shrink and active borders).
*   Inputs should glow cleanly on focus, and input submissions should render loading skeletons immediately.
*   Errors and notifications should fade in smoothly and remain readable.

---

## 5. Design Principles

Below are the 12 core design principles that must guide the Safe Zone redesign:

1.  **Security Must Feel Calm, Not Alarmist**: Inform operators using objective data and clear statistics. Do not use flashing alerts, warning sirens, or fear-based copy.
2.  **Visual Risk-State Distinction**: Ensure that `SAFE` (green), `SUSPICIOUS` (orange), and `MALICIOUS` (red) states are instantly recognizable. Maintain high contrast between status badges and backgrounds.
3.  **UI Must Be Fast and Lightweight**: Keep the dashboard fast and performant by avoiding heavy libraries or unnecessary client-side processing.
4.  **Motion Must Clarify State, Not Decorate**: Animations should only be used to indicate changes in state (such as tab switches, loading states, or validation alerts). Do not add purely decorative animations.
5.  **Interactive Elements Require Complete State Modeling**: Every button, input, and interactive row must support five distinct visual states: default, hover, active (clicked), focus-visible, disabled, and loading.
6.  **Prioritize Operational Clarity**: Ensure the dashboard remains dense and informative. Arrange layout cards and grids to present critical information clearly on a single page.
7.  **Informative, Non-Alarmist Block Page**: Explain the policy reason for sinkholed domains objectively. Avoid warnings that create unnecessary panic.
8.  **Strict Protection of Backend API Contracts**: Do not modify endpoint URLs, HTTP methods, JSON key properties, or cookies during the redesign. Keep all API contracts unchanged.
9.  **Zero Heavy Visual Dependencies**: Do not import heavy libraries (such as Framer Motion, GSAP, or dynamic CSS frameworks) for animations. Use vanilla CSS and CSS variables.
10. **Accessibility First, Not Patchwork**: Ensure high color contrast, full keyboard navigation compatibility, and explicit focus states across the entire application.
11. **Responsive, Mobile-First Scaling**: Layout grids must wrap cleanly into single-column cards on smaller viewports. Telemetry tables should support horizontal scrolling without breaking the container wrapper.
12. **Protection of DOM Selectors**: Keep all current DOM IDs and CSS class bindings intact to prevent JavaScript references from breaking.

---

## 6. Proposed Information Architecture

Below is the proposed layout structure for the Safe Zone control panel dashboard and pages:

```
+-------------------------------------------------------------------------------+
| App Shell / Top Bar                                                           |
| [Logo] Safe Zone  (API: Healthy)  (Cache: Connected)    [Admin] [🚪 Logout]   |
+-------------------------------------------------------------------------------+
| Tab Navigation: [🔍 Analysis] [📊 Telemetry] [🛡 Overrides] [👥 Clients] [⚙️ System] |
+-------------------------------------------------------------------------------+
| App Content Area                                                              |
|                                                                               |
|  +-------------------------------------+  +---------------------------------+ |
|  | Domain Analyzer Toolbar             |  | Threat Feed Status              | |
|  | [ Enter domain name       ] [Search]|  | Sources: 4 | Freshness: 2h ago  | |
|  +-------------------------------------+  +---------------------------------+ |
|                                                                               |
|  +-------------------------------------+  +---------------------------------+ |
|  | Risk Result Panel                   |  | Recent Queries / Activity       | |
|  | Verdict: MALICIOUS (95%)            |  | • bad-domain.com   [MALICIOUS]  | |
|  | Score  : 85/100                     |  | • safe-domain.com  [SAFE]       | |
|  | Signals: matched local threat feed  |  | • test-domain.com  [SUSPICIOUS] | |
|  +-------------------------------------+  +---------------------------------+ |
|                                                                               |
+-------------------------------------------------------------------------------+
```

The table below outlines the implementation status and files for each dashboard section:

| Area | Purpose | Current Status | Source Files | Notes |
| --- | --- | --- | --- | --- |
| **App Shell / Top Bar** | Renders header logo, summary stats, health badges, and logout controls. | Exists | `internal/api/views/dashboard.html` | Redesign to replace emojis with clean typographic indicators. |
| **Protection Overview** | Renders top statistics cards (Total, Safe, Suspicious, Malicious, Cache). | Exists | `internal/api/views/dashboard.html` | Improve the typography and colors of stats cards. |
| **Domain Analyzer** | Text input form for domain queries. Includes check and force OSINT triggers. | Exists | `internal/api/views/dashboard.html` | Clean up form structures and remove inline styling. |
| **Risk Result Panel** | Renders query results, threat levels, OSINT evidence, and whitelisting forms. | Exists | `internal/api/views/dashboard.html` | Redesign whitelisting actions. Whitelist textarea must retain ID `#fp-review-reason`. |
| **Threat Feed Status** | Shows active threat feed sync health. | Partially Exists | `cmd/core-api/main.go` <br> `internal/api/views/dashboard.html` | Currently displayed as health badges in the top bar. Improve visibility on the dashboard. |
| **DNS/Policy Status** | Shows active DoH server configuration settings. | Unknown from current code | `cmd/core-api/main.go` | The DoH resolver runs as a separate binary (`dns-resolver`), but its runtime statistics are not currently queried by the core-api dashboard. Keep as a future enhancement. |
| **Agent/System Controls** | Displays active background tasks and manual trigger controls. | Exists | `internal/api/views/dashboard.html` | Redesign latencies list and wrap task error strings with tooltips. |
| **Recent Events / History** | Displays list of recent domain queries. | Exists | `internal/api/views/dashboard.html` | Style recent item cards as clean rows with colored badges. |
| **Block Page Redirect** | Warning landing page shown when domains are blocked. | Exists | `internal/api/views/block.html` <br> `internal/api/handlers/block.go` | Retain all standard Go template variables. Update layout grid. |

---

## 7. Component Inventory Proposal

The redesigned interface will rely on a modular library of reusable CSS classes and HTML components:

| Component | Purpose | States | Used In | Implementation Note |
| --- | --- | --- | --- | --- |
| **`AppShell`** | Overall layout wrapper. Centered column container. | default | `dashboard.html`, `block.html` | CSS class: `max-w-[var(--sz-container-max)] mx-auto px-4`. |
| **`TopBar`** | Sticky header bar. Handles brand, health status, and logout button. | default | `dashboard.html` | Glassmorphic panel header. Uses flex layout alignment. |
| **`GlassCard`** | Translucent backdrop card container for content panels. | default, hover | `dashboard.html`, `block.html` | CSS class: `.sz-card` with backdrop blur, soft shadows, and light borders. |
| **`Button`** | Standard action trigger button. | default, hover, active, focus-visible, disabled, loading | `dashboard.html`, `login.html`, `block.html` | CSS class `.sz-btn` with transitional glows and active click shrinkage. |
| **`IconButton`** | Small square action buttons (e.g. edit/delete icons). | default, hover, active, focus-visible, disabled | `dashboard.html` | HTML pattern. Uses SVG vectors instead of text or emojis. |
| **`Input`** | Monospace text inputs, selections, and textareas. | default, hover, focus, disabled | `dashboard.html`, `login.html`, `block.html` | CSS class `.sz-input` using `Fira Code` with blue focus rings. |
| **`StatusPill`** | Small capsule badge for health status (e.g. API connected, caching idle). | ok, warn, bad, default | `dashboard.html` | CSS class `.sz-pill`. Capsule pill format using monospace typography. |
| **`RiskBadge`** | High-contrast category tag indicating domain risk. | safe, warning, danger | `dashboard.html` | Capsule pill format. Highlight colors must match HSL risk tokens. |
| **`RiskMeter`** | Visual gauge or bar showing threat scores (e.g. 85/100). | safe, warning, danger | `dashboard.html` | CSS class `.sz-meter`. Visual indicator bar showing score scale. |
| **`MetricTile`** | Display tile for overview stats (Total, Safe, Suspicious, Malicious). | default, hover | `dashboard.html` | HTML pattern. Highlighted numbers using large monospace fonts. |
| **`SectionHeader`** | Panel section titles. Handles text and right-aligned button group filters. | default | `dashboard.html` | HTML layout utility. Flex alignment. |
| **`EmptyState`** | Placeholder banner shown when no results or logs exist. | empty | `dashboard.html`, `block.html` | CSS class `.sz-empty`. Centered layout with muted grey typography. |
| **`LoadingSkeleton`** | Shimmering placeholders shown during data fetches. | loading | `dashboard.html` | CSS class `.sz-skeleton` with keyframe opacity pulsing. |
| **`InlineAlert`** | Inline warning alerts or notifications (e.g. report saved success card). | safe, warning, danger | `block.html`, `dashboard.html` | HTML panel pattern. Soft background colors with clear border lines. |
| **`EventList`** | Historic event feed lines. | default, hover | `dashboard.html` | HTML row lists with thin dashed border dividers. |
| **`BlockPagePanel`** | Core content grid on the sinkhole block screen. | default | `block.html` | Two-column asymmetric layout. Displays block details. |
| **`SegmentedNav`** | Nav tab bar for switching dashboard views. | default | `dashboard.html` | Flex container card. Handles selection highlights. |
| **`Toast`** | Floating notification popup card. | ok, err, default | `dashboard.html`, `login.html` | Fixed positioning in bottom-right corner. Automatically fades out. |

---

## 8. Proposed Design Tokens

The visual system will be configured using standard CSS variables prefixing `--sz-`. These tokens will reside under `:root` inside `safe-zone.css`:

### 1. Colors
```css
--sz-bg:             #06080d;             /* Deep indigo-black canvas */
--sz-bg-elevated:    #0c101a;             /* Elevated background panels */
--sz-surface:        rgba(12, 16, 26, 0.5);/* Glassmorphic card backdrop */
--sz-surface-strong: rgba(12, 16, 26, 0.85);/* High-density overlay surfaces */
--sz-border:         rgba(255, 255, 255, 0.06);/* Thin container border */
--sz-border-strong:  rgba(255, 255, 255, 0.15);/* Hover highlight border */

--sz-text:           #eff1f5;             /* Primary text (light grey) */
--sz-text-muted:     #8a94a6;             /* Muted text (slate-grey) */
--sz-accent:         #54a3ff;             /* Accent color (ice blue) */
--sz-accent-soft:    rgba(84, 163, 255, 0.08);/* Accent background tint */

--sz-safe:           #1dbf73;             /* Safe verdict (Emerald green) */
--sz-safe-soft:      rgba(29, 191, 115, 0.08);/* Safe background tint */
--sz-warning:        #df961a;             /* Suspicious verdict (Amber) */
--sz-warning-soft:   rgba(223, 150, 26, 0.08);/* Suspicious background tint */
--sz-danger:         #f23d6c;             /* Malicious verdict (Crimson) */
--sz-danger-soft:    rgba(242, 61, 108, 0.08);/* Malicious background tint */
--sz-info:           #b3c0cc;             /* Info notification (Slate) */
--sz-info-soft:      rgba(179, 192, 204, 0.08);/* Info background tint */
```

### 2. Typography
```css
--sz-font-sans:     'Inter', system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
--sz-font-mono:     'Fira Code', SFMono-Regular, Consolas, monospace;

--sz-text-xs:        0.72rem;
--sz-text-sm:        0.8rem;
--sz-text-md:        0.85rem;
--sz-text-lg:        1.15rem;
--sz-text-xl:        1.5rem;
--sz-text-2xl:       2.0rem;
--sz-line-height:    1.55;
```

### 3. Spacing
```css
--sz-space-1:        4px;
--sz-space-2:        8px;
--sz-space-3:        12px;
--sz-space-4:        16px;
--sz-space-5:        20px;
--sz-space-6:        24px;
--sz-space-8:        32px;
--sz-space-10:       40px;
```

### 4. Border Radius
```css
--sz-radius-sm:      6px;
--sz-radius-md:      10px;                /* Buttons, inputs */
--sz-radius-lg:      16px;                /* Standard cards, tables */
--sz-radius-xl:      20px;                /* Main layout outer wrappers */
--sz-radius-pill:    9999px;              /* Status pills and badges */
```

### 5. Shadows & Blur
```css
--sz-shadow-soft:    0 4px 20px 0 rgba(0, 0, 0, 0.25);
--sz-shadow-card:    0 8px 30px 0 rgba(0, 0, 0, 0.4);
--sz-shadow-danger:  0 8px 30px 0 rgba(242, 61, 108, 0.1);
--sz-blur-glass:     blur(12px);
```

### 6. Motion & Animation
```css
--sz-motion-fast:    0.12s;
--sz-motion-normal:  0.22s;
--sz-motion-slow:    0.4s;
--sz-ease-out:       cubic-bezier(0.16, 1, 0.3, 1);
--sz-ease-spring:    cubic-bezier(0.34, 1.56, 0.64, 1);
```

### 7. Layout Metrics
```css
--sz-container-max:  1240px;
--sz-sidebar-width:  360px;
--sz-topbar-height:  64px;
--sz-z-header:       100;
--sz-z-toast:        1200;
--sz-z-modal:        1000;
```

---

## 9. State Model

The redesigned UI must support the following visual, typography, and accessibility states:

### 1. Domain Analysis States
*   **Idle**:
    *   *Visual*: Analysis results card displays an empty card `#result` containing `.sz-empty` with the text `"Awaiting input..."`.
    *   *Tone*: Informative and neutral.
    *   *User Action*: User inputs a domain in `#domain-input`.
    *   *Accessibility*: Focus state outline remains on search field.
*   **Typing**:
    *   *Visual*: The domain analyzer input field outline highlights with ice-blue border.
    *   *Tone*: Neutral.
    *   *User Action*: Keypresses. Action button `#analyze-btn` remains enabled.
*   **Valid Input**:
    *   *Visual*: Input field outline remains clean. Search buttons are fully enabled.
    *   *Tone*: Neutral.
*   **Invalid Input**:
    *   *Visual*: Input field border shifts to amber warning (`var(--sz-warning)`) with a clean validation error message shown below.
    *   *Tone*: Helpful and clear.
    *   *User Action*: User corrects domain spelling.
*   **Loading**:
    *   *Visual*: Analyzer form and query buttons disable. Results panel shows a clean shimmering loading skeleton (`.sz-skeleton`) instead of the layout results.
    *   *Tone*: Neutral.
    *   *User Action*: Queries are locked.
    *   *Accessibility*: Add `aria-busy="true"` attribute to the results panel.
*   **Safe Result**:
    *   *Visual*: Renders a green card (`.safe-glow`) detailing verdict `SAFE` using Emerald Green tags (`var(--sz-safe)`).
    *   *Tone*: Clear and reassuring.
    *   *User Action*: Option to view logs or perform a new search.
*   **Suspicious Result**:
    *   *Visual*: Renders an orange card detailing verdict `SUSPICIOUS` using Amber tags (`var(--sz-warning)`). Whitelisting review panel appears.
    *   *Tone*: Objective. Detail exact trigger reasons clearly.
    *   *User Action*: Operator can whitelist or view evidence.
*   **Dangerous Result**:
    *   *Visual*: Renders a red card (`.danger-glow`) detailing verdict `MALICIOUS` using Crimson Red tags (`var(--sz-danger)`). Renders the false-positive review whitelisting block.
    *   *Tone*: Objective and clear.
    *   *User Action*: Operator can whitelist or inspect threat sources.
*   **Error**:
    *   *Visual*: Results container renders a clean inline alert block (`.sz-alert.danger`) detailing connection status or invalid payloads.
    *   *Tone*: Informative and direct.
    *   *User Action*: Click retry button.
*   **Timeout**:
    *   *Visual*: Renders a warning panel (`.sz-alert.warn`) indicating analysis connection timeout.
    *   *Tone*: Informative. Renders `"Analysis took too long to complete. Background checks are continuing."`
    *   *User Action*: Retry query.
*   **Empty History**:
    *   *Visual*: Recent Activity card displays `.sz-empty` with the text `"No cached history."`.

### 2. System/Agent States
*   **Enabled / Active**:
    *   *Visual*: Status badge displays a green circle outline pill with the text `● Active`.
    *   *Accessibility*: Text fallback reads `"Active"`.
*   **Disabled**:
    *   *Visual*: Status badge displays a grey circle outline pill with the text `○ Disabled`.
    *   *Tone*: Muted.
*   **Running**:
    *   *Visual*: Status badge inside task rows shows a soft flashing indicator with the text `Running`.
    *   *Accessibility*: Add `aria-live="polite"` update notification.
*   **Idle**:
    *   *Visual*: Status badge inside task rows displays a clean grey capsule label with the text `Idle`.
*   **Failed**:
    *   *Visual*: Status badge inside task rows displays a red outline tag with the text `Failed`. Hovering over the row displays the full error traceback in a clean tooltip popup.
    *   *Tone*: Informative.
*   **Last Run Stale**:
    *   *Visual*: Scheduled times column highlights in amber text to warn that background updates are running behind schedule.
    *   *Tone*: Informative.
*   **Unknown**:
    *   *Visual*: Renders `Unknown from current code` inside status values.

### 3. Threat Feed States
*   **Fresh**:
    *   *Visual*: Status pill in header displays `core-api healthy` (green). Status details in System panel read `● Fresh` (Emerald Green).
*   **Stale**:
    *   *Visual*: Status pill in header displays `core-api limited` (amber). Status details in System panel read `⚠ Stale` (Amber) to warn that threat feeds have not synced for 36+ hours.
    *   *Tone*: Helpful warning.
*   **Syncing**:
    *   *Visual*: Shows a shimmering update loader inside the status metrics.
*   **Failed**:
    *   *Visual*: Status pill displays `core-api limited`. System details read `✕ Sync Failed`.
    *   *Tone*: Helpful warning.

### 4. Block Page States
*   **Blocked Malicious Domain**:
    *   *Visual*: Warning eyebrow eyebrow displays `Safe Zone Protection`. Block details display domain and category `Malicious Destination` in crimson red text.
    *   *Tone*: Calm, direct, and non-alarmist. Renders: `"This request was blocked to protect your device from potential security risks."`
    *   *User Action*: Fill false-positive ticket form or return to safety.
*   **Blocked Suspicious Domain**:
    *   *Visual*: Block details display domain and category `Suspicious Destination` in amber warning text.
    *   *Tone*: Calm and objective.
*   **Missing Domain Parameter**:
    *   *Visual*: Warning eyebrow eyebrow displays `System Redirect`. Block details display `"the requested domain"` as domain value.
    *   *Tone*: Informative.
*   **Unknown Reason**:
    *   *Visual*: Renders: `Unknown from current code`.
*   **Safe Fallback Actions**:
    *   *Visual*: displays a clean, prominent button pointing to the operator's support email or safe internal landing resources.
    *   *Tone*: Helpful.

---

## 10. Proposed Redesign Phases

To safely implement the redesign without breaking functionality, split the project into 10 phases:

| Phase | Goal | Files Likely Touched | Acceptance Criteria | Manual Test Steps | What NOT to Touch |
| --- | --- | --- | --- | --- | --- |
| **Phase 0** | Inventory and brief | None | [docs/ui-inventory.md](file:///d:/Quorix/services/safe-zone/docs/ui-inventory.md) and [docs/ui-redesign-brief.md](file:///d:/Quorix/services/safe-zone/docs/ui-redesign-brief.md) must be complete, accurate, and fully aligned with the codebase. | Verify that both document files exist and can be read clearly in markdown view. | Do not edit any codebase source files. |
| **Phase 1** | Implement Design Tokens | `internal/api/assets/safe-zone.css` | Define all `--sz-` visual tokens globally under `:root` in `safe-zone.css`. | Load `/dashboard` and check the browser console to verify that `safe-zone.css` loads successfully without syntax errors. | Do not rename existing DOM selectors or modify HTML templates. |
| **Phase 2** | Base UI Primitives | `internal/api/assets/safe-zone.css` | Implement base CSS classes (`.sz-card`, `.sz-btn`, `.sz-input`, `.sz-pill`, `.sz-skeleton`, `.sz-alert`). | Test hover and active click focus animations on dummy elements inside the style sheet. | Do not edit Go template files or Javascript logic. |
| **Phase 3** | Redesign Dashboard Shell | `internal/api/views/dashboard.html`, `internal/api/assets/safe-zone.css` | Apply design shell variables. Replace emojis in navigation tabs with clean typography. Apply smooth active highlights to selected tabs. | Load `/dashboard` in the browser, verify health badge colors, and click through tabs to confirm they swap views cleanly. | Do not modify the `data-tab="..."` attributes or the `switchTab()` function bindings. |
| **Phase 4** | Redesign Domain Analyzer | `internal/api/views/dashboard.html`, `internal/api/assets/safe-zone.css` | Modernize the query text input and submission button, removing inline style attributes. | Click the analyzer search box, verify outline glows, input a test domain, click "Analyze", and verify search executes. | Do not rename DOM IDs `domain-input`, `analyze-form`, `analyze-btn`, or `osint-btn`. |
| **Phase 5** | Redesign Risk Results | `internal/api/views/dashboard.html`, `internal/api/assets/safe-zone.css` | Modernize results rendering (verdict color states, score gauges, evidence lists, and whitelisting review panel layout). | Query a known malicious domain, type a whitelisting note in the panel, click whitelist, and verify the domain is allowed. | Do not rename whitelisting note textarea ID `#fp-review-reason` or modify `submitFalsePositiveReview()` Javascript calls. |
| **Phase 6** | Redesign Telemetry & System Panels | `internal/api/views/dashboard.html`, `internal/api/assets/safe-zone.css` | Modernize stats cards, paginated tables, Overrides lists, policy groups grids, latencies tables, and agent schedule listings. | Navigate through Telemetry and Overrides tabs, verify table grid alignments, trigger an agent task run, and check system status. | Do not change JSON query structures or trigger mappings endpoints paths. |
| **Phase 7** | Redesign Block Page | `internal/api/views/block.html`, `internal/api/assets/safe-zone.css` | Style `/block` landing page cards and details tables. Implement AJAX submit for false-positive reports to prevent full-page reloads. | Visit `/block?domain=test.com`, enter a report note, submit the form, and verify that the page displays the success receipt without full-page reloads. | Do not touch Go template tokens (`{{.Domain}}`, etc.). |
| **Phase 8** | Responsive, Access, Motion Polish | `internal/api/assets/safe-zone.css`, HTML files | Apply responsive media queries, high-contrast states, keyboard tab indexes, and media query reduced motion triggers. | Resize browser viewports to mobile widths, navigate dashboard using Tab/Enter keys, and verify visual highlights. | Do not break routing contracts. |
| **Phase 9** | Cleanup & Documentation | `internal/api/assets/safe-zone.css`, `docs/qa/admin-dashboard-checklist.md` | Remove unused or duplicated legacy CSS styles. Compile a final release walkthrough documenting the redesign. | Perform a full project build (`go build ./...`) to ensure all compiled template files are 100% correct. | Do not alter backend logic. |

---

## 11. Prompt Plan for AI Coding Agents

Below is a series of precise, step-by-step prompts to guide an AI coding agent through the Safe Zone redesign:

### Prompt 1: Implement CSS Design Tokens
*   **Task**: Define all `--sz-` visual tokens globally under `:root` in `safe-zone.css` according to Phase 1.
*   **Input Files to Read First**: [docs/ui-redesign-brief.md](file:///d:/Quorix/services/safe-zone/docs/ui-redesign-brief.md) (Section 8), [internal/api/assets/safe-zone.css](file:///d:/Quorix/services/safe-zone/internal/api/assets/safe-zone.css)
*   **Files Allowed to Edit**: `internal/api/assets/safe-zone.css`
*   **Hard Rules**: Do not modify any HTML template files, Go controllers, or JavaScript.
*   **Acceptance Criteria**: All CSS variables must be declared in `:root` inside `safe-zone.css`.
*   **Manual Test Steps**: Start the Go application, load `/dashboard` in the browser, and verify in developer tools that all variables are declared under `:root`.

### Prompt 2: Define Base UI Primitives/Classes
*   **Task**: Implement base CSS classes (`.sz-card`, `.sz-btn`, `.sz-input`, `.sz-pill`, `.sz-skeleton`, `.sz-alert`) using the new tokens in `safe-zone.css` according to Phase 2.
*   **Input Files to Read First**: [docs/ui-redesign-brief.md](file:///d:/Quorix/services/safe-zone/docs/ui-redesign-brief.md) (Section 7 and 8), [internal/api/assets/safe-zone.css](file:///d:/Quorix/services/safe-zone/internal/api/assets/safe-zone.css)
*   **Files Allowed to Edit**: `internal/api/assets/safe-zone.css`
*   **Hard Rules**: Do not edit Go templates or JavaScript files.
*   **Acceptance Criteria**: CSS classes for base components are declared in `safe-zone.css` using the `--sz-` variables.
*   **Manual Test Steps**: Open `/dashboard` and check the stylesheet to ensure all baseline components compile cleanly.

### Prompt 3: Redesign Dashboard Shell & Header
*   **Task**: Redesign the main dashboard container shell, header bar, and navigation tab controls according to Phase 3.
*   **Input Files to Read First**: [internal/api/views/dashboard.html](file:///d:/Quorix/services/safe-zone/internal/api/views/dashboard.html), [internal/api/assets/safe-zone.css](file:///d:/Quorix/services/safe-zone/internal/api/assets/safe-zone.css)
*   **Files Allowed to Edit**: `internal/api/views/dashboard.html`, `internal/api/assets/safe-zone.css`
*   **Hard Rules**: Do not rename the navigation tab button classes (`.tab-btn`), `data-tab="..."` variables, or the tab IDs (`tab-btn-analysis`, etc.) used by JavaScript to toggle views.
*   **Acceptance Criteria**: The navigation buttons feature clean typography, visual hover indicators, and smooth transition animations.
*   **Manual Test Steps**: Load `/dashboard` and verify that clicking through tabs switches views smoothly without console errors.

### Prompt 4: Redesign Domain Analyzer Toolbar
*   **Task**: Redesign the domain query form input and search buttons, removing inline styles according to Phase 4.
*   **Input Files to Read First**: [internal/api/views/dashboard.html](file:///d:/Quorix/services/safe-zone/internal/api/views/dashboard.html), [internal/api/assets/safe-zone.css](file:///d:/Quorix/services/safe-zone/internal/api/assets/safe-zone.css)
*   **Files Allowed to Edit**: `internal/api/views/dashboard.html`, `internal/api/assets/safe-zone.css`
*   **Hard Rules**: Do not rename the form ID `#analyze-form`, input ID `#domain-input`, button ID `#analyze-btn`, or OSINT button ID `#osint-btn`.
*   **Acceptance Criteria**: Input fields display a clean ice-blue outline glow on focus, and query controls scale cleanly on mobile viewports.
*   **Manual Test Steps**: Focus on the domain search box, verify active outlines, type `test.com`, press Enter, and verify that domain analysis executes.

### Prompt 5: Redesign Analysis Risk Results Panel
*   **Task**: Redesign the dynamic results output panel, styling risk verdicts (`SAFE`, `SUSPICIOUS`, `MALICIOUS`), score indicators, threat evidence lists, and false-positive review whitelisting modules according to Phase 5.
*   **Input Files to Read First**: [internal/api/views/dashboard.html](file:///d:/Quorix/services/safe-zone/internal/api/views/dashboard.html) (functions `renderResult`, `renderEvidence`, and `renderFalsePositiveReviewPanel`), [internal/api/assets/safe-zone.css](file:///d:/Quorix/services/safe-zone/internal/api/assets/safe-zone.css)
*   **Files Allowed to Edit**: `internal/api/views/dashboard.html` (only the script block functions rendering HTML), `internal/api/assets/safe-zone.css`
*   **Hard Rules**: Do not rename the whitelisting notes textarea ID `#fp-review-reason` or modify `submitFalsePositiveReview()` function calls.
*   **Acceptance Criteria**: Verdict panels load colored risk tags with soft container shadows. Whitelisting submissions show simple loading indicators.
*   **Manual Test Steps**: Query `malicious-domain.com`, verify the layout of the risk details panel, type a note, click the whitelist button, and confirm the whitelisting completes successfully.

### Prompt 6: Redesign Telemetry History and Overrides Tables
*   **Task**: Style the telemetry summary tiles, paginated logs table, and Overrides listings according to Phase 6.
*   **Input Files to Read First**: [internal/api/views/dashboard.html](file:///d:/Quorix/services/safe-zone/internal/api/views/dashboard.html), [internal/api/assets/safe-zone.css](file:///d:/Quorix/services/safe-zone/internal/api/assets/safe-zone.css)
*   **Files Allowed to Edit**: `internal/api/views/dashboard.html`, `internal/api/assets/safe-zone.css`
*   **Hard Rules**: Do not rename statistical metric IDs (`st-total`, `st-safe`, etc.) or the Chart.js canvas target `#verdict-chart`.
*   **Acceptance Criteria**: All listing tables display clean dashed row borders. Telemetry status doughnut charts use the design tokens palette.
*   **Manual Test Steps**: Navigate to the Telemetry tab, change range selectors between 24h, 7d, and 30d, and check if statistics and charts render correctly.

### Prompt 7: Redesign Policy Groups, Mappings, and System Controls
*   **Task**: Style policy group cards, mapping input forms, group override controls, average latencies listings, and background agent scheduler lists according to Phase 6.
*   **Input Files to Read First**: [internal/api/views/dashboard.html](file:///d:/Quorix/services/safe-zone/internal/api/views/dashboard.html), [internal/api/assets/safe-zone.css](file:///d:/Quorix/services/safe-zone/internal/api/assets/safe-zone.css)
*   **Files Allowed to Edit**: `internal/api/views/dashboard.html`, `internal/api/assets/safe-zone.css`
*   **Hard Rules**: Do not rename mapping text input IDs or manual task trigger endpoints in JavaScript (`triggerAgentTask`).
*   **Acceptance Criteria**: Policy groups display as a responsive card grid. Client mapping forms and overrides tables scale cleanly on mobile viewports. Average latencies display with appropriate units.
*   **Manual Test Steps**: Navigate through "Clients & Policies" and "System" tabs, verify all grids and forms, click "Trigger" next to a background task, and verify execution completes.

### Prompt 8: Redesign Site Block Redirect Landing Page
*   **Task**: Style the block warning landing page cards and details grids according to Phase 7. Implement an asynchronous AJAX fetch for false-positive submissions to prevent full-page redirects.
*   **Input Files to Read First**: [internal/api/views/block.html](file:///d:/Quorix/services/safe-zone/internal/api/views/block.html), [internal/api/handlers/block.go](file:///d:/Quorix/services/safe-zone/internal/api/handlers/block.go), [internal/api/assets/safe-zone.css](file:///d:/Quorix/services/safe-zone/internal/api/assets/safe-zone.css)
*   **Files Allowed to Edit**: `internal/api/views/block.html`, `internal/api/assets/safe-zone.css`
*   **Hard Rules**: Do not modify Go template variables (`{{.Domain}}`, `{{.RequestedPath}}`, etc.) inside the HTML file. Form inputs must retain names `contact` and `note`.
*   **Acceptance Criteria**: The block redirect displays a clean warning eyebrow. False-positive tickets submit asynchronously via JavaScript `fetch` and render a receipt state inline without reloading the page.
*   **Manual Test Steps**: Visit `/block?domain=test.com`, enter a report, click submit, and verify that the page displays the success receipt without full-page reloads.

### Prompt 9: Implement Responsive Boundaries and Mobile Optimization
*   **Task**: Modernize media queries in `safe-zone.css` to support mobile viewports down to 360px according to Phase 8.
*   **Input Files to Read First**: [internal/api/assets/safe-zone.css](file:///d:/Quorix/services/safe-zone/internal/api/assets/safe-zone.css), HTML files
*   **Files Allowed to Edit**: `internal/api/assets/safe-zone.css`
*   **Hard Rules**: Do not modify any Go or JavaScript logic.
*   **Acceptance Criteria**: Tables support horizontal scrolling on mobile. Forms and cards wrap cleanly into a single-column layout on viewports <= 720px.
*   **Manual Test Steps**: Open `/dashboard` in mobile responsive preview, resize the viewport down to 360px, and check if all tabs, grids, and tables scale fluidly.

### Prompt 10: Implement Accessibility Focus and Reduced-Motion Polish
*   **Task**: Add high-visibility keyboard focus rings, semantic accessibility headers, and reduced-motion media query gates to disable heavy animations according to Phase 8.
*   **Input Files to Read First**: [internal/api/views/dashboard.html](file:///d:/Quorix/services/safe-zone/internal/api/views/dashboard.html), [internal/api/assets/safe-zone.css](file:///d:/Quorix/services/safe-zone/internal/api/assets/safe-zone.css)
*   **Files Allowed to Edit**: `internal/api/views/dashboard.html`, `internal/api/assets/safe-zone.css`, `internal/api/views/block.html`
*   **Hard Rules**: Do not touch backend endpoints.
*   **Acceptance Criteria**: Keyboard navigation allows users to cycle focus through all interactive elements using Tab/Enter. Active focus indicators display a highly visible outline. System lasers and shockwave animations respect user reduced-motion browser settings.
*   **Manual Test Steps**: Enable reduced-motion in system settings, trigger a domain analysis, and verify that visual lasers do not slide. Use keyboard navigation (`Tab` and `Enter` keys) to browse the dashboard.

### Prompt 11: Cleanup Duplicated and Obsolete CSS Styling
*   **Task**: Audit, consolidate, and remove any legacy styling rules, hardcoded pixel declarations, or duplicated CSS classes according to Phase 9.
*   **Input Files to Read First**: [internal/api/assets/safe-zone.css](file:///d:/Quorix/services/safe-zone/internal/api/assets/safe-zone.css)
*   **Files Allowed to Edit**: `internal/api/assets/safe-zone.css`
*   **Hard Rules**: Perform validation compiles (`go build ./...`) to ensure all modified styles load correctly.
*   **Acceptance Criteria**: Legacy colors and inline definitions are removed. All classes inherit exclusively from the `--sz-` variables.
*   **Manual Test Steps**: Verify all dashboard views to ensure visual regressions did not occur.

### Prompt 12: Compile Redesign Walkthrough and Developer Guide
*   **Task**: Create a detailed technical walkthrough document inside the `docs/` folder summarizing all design token structures, base component primitives, and implementation results.
*   **Input Files to Read First**: All edited frontend files
*   **Files Allowed to Edit**: `docs/qa/admin-dashboard-checklist.md`
*   **Hard Rules**: Create or update ONLY the walkthrough documentation file.
*   **Acceptance Criteria**: Walkthrough document is complete, accurate, and lists all visual tokens, class styles, and manuals for future developers.
*   **Manual Test Steps**: Verify that the document can be read cleanly.

---

## 12. Risks and Mitigations

The table below outlines the primary risks associated with an AI-assisted front-end redesign and the corresponding mitigation strategies:

| Risk | Why It Matters | Mitigation Strategy |
| --- | --- | --- |
| **AI alters backend contracts** | Changing REST paths (`/v1/*`) or parameter names (e.g. `domain`) will cause AJAX requests to fail, breaking core dashboard functionality. | Explicitly forbid the AI from modifying `main.go`, `dashboard.go`, or any route registration files. All API calls in JS must remain unchanged. |
| **AI duplicates CSS variables** | Adding duplicated visual declarations or hardcoded pixel definitions inside `safe-zone.css` bloats the stylesheet and makes maintenance difficult. | Enforce that all styles must inherit from the declared `--sz-` variables. Obsolete classes must be pruned. |
| **AI imports heavy external libraries** | Adding dependencies (such as tailwind npm packages or animation libraries) increases overhead and goes against the project's lightweight design. | Enforce the use of pure vanilla CSS transitions and variables. Prohibit adding imports to external script bundles. |
| **AI breaks embedded HTML templates** | Deleting Go template bindings (such as `{{.Domain}}` inside `block.html`) will cause server-side compilation crashes at render time. | Enforce a strict policy to preserve Go template blocks exactly. Always run `go build ./...` after modifying HTML templates. |
| **AI renames DOM selectors** | JavaScript relies on exact DOM element IDs to target and write dynamic values (e.g. `recentEl`). Renaming these will cause JavaScript exceptions. | Mark all critical selectors as protected. Do not allow the AI to rename key DOM IDs used by the script block. |
| **AI makes warnings fearmongering** | Over-saturating the block screen with alarmist warnings can create unnecessary panic for users. | Block layouts must remain calm, objective, and informative. Inform users neutrally. |
| **AI over-animates the UI** | Adding excessive visual movements, spin transitions, or sliding lasers can cause distractions and impact accessibility. | Restrict animations to slow transitions (such as tab switches and loading skeletons) and respect user reduced-motion settings. |
| **AI breaks keyboard focus** | Removing outline borders on focused items makes keyboard navigation difficult for screen readers and keyboard users. | Enforce explicit focus outline indicators (`outline-glow`) across all interactive elements. |
| **AI removes security-relevant text** | Deleting the certificate warning notice on the block page can lead to user confusion when accessing blocked HTTPS destinations. | Ensure that all technical explanations (such as TLS certificate limits) remain fully intact. |

---

## 13. Non-Goals

The redesign will **not** attempt to accomplish the following tasks:
*   **Do Not Rewrite the Backend**: Do not rewrite core Go algorithms, threat matching logic, cache management systems, or storage engines.
*   **Do Not Alter DNS / Policy Behaviors**: The DNS resolver logic and policy lookup flows must remain completely unchanged.
*   **Do Not Modify API Contracts**: Do not change endpoint URLs, HTTP methods, JSON request/response formats, or parameter requirements.
*   **Do Not Introduce Frontend Frameworks**: Do not migrate the UI to React, Vue, Svelte, or Next.js. Keep the codebase lightweight using vanilla JS and HTML templates.
*   **Do Not Add Heavy Animation Libraries**: Avoid using libraries like GSAP or Framer Motion. Restrict animation to native CSS transitions.
*   **Do Not Modify Threat Feed Logic**: Threat feed sorting, synchronization timing, and priority algorithms must remain unchanged.
*   **Do Not Create a SaaS Landing Style**: The dashboard is a professional security tool. Avoid generic marketing visuals, illustrations, or promotional content.
*   **Do Not Over-Dramatize Warnings**: Warning pages must present threat details factually and objectively, avoiding alarmist language or graphics.

---

## 14. Success Criteria

A successful redesign will satisfy the following conditions:
1.  **Improved Dashboard Scannability**: Visual grids and metrics are clearly structured, allowing operators to quickly evaluate system health.
2.  **Clear Domain Analysis Results**: Verdicts, confidence scores, signals, and whitelisting panels are presented cleanly.
3.  **Visual Risk-State Distinction**: Emerald Green (`SAFE`), Amber (`SUSPICIOUS`), and Crimson Red (`MALICIOUS`) indicators are unmistakable.
4.  **Calm, Informative Block Page**: The blocked site page is clean, explains the blocking reason neutrally, and supports smooth false-positive reports.
5.  **Tactile, Responsive Interactions**: All interactive elements respond instantly to hovers and clicks with subtle, clean transitions.
6.  **Lightweight Frontend**: The page size remains small, loads quickly, and performs smoothly.
7.  **Unchanged Backend & APIs**: Existing Go route handlers, CLI commands, and database models continue to function without modifications.
8.  **Responsive mobile layouts**: Grid structures scale fluidly, and tables support clean horizontal scrolling down to 360px viewport widths.
9.  **Complete Accessibility Compliance**: Interactive controls are fully accessible via keyboard (`Tab` and `Enter`), featuring visible focus states and respecting reduced-motion settings.
10. **Extensible UI Architecture**: Proposing CSS variables and reusable classes simplifies future frontend updates.

---

## 15. Summary for Implementers

### Design Direction
The redesign will implement the **Calm Security Glass** theme: a clean, dark navy atmosphere featuring glassmorphic panels, clear typography, and subtle visual transitions. Keep the interface minimal, structured, and professional, avoiding loud neon colors or complex animations.

### safest Implementation Order
1.  **Phase 1 & 2**: Add design tokens and base CSS utility classes directly inside `safe-zone.css`.
2.  **Phase 3 & 4**: Redesign the main dashboard container shell, header status controls, navigation tabs, and the domain search analyzer block.
3.  **Phase 5 & 6**: Style results panels, telemetry doughnut charts, overriding logs, policy group cards, mapping input fields, and manual system agent triggers.
4.  **Phase 7**: Redesign the site block warning page, refactoring the false-positive report submission flow to use asynchronous AJAX `fetch` requests.
5.  **Phase 8 & 9**: Apply responsive polish, keyboard focus highlights, and clean up legacy style definitions.

### Critical Safety Rules
*   **Do Not Rename Selectors**: Keep all existing DOM element IDs (such as `domain-input`, `result`, `recent`, `st-total`, etc.) intact to prevent JavaScript reference exceptions.
*   **Do Not Modify Templates**: Preserve all Go template parameters (such as `{{.Domain}}` inside `block.html`) to prevent server-side compilation crashes.
*   **Do Not Alter API Routing**: Keep all REST endpoints, query parameters, JSON schemas, and cookie keys unchanged.
*   **Keep Patches Small**: Implement changes in small, reviewable increments following the prompt plan to ensure stability and ease of review.
