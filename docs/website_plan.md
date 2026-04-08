# Cullis Website Plan

Status: **Sprint 1-11 completati** (2026-04-08)
Domain: `cullis.io`
Source: `docs/index.html` (single-file landing, self-contained)

## Design system

| Token | Value |
|---|---|
| Display font | `Instrument Serif` (italic cyan for accents) |
| Body font | `Satoshi` |
| Mono font | `DM Mono` |
| Brand font | `Chakra Petch` (logo lockup only) |
| Background | `#050508` (void) / `#0a0b10` (surface) |
| Accent | `#00e5c7` (teal, same as MCP proxy dashboard) |
| Text tertiary | `#6e7180` (WCAG AA compliant, raised from `#555868`) |

Consistent with the MCP Proxy dashboard refactor done in the same session (`app/dashboard/templates/`) — same color tokens, same fonts, same aesthetic direction.

## Architecture

Single `index.html` file, ~2000 lines, fully self-contained:
- Inline CSS (design tokens as CSS variables)
- Inline JS (reveal animations, pillar tabs, copy button, nav scroll-shrink)
- External deps: Google Fonts (4 families), `cullis.svg` logo
- No build step, no framework, no bundler

## Page structure

```
┌─ NAV (shrinks on scroll)
├─ HERO (2-col)
│  ├─ Left  — brand lockup, eyebrow, h1, sub, CTAs, social strip
│  └─ Right — animated Python SDK terminal (self-typing)
├─ STANDARDS BAR (6 tiles)
├─ PROBLEM (3 cards with distinct icons)
├─ FEATURES (Pillar tabs → Stage panel, Tailscale-style)
│  └─ 6 tabs: Identity · E2E · Authorization · Audit · Federation · SDKs
│     Each panel = text + mock visual (card-style)
├─ ARCHITECTURE (inline SVG with <title>/<desc>)
├─ USE CASES (3 concrete scenarios with numbered flows)
├─ QUICKSTART (terminal with copy button)
├─ COMPARISON (4-column table vs MCP raw, SPIFFE, Vault+Consul)
├─ CTA (Star on GitHub, Join Discussions)
└─ FOOTER (3 columns: Project / Security / Community)
```

---

## Audit history

Starting state: 1282 lines, heavy feature list (15 cards), weak tagline, vague stats bar, generic comparison. Design tokens already strong (Instrument Serif + Satoshi), but content organization weak.

### Sprint 1 — Hero redesign + a11y [DONE]
- New tagline: *"Cryptographic identity and E2E messaging for AI agents that work across organizations."*
- Hero split into 2-col: text/CTAs left, self-typing Python SDK terminal right
- CTAs rebalanced: `Read the Docs →` (primary) + `View on GitHub` (ghost)
- Fix `--text-tertiary` `#555868` → `#6e7180` (WCAG AA, 18 SVG occurrences updated)
- Added `prefers-reduced-motion` support
- `aria-label`, `role`, `rel="noopener"` on external links

### Sprint 2 — Features 15 → 6 pillars [DONE, superseded]
- Collapsed 15 feature cards into 6 thematic pillars
- Grouped as: Identity / E2E / Authorization / Audit / Federation / SDKs
- *Note: initial grid layout later replaced by Sprint 10 tabbed showcase*

### Sprint 3 — Enterprise → Use Cases [DONE]
- Removed duplicate "Enterprise features" grid
- Replaced with 3 concrete use cases:
  1. **Cross-Org RFQ Negotiation** (supply chain)
  2. **Multi-Tenant SaaS** (customer agents ↔ vendor agents)
  3. **Regulated B2B Data Exchange** (healthcare/finance, BYOCA + OPA)
- Each use case has a numbered 4-step flow

### Sprint 4 — Comparison with real competitors [DONE]
- Removed API Keys/OAuth (strawman)
- New columns: MCP (raw), SPIFFE/SPIRE, Vault+Consul, Cullis
- 9 rows focused on cross-org federated identity
- Added "composes with" note clarifying positioning vs stack tools

### Sprint 5 — Stats bar → Standards bar [DONE]
- Removed fake stats (450+ tests, 2 components, E2E)
- Replaced with standards/facts bar: RFC 9449, SPIFFE, x509·mTLS, AES-256-GCM, Apache 2.0, Self-Hosted

### Sprint 6 — Meta social tags + favicon [DONE]
- Open Graph (Facebook/LinkedIn) tags
- Twitter/X card tags
- JSON-LD structured data (`SoftwareApplication` schema)
- Canonical URL, theme-color, keywords
- Favicon referenced (SVG primary + PNG fallbacks)

### Sprint 7 — Quickstart copy button [DONE]
- `Copy` button in terminal bar with clipboard feedback
- "Copied" state + hover glow
- `data-copy` attribute keeps copied text clean (no HTML)

### Sprint 8 — Social proof [DONE]
- Hero social strip: GitHub stars badge (shields.io, teal-styled), Discussions link, Apache 2.0 license
- Footer: replaced "Contributing Guide" with "Join Discussions"

### Sprint 9 — Nav scroll-shrink [DONE]
- Nav padding `1.15rem → 0.7rem` on scroll > 80px
- Logo height `32px → 26px`
- Background opacity + blur intensify
- RAF-throttled scroll listener

### Sprint 10 — Pillars tabbed showcase [DONE]
- Tailscale-inspired: 6 tabs in a row, clicking one swaps the stage below
- Active tab lifts `-6px` with gradient + arrow pointing to panel
- Each of the 6 panels has 2-col: text+bullets left, mock visual right
- 6 custom mocks (not stock screenshots):
  1. **Identity** — agent card with Pinned badge + SPIFFE ID + thumbprint
  2. **E2E** — 3-node flow Agent A → Broker (blind) → Agent B
  3. **Authorization** — dual PDP verdict card
  4. **Audit** — hash-chain 4-block visualization + verify stamp
  5. **Federation** — 4-step onboarding flow
  6. **SDKs** — Python code snippet with Vault key loading
- Keyboard navigation: `ArrowLeft`/`ArrowRight` between tabs
- ARIA: `role="tablist"`, `aria-selected`, `aria-controls`, `aria-labelledby`

### Sprint 11 — Audit closure [DONE]
- Tagline CTA: *"Engineered for zero-trust, built for the agent era"*
- Footer bottom: matches the new tagline
- `<nav role="navigation" aria-label="Primary">`
- Architecture SVG: `<title>` + `<desc>` for screen readers
- Noise texture opacity `0.025 → 0.04` (visible now)
- Problem cards: 3 distinct icons (broken lock, broken link, crossed eye) instead of 3 identical `×`
- Terminal body: `.sr-only` text labels for prompt/cmd/output (WCAG 1.4.1)
- Footer: added Community column (Discussions, Changelog, Contact email)
- Roadmap link added to Project column

---

## TODO (known gaps, not blocking ship)

### Assets to generate (external dependency)
- [ ] `docs/og-image.png` — 1200×630, referenced in meta tags. Suggested: Cullis logo + tagline on `#0a0b10`, Instrument Serif italic teal
- [ ] `docs/favicon-32.png` — 32×32 PNG fallback (SVG already serves modern browsers)
- [ ] `docs/apple-touch-icon.png` — 180×180 for iOS home screen

### Performance
- [ ] **Font self-hosting** — currently 4 families × multiple weights loaded from Google Fonts (~200KB)
  - Suggested subset: Satoshi 400/500/700, Instrument Serif 400 italic, DM Mono 400/500, Chakra Petch 600
  - Download woff2, place in `docs/fonts/`, update `@font-face` in inline CSS, add `<link rel="preload">` for critical weights
  - Expected saving: ~140KB gzipped

### Content to finalize
- [ ] Write proper README.md (currently linked but may be outdated)
- [ ] Create CONTRIBUTING.md with repo structure and dev setup
- [ ] Create `SECURITY.md` disclosure policy (if not already present)
- [ ] `enterprise-kit/BYOCA.md` — linked but verify it exists

### Branding decisions (NOT automated — requires human input)
- [ ] **GitHub handle/org rename**: `DaenAIHax/cullis` is great for personal hacking but can feel informal to enterprise buyers evaluating a Trust Broker. Consider:
  - Create org `cullis-security` or `cullis-dev`
  - Transfer repo ownership
  - Maintainer listed with real name or neutral pseudonym (e.g. `D. Enright`)
  - Rationale: a CISO reviewing supply chain risk is more comfortable with `cullis-security/cullis` than `DaenAIHax/cullis`
- [ ] **Origin story**: add 3-4 lines "About" or "Why Cullis" in README explaining the motivation (working with AI agents, realized no cross-org trust primitive exists, built from IETF standards)
- [ ] **Contact email**: `hello@cullis.io` referenced in footer — set up mailbox/forwarding once domain is live
- [ ] **Declare maintainer as Independent Security Researcher / Software Architect** in GitHub profile + LinkedIn

### Nice-to-have (low priority)
- [ ] GitHub stars badge uses `img.shields.io` inline — consider caching or self-hosting if rate-limited
- [ ] Architecture SVG animation: currently has `flow-line` dash animation; could add staggered reveal on scroll
- [ ] Add a language switch (EN only for now — Italian audience is main user but English reach is global)
- [ ] Docs subsite: `/docs` → separate static site for API docs, SDK docs, deployment guides (currently everything points back to GitHub README)
- [ ] `/blog` subsite: changelog + deep-dive posts (DPoP implementation, E2E flow, audit chain verification)

---

## How to preview locally

```bash
python -m http.server 8080 --directory docs
# open http://localhost:8080
```

## How to deploy

The landing is a static single file. Any static host works:
- **GitHub Pages** — point at `docs/` from repo settings (current assumption)
- **Cloudflare Pages** — connect repo, build command none, output dir `docs/`
- **Netlify / Vercel** — drag-and-drop `docs/` folder or connect repo
- **S3 + CloudFront** — upload `docs/*` to bucket with static hosting

No build step needed. DNS: point `cullis.io` A/CNAME at the host.
