# AI-Native Recon & Bug Bounty Framework — Build Specification

*An AI-native, Docker-based, multi-tool reconnaissance and vulnerability-discovery platform with a guided UI, a Postgres-backed data model, and an MCP server for AI-agent control.*

## 1. Purpose & Philosophy

Build a self-hosted web application that wraps 40–50+ open-source security tools behind a single UI and REST API, enforcing a correct bug-bounty methodology (recon → enumeration → prioritization → manual testing) rather than letting the user run tools ad hoc. Three pillars:

- **Human creativity** drives target selection and exploitation judgment — the UI should surface data, not make decisions for the user.
- **AI/LLM** converts unstructured tool output into structured data and runs decision-heavy workflows (an MCP server should let an agent drive the same actions a human can).
- **Automated tools** handle repetitive, high-volume scanning (subdomain enum, port scans, fuzzing).

Every feature should assume **authorized testing only** (owned assets or in-scope bug bounty programs). Build in an explicit scope/authorization field on every target and refuse to let a scan start without it acknowledged.

## 2. Tech Stack

- **Frontend:** React (Vite), component library of your choice (Chakra/MUI/Tailwind), React Query for data fetching, charts via Recharts/D3 for attack-surface visualizations.
- **Backend API:** Go (idiomatic for this domain — fast, single static binaries, easy to shell out to CLI tools) with a lightweight router (chi/gin). Alternative: Python/FastAPI if the team prefers richer tool SDKIntegration.
- **Database:** PostgreSQL — stores scope targets, scan jobs, raw + parsed tool output, findings, ROI scores, notes.
- **Job orchestration:** Each scan runs as its own short-lived Docker container (or a worker pool with a job queue — Redis + a worker service) so tools stay isolated, versioned, and resource-capped.
- **Reverse proxy:** nginx routing `/api/*` to the backend and `/*` to the React build, single exposed port.
- **AI integration:** a separate MCP server service (Node or Go) exposing tool-call endpoints over SSE/stdio that map 1:1 to backend REST endpoints.
- **Container orchestration:** docker-compose for local/self-hosted deployment; one Dockerfile per scanning tool that doesn't ship a usable public image.

## 3. High-Level Architecture

```
Browser → nginx → React SPA (static)
                 → /api → Go Backend API → Postgres
                                          → Job Queue → Worker(s) → per-tool Docker containers
        → MCP Server (SSE :3001) → same Go Backend API
```

Keep the backend as the single source of truth: both the React UI and the MCP server call the same REST endpoints, never duplicate logic in two places.

## 4. Data Model (Postgres)

Core tables (adapt names freely):

- `scope_targets` (id, type\[company|wildcard|url\], value, auth\_confirmed bool, created\_at)
- `companies` (id, scope\_target\_id, name)
- `asns` / `network_ranges` (id, company\_id, asn, cidr, source\_tool)
- `root_domains` (id, company\_id, domain, source\[dork|crt|whois|securitytrails|github|shodan|censys\])
- `wildcard_targets` (id, scope\_target\_id, root\_domain)
- `subdomains` (id, wildcard\_target\_id, subdomain, source\_tool, first\_seen, last\_seen)
- `live_web_servers` (id, subdomain\_id OR ip, url, status\_code, title, tech\_stack jsonb, headers jsonb, tls jsonb, screenshot\_path)
- `dns_records` (id, subdomain\_id, record\_type, value)
- `dorks_results` (id, scope\_target\_id, dork\_type\[google|github\], query, result\_url, snippet, reviewed bool)
- `directories` / `endpoints` (id, live\_web\_server\_id, path, status\_code, content\_length, source\_tool\[ffuf|katana|gospider|gau\])
- `parameters` (id, endpoint\_id, name, source\_tool\[arjun|x8\])
- `findings` (id, scope\_target\_id, vuln\_class, severity, tool, raw\_output, status\[new|triaged|reported|fp\], evidence jsonb)
- `roi_scores` (id, live\_web\_server\_id, score, breakdown jsonb)
- `scan_jobs` (id, scope\_target\_id, tool, status, started\_at, finished\_at, stdout\_path, stderr\_path, exit\_code)
- `settings` / `api_keys` (service, encrypted\_key)

Store raw tool stdout/stderr (as files or large text columns) alongside parsed structured rows, so the UI can always show "raw output" for trust/debugging.

## 5. Scope Target Types

1. **Company** — a named organization; framework discovers everything it owns, on-prem and cloud.
2. **Wildcard** — `*.domain.com`; framework enumerates and prioritizes every subdomain.
3. **URL** — a single specific target used for deep, guided manual-testing education/automation.

A Company scan should auto-generate Wildcard targets for every root domain it discovers, chaining workflows together.

## 6. Workflow 1 — Company (asset discovery)

Steps, each a distinct backend job type with its own status row and UI stage:

1. **ASN / network range discovery** — Amass Intel, Metabigor. Input: company name. Output: ASNs + CIDRs.
2. **Live web server discovery (on-prem)** — port scan the CIDRs (naabu/masscan) then HTTP-probe (httpx) to find live services.
3. **Root domain discovery, no API key** — Google dorking (`site:`, `intitle:`, `inurl:` queries built from the company name and known domains), Certificate Transparency (crt.sh), reverse WHOIS.
4. **Root domain discovery, API key enhanced** — SecurityTrails, Shodan, Censys, GitHub recon (search code/orgs for the company's domains and leaked references).
5. **Consolidate root domains** — dedupe, then auto-create Wildcard scope targets per unique root domain.
6. **Cloud asset enumeration (DNS)** — Amass Enum + DNSx across every discovered domain to pick up cloud-hosted subdomains.

Output: a unified attack-surface view (domains → subdomains → live servers → findings) the user can drill into.

## 7. Workflow 2 — Wildcard (subdomain enum + prioritization)

This is the most tool-heavy workflow; implement a consolidation step after each discovery round so later tools run against a deduped, validated list.

1. **Amass Enum** — active+passive subdomain enumeration.
2. **Subdomain scraping** — Sublist3r, Assetfinder, GAU, CTL, Subfinder run in parallel; merge results.
3. **Consolidate + live-server probe (round 1)** — dedupe subdomains, run httpx to flag which resolve and serve HTTP(S).
4. **Brute-force** — generate a target-specific wordlist with CeWL (scraped from the target's own pages) and mass-resolve with ShuffleDNS.
5. **Consolidate + live-server probe (round 2)**.
6. **JS/link discovery** — crawl live sites with GoSpider, extract embedded subdomains/endpoints from JS with Subdomainizer and LinkFinder.
7. **Consolidate + live-server probe (round 3)** — final pass.
8. **ROI / decision point** — screenshot every live server (e.g., with gowitness or a headless-Chrome service) and pull metadata (tech stack, headers, TLS, DNS) to compute an ROI score per target (see §9) so the user knows where to spend manual-testing time first.

## 8. Workflow 3 — URL (guided manual-testing / education)

A single-target deep-dive workflow. Build it as a set of independent, resumable "modules" rather than one linear pipeline, since a user may only want a subset:

- **Directory / content discovery**: ffuf or feroxbuster against the target with curated wordlists (SecLists), plus Katana/GAU for crawled + historical URLs. Store every discovered path with status code, length, and a diff-against-baseline flag to surface non-404 hidden content.
- **Parameter discovery**: Arjun / x8 to find hidden GET/POST params on discovered endpoints.
- **Client-side injection (XSS)**: Dalfox / xssFuzz / a headless-DOM scanner (domdig) to find and verify reflected/stored sinks; surface each candidate with the reflection context so the user can manually confirm.
- **Server-side injection**: sqlmap/Ghauri for SQLi, Commix for command injection, SSTImap/TInjA for template injection, LFImap/LFIHunt for LFI — each wrapped so results land in `findings` with raw evidence.
- **SSRF / open redirect**: SSRFmap, REcollapse.
- **Access control / smuggling / cache**: nomore403, forbidden, Web Cache Vulnerability Scanner, CacheBoom, smugglex/http2smugl.
- **GraphQL**: graphw00f (fingerprint), graphql-cop (misconfig audit), Clairvoyance (schema recovery when introspection is off).
- **Secrets & exposure**: TruffleHog, Mantra, Snallygaster, git-dumper/GitTools for exposed `.git`.
- **JWT / auth**: jwt\_tool for token tampering; a dedicated module to record and replay register/login/MFA/reset flows step by step so the user can test session handling.

Each module should follow **Discover → Understand → Test → Validate**: the tool finds candidates, the UI explains *why* this matters (a short write-up per vuln class), the user runs/edits the actual payload, and an automated check confirms the finding before it's logged.

## 9. ROI Scoring (example algorithm — tune freely)

Per live web server, accumulate points from its metadata:

- Expired/self-signed/misconfigured TLS cert: **+25** each
- Each discovered endpoint/content item: **+1 to +3**
- Each identified technology with a known CVE history: **+3**
- Missing security headers (e.g., no CSP): **+10**
- Caching / dynamic-content indicators: **+10**
- 404 pages that leak stack traces or paths: **+50**

Store the full point breakdown (not just the total) so the UI can show *why* a target scored high — this is what turns the score into something the user trusts rather than a black box.

## 10. Backend API Design

RESTful, resource-oriented, versioned under `/api/v1`. Minimum surface:

- `POST/GET/DELETE /scope-targets`, `PATCH /scope-targets/{id}/activate`
- `POST /scans/{tool}` (body: scope\_target\_id, tool-specific options) → `scan_job` id
- `GET /scans/{id}` (status, exit code, duration), `POST /scans/{id}/cancel`
- `GET /scans/{id}/raw-output`
- `POST /workflows/{company|wildcard|url}/run`, `GET /workflows/{id}/status` (per-step status so the UI can render a progress stepper)
- `GET /targets/{id}/subdomains|domains|live-servers|endpoints|findings|roi`
- `GET /analysis/subdomain-takeover|exposed-panels|api-endpoints|sensitive-files`
- `GET/PATCH /settings`, `PUT /settings/api-keys/{service}`
- `GET /export/{scope_target_id}` → portable export bundle (the `.vexora`-style format), `POST /import`

Every scan/workflow endpoint should be idempotent-safe to re-trigger and should write a `scan_jobs` row immediately (status `queued`) so the UI never has to guess whether a click registered.

## 11. Frontend UX Requirements

- **Welcome/onboarding screen**: create new scope target (with explicit authorization checkbox) or import existing scan data (file upload or URL).
- **Workflow stepper UI**: each workflow (Company/Wildcard/URL) renders as a vertical/horizontal stepper; every step shows live status (queued/running/done/failed), a "Help Me Learn!" collapsible explaining the step's purpose and the *why*, and a link to raw tool output.
- **Attack-surface dashboard**: searchable/filterable tables for domains, subdomains, live servers, endpoints, and findings, with CSV/JSON export.
- **ROI view**: sortable list of live servers by score with the breakdown visible on hover/expand; this is the primary "where do I start manually testing" screen.
- **Findings/triage board**: kanban-style (new → triaged → reported → false positive) for anything discovered by the vuln-scanning modules.
- **Settings**: API key management per integrated service (SecurityTrails, Censys, Shodan, GitHub token, etc.), rate-limit and custom-header config, Burp Suite integration config if desired.

## 12. Deployment

- Single `docker-compose.yml` defining: `db` (Postgres), `api` (Go backend), `client` (React build served by nginx or its own container), `nginx` (reverse proxy on port 80), `mcp-server`, and one service per self-built tool container (anything not available as a trustworthy public image).
- Build scripts (`build.sh` / `build.ps1`) that build tool images **sequentially** rather than `docker compose up --build` in parallel — parallel builds of many source-compiled tools commonly race on Docker's image store and fail; a sequential script avoids this even though it's slower on first run.
- `update.sh` / `update.ps1` that stop containers, back up `docker-compose.yml`/wordlists, pull latest code, rebuild, and run DB migrations on startup.
- Document minimum system requirements (8GB+ RAM recommended given the number of concurrent containers).

## 13. MCP Server (AI-agent control plane)

Expose the backend's full capability set as MCP tools over SSE (`/sse`) with a `/health` endpoint reporting the live tool count. Group tools to mirror the REST API: scope/target management, scan execution, recon data queries, analysis queries, workflow control, findings/triage, settings. Support an optional bearer-token auth (`MCP_AUTH_TOKEN`) since an unauthenticated MCP server on a reachable port can run scans or delete data. This lets a coding/security agent (Claude Code, Claude Desktop, Cursor, etc.) drive the entire framework the same way a human does through the UI — useful for "what should I do next" guidance and for automating the repetitive parts of the methodology while leaving judgment calls to the human.

## 14. Guardrails to Build In

- Require an explicit "I am authorized to test this target" acknowledgment before any scope target can be activated for scanning.
- Rate-limit and timeout every outbound tool call by default; make limits configurable per target, not just global.
- Never auto-exploit: vulnerability modules should **detect and report candidates for human/agent confirmation**, not automatically chain into exploitation against a live target without an explicit user-triggered "validate" action.
- Log every outbound request the framework makes (target, tool, timestamp) for auditability, since this is operating against real external infrastructure.

## 15. Suggested Build Order (milestones)

1. Postgres schema + Go API skeleton (scope targets CRUD) + React shell hitting it.
2. Single tool integration end-to-end (e.g., Subfinder) to prove the job-queue → Docker-container → parsed-results → UI pipeline.
3. Wildcard workflow steps 1–3 (enum, scrape, consolidate/live-probe) — this validates the consolidation pattern you'll reuse everywhere.
4. ROI scoring + dashboard.
5. Company workflow (reuses Wildcard once root domains are found).
6. URL workflow modules, starting with directory/content discovery and XSS, then expanding.
7. MCP server wrapping the by-then-stable REST API.
8. Import/export, settings/API-key management, auth hardening.

---

**Use this as the prompt for a coding agent**: paste a given section (or the whole doc) as the task description, naming your preferred stack if it differs from §2, and build milestone-by-milestone from §15 rather than attempting the whole system in one pass.

## 16. Advanced Tool Invocation & Knowledge-Base Integration

Wrapping a tool with default flags is not enough — most of these tools only become useful at bug-bounty scale with their advanced options tuned. Each tool integration should ship a configurable "advanced mode" (exposed in Settings, with sane defaults) rather than hardcoding a basic invocation.

### Nuclei (core vulnerability-scanning engine)

Make Nuclei a first-class citizen, not an afterthought — run it at multiple points in the pipeline, not just once at the end:

- **Template management**: auto-update templates on a schedule (`nuclei -update-templates`), let the user pin/exclude template tags (`-tags`), severities (`-severity critical,high,medium`), and protocol types (`-tags cve,exposure,misconfig,takeover,default-login`).
- **Scale controls**: `-c` (concurrency), `-rl` (rate-limit), `-bs`/`-bulk-size`, `-timeout`, and a per-target rate-limit pulled from the target's engagement config (§14) rather than a global constant.
- **Signal-to-noise**: `-silent -jsonl` for machine-parseable output straight into `findings`, `-etags intrusive` to skip template tags that could disrupt production targets by default, with an explicit opt-in toggle to include them.
- **Staged runs**: a fast pass with `-tags tech,exposure,misconfig` right after live-server discovery (cheap, high signal), then a deeper pass with CVE/fuzzing templates only against the top ROI-scored targets — this keeps Nuclei useful at both the "triage everything" and "deep-dive the best targets" stages of the Wildcard and URL workflows.
- **Custom templates**: let users drop org/target-specific YAML templates into a mounted directory (`-t /custom-templates/`) so the framework's own community/education content can ship as real, runnable Nuclei templates.

### Other tools — don't settle for defaults

- **Amass**: use `-active` only when explicitly authorized (it's noisier/more detectable than passive mode); tune `-config` for custom resolvers and rate limits rather than relying on Amass's defaults, which are conservative for bug-bounty scale.
- **Subfinder**: `-all` to enable every configured source, `-recursive` for recursive subdomain discovery, and feed in API keys via `provider-config.yaml` so passive sources aren't silently skipped.
- **httpx**: `-tech-detect -title -status-code -follow-redirects -json` at minimum; add `-screenshot` if not handling screenshots via a separate headless service.
- **ffuf**: use `-recursion -recursion-depth` for nested content discovery, `-fc`/`-fs` filters tuned per-target after an initial baseline run (to kill false-positive "soft 404" noise), and `-mc all -ac` (auto-calibration) rather than a fixed status-code allowlist.
- **Katana**: `-jc` (JS crawling) and `-kf` (known-files, e.g. robots.txt/sitemap.xml) on, `-d` (depth) tuned per engagement size, `-xhr-extraction` to catch API calls made via JS.
- **GAU/waybackurls**: always paired with a dedupe + "interesting extension" filter (`.json`, `.env`, `.sql`, `.bak`, `.git`, backups) so historical-URL noise doesn't bury real findings.

### Dorking & community knowledge bases

Treat dorking as data-driven, not a hardcoded query list — vendor curated dork/tip sets as versioned content the framework can search and update, mirroring the "Education Layer" concept from the original framework:

- **Google dorking**: build the Company workflow's dork step from a maintained dork-pattern library (operators like `site:`, `intitle:`, `inurl:`, `ext:`, `intext:` combined with the target's known domains/brand terms), and let users add custom dork templates per engagement.
- **GitHub dorking/recon**: search GitHub code/orgs/commits for the target's domains, internal hostnames, API keys, and config references; this pairs naturally with TruffleHog/Mantra once a repo is identified.
- **Payload reference library**: vendor (as a git submodule or scheduled sync job) a copy of **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** and surface it inside each vulnerability module's "Understand" step (§8) — e.g., the XSS module links directly to the matching PayloadsAllTheThings payload set instead of the framework trying to maintain its own payload corpus from scratch. Let the user copy a payload straight into the manual-testing panel.
- **Bug-bounty tips & methodology**: similarly vendor **[kingofbugbountytips](https://github.com/KingOfBugbounty/kingofbugbountytips)** as searchable methodology/tips content surfaced in the "what should I do next" guidance and per-vuln-class playbooks (§8, MCP §13's "Methodology and guidance" category).
- **Recon automation reference**: use **[enumrust](https://github.com/KingOfBugbounty/enumrust)** as a reference implementation for the recon-chaining logic in the Wildcard workflow (§7) — its enumeration-pipeline structure is a useful model for how to chain multiple subdomain sources, resolve, and probe efficiently in a compiled language; borrow its approach rather than just its wordlists.
- Keep all three as **pinned, periodically-updated references** (not live scraped at request time) so scan behavior stays reproducible and offline-capable once synced.

Add a `knowledge_base` table (source, category, content, tags, synced\_at) so dork patterns, tips, and payload references are queryable through the same API/MCP surface as everything else, rather than living only in static files.

## 16. Advanced Tool Usage (don't run tools with defaults)

Default flags give shallow results. Every tool wrapper in §7–§8 should expose (and the backend should set sane non-default values for) each tool's advanced options, not just a bare invocation:

- **Nuclei** — this is the workhorse for the final "validate everything live" pass across every workflow, not just a one-off scan. Run it with: `-as` (automatic template selection based on tech detected), `-tags`/`-etags` to scope by vuln class, `-s critical,high,medium` severity filtering, `-rl` and `-c` tuned to the target's rate-limit profile, `-irr` to include request/response in output for the findings table, `-ni` to disable interactsh when an internal/offline target needs it, and a `-t` pointing at a **custom template directory** the framework maintains per vuln class (see repos below) in addition to the official nuclei-templates repo. Schedule a lightweight Nuclei pass after every subdomain consolidation round (cheap, high signal) and a deep pass as the final step of the Wildcard and URL workflows.
- **Subfinder** — `-all` (every source, not just fast ones), `-recursive`.
- **httpx** — `-tech-detect -title -status-code -content-length -tls-grab -follow-redirects -favicon` so a single pass populates most of the `live_web_servers` metadata needed for ROI scoring.
- **Amass** — `enum -active -brute -w <wordlist>` for the active/brute pass, not just passive.
- **Katana** — `-jc -kf all -d 3` (JS crawling, known files, depth) to actually surface the endpoints other tools miss.
- **ffuf / feroxbuster** — recursive mode with a depth cap, `-fc`/`-fs` tuned per-target after an initial baseline run (so wildcard-response noise doesn't drown real hits), and extension lists matched to the detected tech stack.
- **sqlmap** — `--batch --risk=2 --level=3 --dbs` as the default "confirm" pass once a candidate parameter is flagged by another tool, not as the discovery tool itself.
- **Dalfox** — `--mining-dom --mining-dict --deep-domxss` for the DOM-XSS module.

Surface these flags as editable per-scan options in the UI (power users) while keeping a one-click "recommended" preset (beginners) — this matches the framework's "UI enforces correct methodology but doesn't block experts" principle from §1.

## 17. Payload & Methodology Reference Sources

Vendor (as git submodules or a scheduled sync job, not copy-pasted) these community repos and wire them directly into the tooling rather than treating them as reading material:

- **PayloadsAllTheThings** — the payload source for every fuzzing/injection module in the URL workflow (§8): XSS, SQLi, SSTI, SSRF, LFI, command injection, XXE. Parse its per-vuln-class payload lists into the wordlists ffuf/dalfox/sqlmap/commix consume, and surface the matching "Methodology and Resources" notes from the repo in each module's "Help Me Learn!" panel (§1, §8) so the educational content is sourced from a maintained reference instead of hand-written and going stale.
- **KingOfBugBountyTips** — mine this for Google/GitHub dork query patterns (feed directly into the Company workflow's dorking step, §6.3) and for recon one-liners/tool-chaining recipes — use it to seed the "what should I do next" guidance the MCP server exposes (§13).
- **enumrust** — a fast Rust subdomain enumerator; add it as an additional parallel source alongside Subfinder/Assetfinder/Sublist3r/GAU/CTL in the Wildcard workflow's scraping step (§7.2) for an extra, fast-running discovery pass before consolidation.

Build a small sync job that periodically re-pulls these repos and re-indexes their content into the `dorks_results` seed data and the Nuclei custom-template/wordlist directories, so the framework's payload and dork coverage doesn't silently drift out of date.

## 18. Visual Design System

The audience is security practitioners reading dense, data-heavy tables for hours — optimize for legibility and scan-ability over decoration, and let the ROI scores, status codes, and severities (not chrome) carry the visual weight.

**Color** — a near-black, slightly blue-leaning base (not pure #000) so long sessions are easy on the eyes, with a single confident accent reserved for primary actions and active states, and a strict severity scale that's the real color language of the app:

- Background: `#0D1117` (base), `#161B22` (raised surfaces/cards), `#21262D` (borders/dividers)
- Text: `#E6EDF3` (primary), `#8B949E` (secondary/muted)
- Accent (primary actions, links, active nav): `#3FB950` (a muted signal-green — reads as "system operational / scan running," distinct from the generic terracotta/violet SaaS accent)
- Severity scale (used consistently for findings, ROI bands, status dots): Critical `#F85149`, High `#DB6D28`, Medium `#D29922`, Low `#58A6FF`, Info `#8B949E`

Keep the palette this disciplined everywhere — don't introduce extra accent colors per workflow; let the severity scale do the differentiating work instead.

**Type** — two families, clearly distinct roles:

- UI/body: a grounded grotesque sans (Inter or IBM Plex Sans) at 14–15px base for table-dense screens; avoid serif here, this is an instrument panel, not an editorial page.
- Data/code: a monospace face (JetBrains Mono or IBM Plex Mono) for everything literal — domains, URLs, raw tool output, status codes, CLI flags, request/response bodies. This distinction matters more here than in most apps: it lets the eye instantly separate "system fact" from "UI label" when scanning a dense findings table.

**Layout** — left rail for workflow/scope-target navigation (collapsible), persistent top bar with the active scope target and global scan status, main content as data tables/cards. Left-align all data tables (never center tabular data). Use the workflow stepper (§11) as a horizontal progress rail on desktop, collapsing to a vertical accordion on mobile.

**Responsive behavior** — this is a tool people will check from a phone mid-engagement to see if a long scan finished, so build mobile as a real target, not an afterthought:

- Breakpoints: mobile <640px, tablet 640–1024px, desktop >1024px.
- Desktop: multi-column dashboards, side-by-side raw-output/parsed-view panes.
- Tablet: single-column dashboard, tables scroll horizontally within their own container rather than squeezing columns.
- Mobile: the left rail collapses to a bottom nav or hamburger drawer; data tables collapse to stacked cards (one finding/subdomain per card, key fields only, tap through for full detail) rather than a horizontally-scrolled table; the workflow stepper becomes a single current-step summary with a progress fraction ("Step 3 of 6") instead of showing every step at once.
- Respect `prefers-reduced-motion`; keep focus states visibly outlined (accent-colored ring) throughout — this is a tool, keyboard-driven use is common.

Spend restraint everywhere except one moment: the ROI dashboard (§11) is the page people will stare at longest, so it's the one place worth a slightly bolder treatment (e.g., the score itself rendered large, in the severity-adjacent accent, with the point breakdown as a quiet secondary list) — keep every other screen quiet and consistent around it.
