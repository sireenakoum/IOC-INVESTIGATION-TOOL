# IOC Investigation Tool

A threat intelligence aggregator that checks IPs, domains, and file hashes against VirusTotal, AlienVault OTX, AbuseIPDB, Shodan, Censys, WHOIS, GreyNoise, URLhaus, URLScan, Hybrid Analysis, ThreatFox, Spamhaus DROP, and Google Intel, then issues a scored verdict. Co-mentioned IOCs discovered during a scan are automatically pivot-scanned. The web UI adds role-based accounts (Admin/Analyst) with per-user history and API keys, an admin panel for user management and activity logging, a local LLM-generated analyst summary, an interactive pivot graph, and TXT/CSV/JSON/DOCX export.

---

## Quick start

```bash
pip install -r requirements.txt
```

Add a `.env` file (copy [.env.example](.env.example) and fill in your keys — it's the source of truth for which keys are required vs. optional):

```bash
cp .env.example .env
```

The Censys token is the Bearer token shown in your account at search.censys.io → API. Censys is optional — the tool works without it, adding independent Censys findings to the report when present.

GreyNoise uses the free community endpoint and requires no API key.

Spamhaus DROP uses a public feed and requires no API key.

Google Intel searches via a free DuckDuckGo backend (`ddgs`), with `trafilatura` for full-page article extraction. No API key needed.

The web UI's **AI Analyst Summary** panel calls a local [Ollama](https://ollama.com) instance (`http://localhost:11434`, model `qwen2.5:3b-instruct`) — install Ollama and pull the model to enable it:

```bash
ollama pull qwen2.5:3b-instruct
```

No API key or cloud call is involved; if Ollama isn't running, the rest of the app still works and the summary panel just reports an error.

The web UI requires an account (see [Accounts](#accounts) below) — set `JWT_SECRET` (any random string, used to sign session tokens) and, for self-service sign up, `BREVO_API_KEY` and `BREVO_SENDER_EMAIL` (a free [Brevo](https://www.brevo.com) transactional-email account) to send the verification link a new account needs before it can log in. Admin-created accounts don't have this dependency: without Brevo configured, an admin creating or resetting a user gets a one-time temp password to share out of band instead of an emailed link. The rest of `.env` (scan source keys, Ollama) is unaffected either way.

Run (CLI):

```bash
python main.py
```

Run (Web UI):

```bash
cd web/frontend
npm install
npm run build      # outputs to web/frontend/dist, which the backend serves
cd ..
uvicorn app:app --reload
```

Then open `http://localhost:8000` in your browser. For frontend development with hot reload, run `npm run dev` inside `web/frontend` instead (proxies API calls to the FastAPI backend) and skip the build step.

---

## Usage

| Input | Action |
|-------|--------|
| IPv4 address | Check against VT, OTX, AbuseIPDB, Shodan, Censys, GreyNoise, URLhaus, URLScan, ThreatFox, Spamhaus DROP (via ASN), and Google Intel |
| Domain name | Check against VT, OTX, WHOIS, URLhaus, URLScan, Hybrid Analysis, ThreatFox, and Google Intel |
| MD5 / SHA1 / SHA256 hash | Check against VT, OTX, Hybrid Analysis, ThreatFox, and Google Intel |
| `verbose` | Switch to full breakdown view |
| `brief` | Switch to summary view (default) |
| `history` | List all past lookups |
| `history <n>` | Replay report for entry #n |
| `history clear` | Delete all history (prompts for confirmation) |
| `reset cache` | Clear all cached API results (prompts for confirmation) |
| `rescan <indicator>` | Delete cache and history for that indicator, then re-query all sources |
| `help` | Show command reference |
| `exit` / `quit` / `q` | Exit |

Results are saved to `ioc_cache.db` (SQLite). Results are cached indefinitely; use `reset cache` to clear all entries or `rescan <ioc>` to clear and re-query a single indicator.

The web UI covers the same commands through its Dashboard, History, and Pivot views, plus several features the CLI doesn't have — see [Web UI](#web-ui) below.

---

## Web UI

| Feature | What it does |
|---------|---------------|
| **AI Analyst Summary** | A right-hand panel (`AiSummaryPanel.jsx`) that streams a narrative verdict from a local Ollama LLM ([llm/ioc_llm.py](llm/ioc_llm.py)), grounded in the same trimmed report digest ([output.py](output.py)'s `build_llm_report_digest`) sent to the frontend — not a separate re-scan. Regenerate on demand; requires Ollama running locally, see [Quick start](#quick-start). |
| **Export menu** | One button on each result (`ExportMenu.jsx`) offering a plain-text report, a CSV evidence table, a full structured JSON report, or a formatted Word (.docx) report ([web/docx_export.py](web/docx_export.py)) — served by `/api/report`, `/api/report/csv`, `/api/report/json`, and `/api/report/docx`. `/api/report/docx/generate` + `/api/report/docx/download` support pre-generating a report and downloading it separately (`DocxReadyBanner.jsx`). |
| **Pivot graph** | An interactive D3 force-directed graph (`PivotVisualization.jsx`) of an indicator and everything discovered during its pivot scan. Drag, zoom, and click a node for its verdict, score, WHOIS, and scan log in a side panel. |
| **Accounts** | Sign up / log in (`AuthView.jsx`) gates the whole app; an account panel (`AccountPanel.jsx`) exposes your API key, a regenerate button, and account deletion. See [Accounts](#accounts) below. |
| **Users & Activity Log** (Admin only) | `UsersView.jsx` + `ActivityLogTable.jsx`: create users, promote/demote role, suspend/reactivate, force a password reset, and drill into a user's own login/logout/scan history via `UserDetailView.jsx`. |
| **My Activity** (Analyst) | `MyActivityView.jsx` — an Analyst's own login/logout/scan-run history, filterable by event type and date range. |
| **Invite / forced password flows** | `AcceptInviteView.jsx` handles both admin-invite and admin-reset-password links (`?invite=<token>`); `ForcePasswordChangeView.jsx` blocks the app until a user issued a temp password sets a real one. |

---

## Accounts

The web UI requires a logged-in account — `AuthView.jsx` blocks the rest of the app until you sign up or log in. The CLI is untouched by any of this: it never authenticates and keeps its own local history/cache scope (`LOCAL_USER_ID` in [cache.py](cache.py)), separate from any web account.

Every account has a role, enforced server-side on every admin route (`require_roles(...)` in [web/app.py](web/app.py)) regardless of what the frontend shows or hides:

| Role | Can do |
|------|--------|
| **Admin** | Everything an Analyst can, plus the Users & Activity Log page: create users, change roles/status, force a password reset, and view any user's (or the global) activity log. |
| **Analyst** | Run scans, view history/pivot/exports, and see their own activity log (My Activity page). Self-service signups default to this role. |

One fixed **bootstrap admin** account (`sireen.akoum@gmail.com`, see `BOOTSTRAP_ADMIN_EMAIL` in [sources/users.py](sources/users.py)) is auto-created — or re-promoted to Admin if it already exists — every time the app starts (`ensure_users_seeded()`), so there's always at least one working Admin even on a wiped/fresh database. It cannot be demoted, suspended, deleted, or have its password reset by another admin.

| Step | What happens |
|------|---------------|
| Self-service sign up (`POST /api/auth/signup`) | Name + email + password (8+ chars). A row is created in `users` (unverified, role `Analyst`), a per-user API key is generated, and a verification email is sent via Brevo. |
| Verify (`GET /api/auth/verify`) | Clicking the emailed link flips `is_verified`; login is rejected until this happens. |
| Admin-created user (`POST /api/admin/users`, Admin only) | Admin picks name, email, and role (Admin or Analyst) from the Users page. If Brevo is configured, an invite email is sent (`?invite=<token>` link → `AcceptInviteView.jsx` sets the first password). If not, the response includes a one-time temp password for the admin to share out of band, and the account is flagged `must_change_password` so `ForcePasswordChangeView.jsx` blocks the app until it's changed. |
| Log in (`POST /api/auth/login`) | Returns a JWT session token (7-day expiry, `JWT_SECRET`-signed), stored in `localStorage` and sent as `Authorization: Bearer <token>` for session-scoped calls (e.g. `/api/history`). Role/status/`must_change_password` are re-read from the DB on every request (`verify_session_token`), so a promotion, demotion, or suspension takes effect immediately rather than waiting for the token to expire. |
| Scan calls | Authenticated via `X-API-Key` (`verify_api_key` in [web/app.py](web/app.py)) rather than the session token — the frontend sends the logged-in user's own key. This also accepts the shared server-wide `API_KEY` env var for external tools/scripts, which fall back to the same unscoped behavior as the CLI. Suspended accounts are rejected here too. |
| Manage users (Admin only) | Promote/demote role (`PATCH /api/admin/users/{id}/role`), suspend/reactivate (`PATCH .../status`), or force a password reset (`POST .../reset-password`, same invite-link-or-temp-password behavior as user creation). Guards prevent an admin from demoting, suspending, or deleting the last remaining Admin (themselves or otherwise via account deletion). |
| Account panel | View/copy your API key, regenerate it (`POST /api/auth/regenerate-key`), or delete your account (`DELETE /api/auth/delete-account`, cascades to your `history`, `cache`, and `activity_log` rows). |

Every login, logout, and scan run is written to `activity_log` (`log_activity()` in [sources/users.py](sources/users.py)). Admins can browse the global log or any single user's log from the Users page; Analysts see only their own, via My Activity — both filterable by event type and date range (`GET /api/admin/activity`, `/api/admin/users/{id}/activity`, `/api/activity/me`).

History and cache rows are scoped per `user_id`, so each account only sees its own scan history and cached results. `/api/scan` and `/api/scan/stream` are rate-limited to 10 requests/minute per API key (`slowapi`).

---

## How it scores

| Score | Verdict |
|-------|---------|
| 0 | Clean |
| 1–3 | Suspicious |
| 4–7 | Low risk |
| 8–11 | Medium risk |
| 12+ | High risk |

The **combined score** is the sum of all active sources' individual scores (capped at 20), plus WHOIS modifier (up to +2) and pivot bonus (up to +6).

### VirusTotal

| Signal | Points |
|--------|--------|
| Malicious engine count (1+, 4+, 10+) | +1 / +2 / +3 |
| Suspicious engine count (3+) | +1 |
| Tier 1 vendor hits | +2 each (cap +6) |
| Tier 2 vendor hits | +1 each (cap +3) |
| Tier 3 vendor hits | +0.5 each (cap +2) |
| Behavioral tags (e.g. c2, botnet, phishing) | +1–4 each (cap +5) |
| Scan recency when malicious (≤7 / ≤30 days) | +2 / +1 |
| Communicating files with malicious detections (1 / 2+) | +1 / +2 |
| Downloaded files with malicious detections (1 / 2+) | +1 / +2 |
| Relations combined cap | +3 |
| Community vote net consensus (≥ 2 / ≥ 5 positive net votes) | +1 / +2 |
| Community vote negative consensus (net votes ≤ −2) | −1 |
| Detection ratio 30–49% / 50–69% / 70%+ (skipped when malicious count ≥ 10) | +1 / +2 / +3 (cap +3) |

Recency scoring only applies when there are active malicious detections **and** the detections clear a minimum threshold (`tier1_hits ≥ 1`, or `tier2_hits ≥ 2`, or `malicious ≥ 4`). Weak single-engine hits do not earn a recency bonus.

### AlienVault OTX

Noise-only pulses (honeypot sensors: `cowrie`, `suricata`, `dionaea`, `tpot`, etc.) are filtered before scoring. Raw pulse *count* is not scored on its own — it only drives the findings label/tier; the score comes entirely from the qualitative signals below.

| Signal | Points |
|--------|--------|
| Negative reputation | +1 |
| OTX reputation threat type (e.g. command and control +4, malicious host/malware distribution/botnet +3, phishing/compromised/tor exit node +2, spam/scanning host/anonymization +1) | cap +4 |
| Recent activity indicator (2025 / 2026 in pulse name, tags, or references) | +1 |
| Pulse tags with weight ≥ 2 (e.g. c2, backdoor, trojan, phishing), summed across non-noise pulses | cap +3 |
| Named APT actor (from known/auto-learned APT list) | +4 (cap +4) |
| Unique malware families from full pulse detail (1 / 2–3 / 4+) | +1 / +2 / +3 (cap +3) |
| ATT&CK technique IDs from full pulse detail (1 / 2–4 / 5+) | +1 / +2 / +3 (+1 for high-impact techniques, cap +3) |
| Passive DNS last seen ≤30 days (requires pulse data or negative reputation) | +1 |

Low-weight tags (`scanner`, `proxy`, `exploit`, etc.) never count — only tags with weight ≥ 2 in the config (seeded from `config.seed.json`, stored in the DB) contribute.

### AbuseIPDB (IPs only)

Attack types are the primary driver; confidence score, recency, and Tor are smaller corroborating signals.

| Signal | Points |
|--------|--------|
| Abuse confidence score ≥ 40% | +1 |
| Last reported ≤7 / ≤30 days (ungated — applies regardless of report volume) | +2 / +1 |
| Tor exit node | +1 |
| High-severity attack types (Phishing, Hacking, Exploited Host, SQL Injection, XSS, DNS Poisoning) | +2 each (cap +4) |
| Medium-severity attack types (Brute-Force, DDoS Attack, Web App Attack, Bad Web Bot, Web Spam, Email Spam, Spoofing) | +1 each (cap +2) |

`Port Scan`, `Ping`, and `Open Proxy` are excluded as scanner noise. On CDN-hosted IPs (`cdn_asns` in config), the combined attack-type bonus is capped at +3 instead of +6, since shared infrastructure legitimately draws mixed reports.

### Shodan (IPs only)

| Signal | Points |
|--------|--------|
| CVEs (1+, 3+, 5+) | +1 / +2 / +3 |
| Malicious product in banner (e.g. Cobalt Strike, Sliver, XMRig) | +2–4 each (cap +6) |
| Shodan tags (e.g. compromised, c2, doublepulsar) | +1–4 each (cap +5) |
| No reverse-DNS hostname | +1 |

**Minimum evidence threshold:** open ports and a missing hostname alone never push the verdict above Clean. A non-clean verdict requires at least one CVE, suspicious product, or high-weight tag (weight ≥ 3).

### Censys (IPs only)

| Signal | Points |
|--------|--------|
| CVEs (1+, 3+, 5+) | +1 / +2 / +3 |
| Malicious product in service banner (cap +6) | +weight each |
| Censys labels matching known threat categories (cap +5) | +1–4 each |

**Minimum evidence threshold:** same as Shodan — a non-clean verdict requires at least one CVE, suspicious product, or high-weight label (weight ≥ 3).

### GreyNoise (IPs only)

GreyNoise "benign" (internet scanner/noise) is excluded from the combined score and noted as context only.

| Signal | Points |
|--------|--------|
| Classification: malicious | +3 |
| Classification: suspicious | +2 |
| Named actor | +2 |
| CVE associated | +1 |

Cap: +6.

### URLhaus (IPs and domains)

| Signal | Points |
|--------|--------|
| Malicious URL count (1 / 2–4 / 5+) | +1 / +2 / +3 |
| Threat type: ransomware / trojan / banker | +3 |
| Threat type: malware / dropper | +2 |

Cap: +8.

### Hybrid Analysis (IPs, domains, and hashes)

| Signal | Points |
|--------|--------|
| Threat score 20–39 / 40–59 / 60–79 / 80+ | +2 / +3 / +4 / +5 |
| Malware family named | +1 |
| Verdict: malicious (no numeric score) | +3 |
| Verdict: suspicious (no numeric score) | +1 |

Cap: +6.

### URLScan (IPs and domains)

| Signal | Points |
|--------|--------|
| Malicious verdict | +3 |
| Threat categories (cap +2) | +1 each |
| Page title contains phishing keywords (e.g. "login", "verify", "account") | +3 (cap +3) |
| Page title contains suspicious infrastructure keywords (e.g. "tor exit", "proxy") | +1 |
| Phishing-keyword domains in scan (cap +4) | +2 each |

### ThreatFox (IPs, domains, URLs, and hashes)

| Signal | Points |
|--------|--------|
| IOC count (1 / 3–9 / 10+) | +1 / +2 / +3 |
| Threat type: botnet_cc (C2 server infrastructure) | +3 |
| Threat type: payload_delivery (malware distribution server) | +2 |
| Threat type: payload (file hash of a malware sample) | +2 |
| Threat type: cc_skimming (credit card skimming infrastructure) | +1 |
| Confidence level 50–74% / 75%+ | +1 / +2 |
| Tags (cap +2) | +weight |
| Malware family named | +1 |

Cap: +10.

### Spamhaus DROP (IPs only)

Spamhaus DROP checks whether the indicator's ASN appears on the [Don't Route Or Peer list](https://www.spamhaus.org/drop/). The list is fetched once and cached in-memory for 6 hours; no API key is required.

| Signal | Points |
|--------|--------|
| ASN on Spamhaus DROP list | +4 |

This bonus is added to the final combined score (after all per-source scores) and is capped at the overall maximum of 20.

### Google Intel (IPs, domains, and hashes)

Google Intel searches threat intelligence sources (Securelist, Talos, Unit42, Mandiant, CrowdStrike, DFIR Report, any.run, MalwareBazaar, etc.) for mentions of the indicator, entirely via a free DuckDuckGo backend (`ddgs`) with `trafilatura` for full-page article extraction — no API key needed. Queries are plain-text (DDG doesn't support Google-style `site:`/`intext:` dork operators); a first round runs indicator-type-aware keyword searches, with a broader second round as a top-up if that comes up short. Trusted sources (Securelist, Unit42, CrowdStrike, etc.) aren't dork-targeted — they're prioritized post-fetch when trimming results to the configured max.

Malware family and APT actor matching draws on a hardcoded seed list plus an **auto-learned entities DB** ([sources/enrichment.py](sources/enrichment.py)): every OTX pulse and ThreatFox result that names a malware family or adversary writes it into `known_malware` / `known_apt_actors` in `reference.db`, so future Google Intel scans and OTX's named-APT-actor scoring recognize it too, even if it's not in the original seed set.

| Signal | Points |
|--------|--------|
| Malware family named (1 / 2–3 / 4+) | +2 / +3 / +4 (cap +4) |
| APT actor named (1 / 2+) | +3 / +4 (cap +4) |
| ATT&CK technique IDs (1 / 2–3 / 4+) | +1 / +2 / +3 (cap +3) |
| CVEs mentioned (1–2 / 3+) | +1 / +2 (cap +2) |
| Severity keywords (e.g. zero-day, active exploitation, ransomware attack) | +1 each (cap +3) |
| Tier-1 sources with signals (1 / 2+) | +1 / +2 (cap +2) |

Cap: +10. Co-mentioned IOCs extracted from articles are not scored here — they are sent to the pivot scanner.

### Pivot scanning (all indicator types)

After every primary scan, co-mentioned IOCs collected from VirusTotal relations, OTX passive DNS, ThreatFox, URLhaus, URLScan, Censys, Shodan, and Google Intel are scanned against a subset of sources. The results add a bonus to the parent indicator's score.

| Signal | Bonus |
|--------|-------|
| Each malicious pivot IOC | +2 (cap +6) |
| Each suspicious pivot IOC | +1 (cap +2) |

Total pivot bonus cap: +6.

### WHOIS (domains only)

WHOIS is a supporting signal — it strengthens existing suspicion but cannot create it from nothing. The final score modifier is capped at +1 when the base score is weak (< 4) and +2 when real threat signal already exists (≥ 4).
| Signal | Points |
|--------|--------|
| Domain age < 7 days | +4 |
| Domain age 7–29 days | +3 |
| Domain age 30–89 days | +2 |
| Domain age 90–364 days | +1 |
| Domain age 365+ days | +0 |
| Privacy / proxy masking on registrant | +1 |
| No registrar found | +1 |

---

## Vendor tiers

VirusTotal vendor hits are weighted by engine reputation (AV-Comparatives 2023–2025).

| Tier | Examples | Weight per hit |
|------|----------|---------------|
| Tier 1 | Bitdefender, ESET, Kaspersky, Avast, AVG, G Data, Norton, Microsoft, Palo Alto Networks, Symantec | +2 (cap 6) |
| Tier 2 | CrowdStrike, Sophos, Trend Micro, McAfee, Malwarebytes, F-Secure, Elastic, VIPRE, Emsisoft, Total Defense, Fortect, K7 | +1 (cap 3) |
| Tier 3 | All other VT vendors | +0.5 (cap 2) |

Vendor name aliases (e.g. `ESET-NOD32` → `ESET`) are resolved via the config (see [Config](#config) below).

---

## Project structure

| File | Responsibility |
|------|----------------|
| [main.py](main.py) | Input loop, history commands, brief and verbose report display |
| [detect.py](detect.py) | Detects whether input is an IP, domain, or hash |
| [sources/enrichment.py](sources/enrichment.py) | Auto-learned entities DB (`known_malware`, `known_apt_actors`, `known_tools`) in `reference.db` — fed by OTX and ThreatFox, consulted by Google Intel and OTX scoring |
| [sources/vt.py](sources/vt.py) | VirusTotal lookups + rescan requests |
| [sources/otx.py](sources/otx.py) | AlienVault OTX lookups + passive DNS |
| [sources/abuseipdb.py](sources/abuseipdb.py) | AbuseIPDB lookups |
| [sources/shodan.py](sources/shodan.py) | Shodan lookups — open ports, CVEs, banners, tags |
| [sources/censys.py](sources/censys.py) | Censys v3 lookups — ports, services, CVEs, labels, hostnames, favicons, SSH fingerprints |
| [sources/whois.py](sources/whois.py) | WHOIS lookups — domain age, registrar, privacy masking |
| [sources/greynoise.py](sources/greynoise.py) | GreyNoise community lookups — classification, actor, CVE (IPs only) |
| [sources/urlhaus.py](sources/urlhaus.py) | URLhaus lookups — malicious URL count and threat type (IPs and domains) |
| [sources/urlscan.py](sources/urlscan.py) | URLScan lookups — malicious verdict, categories, page title, phishing domains |
| [sources/hybrid.py](sources/hybrid.py) | Hybrid Analysis lookups — threat score and malware family (IPs, domains, hashes) |
| [sources/threatfox.py](sources/threatfox.py) | ThreatFox lookups — IOC count, threat type, malware family, confidence (IPs, domains, URLs, hashes) |
| [sources/spamhaus.py](sources/spamhaus.py) | Spamhaus DROP ASN lookup — in-memory cache, 6 h TTL, no API key required (IPs only) |
| [sources/google_intel.py](sources/google_intel.py) | Google Intel — threat intel site searches via DuckDuckGo (`ddgs`); extracts malware families, APT actors, ATT&CK IDs, CVEs, and co-mentioned IOCs |
| [sources/pivot.py](sources/pivot.py) | Pivot scanner — collects co-mentioned IOCs from all sources, scans them against a subset of sources, and builds the brief/verbose report text (moved here from `main.py`) |
| [sources/scoring.py](sources/scoring.py) | Per-source scoring, combined verdict logic, pivot scoring |
| [output.py](output.py) | History (save, list, retrieve, clear) + report builders: CSV evidence rows, structured JSON report, and the trimmed LLM digest used for the AI summary |
| [cache.py](cache.py) | SQLite cache (`ioc_cache.db`) — your scan history and per-lookup result cache, no expiry, gitignored (personal, per-deployment) |
| [sources/app_config.py](sources/app_config.py) | DB-backed config store (key-value + change history); config is now loaded from the DB, not a file — [config.seed.json](config.seed.json) is only the one-time import source / exportable backup |
| [sources/users.py](sources/users.py) | Accounts, roles, and activity log: table schema/self-heal, bootstrap-admin seeding, and `log_activity()`. See [Accounts](#accounts) above |
| [scripts/import_config_to_db.py](scripts/import_config_to_db.py) | CLI to force-reseed `app_config` from `config.seed.json` (`--force`); not required for normal boot, see [Config](#config) |
| [scripts/migrate_history_user_scoping.py](scripts/migrate_history_user_scoping.py) | One-time CLI to assign pre-existing `history`/`cache` rows (from before per-user scoping existed) to a given account (`--user-id`, `--dry-run`); not needed on a fresh install |
| [llm/ioc_llm.py](llm/ioc_llm.py) | Calls a local Ollama model (`qwen2.5:3b-instruct`) to generate/stream the AI Analyst Summary from the report digest |
| [web/docx_export.py](web/docx_export.py) | Builds the formatted Word (.docx) report served by `/api/report/docx` |
| [web/app.py](web/app.py) | FastAPI backend — serves the React frontend, exposes scan/history/report/AI-summary endpoints, and handles accounts (signup, email verification via Brevo, JWT session login, per-user API keys) and rate limiting |
| [web/frontend/](web/frontend/) | React + Vite frontend — browser-based UI for running scans, viewing history, exporting reports, and the pivot graph |

---

## Config

Scoring config (vendor tiers, tag weights, suspicious ports/products, trusted ASNs, known APT actor seed list, etc.) lives in the `app_config` table inside `ioc_cache.db`, managed by [sources/app_config.py](sources/app_config.py). [config.seed.json](config.seed.json) is only the one-time import source on first run and a manual backup target (`export_config_to_json`) — editing it after the DB has been seeded has no effect. Every write is logged to `app_config_history` with the old and new value.

A fresh `ioc_cache.db` (new clone, new deploy, a redeploy on a platform with an ephemeral filesystem) has no config in it yet. Both `main.py` and `web/app.py` call `ensure_seeded()` ([sources/app_config.py](sources/app_config.py)) at import time, before anything that depends on config loads — so this self-heals automatically on every process start, no manual step required. [scripts/import_config_to_db.py](scripts/import_config_to_db.py) still exists for forcing a reseed after editing `config.seed.json` (`--force`), but you don't need to run it just to get a fresh deploy working.

### Reference data vs. personal data

The SQLite state is deliberately split across two files:

- **`reference.db`** — `known_malware` / `known_apt_actors` / `known_tools` ([sources/enrichment.py](sources/enrichment.py)): shared threat-intel lookup tables, the same for every deployment. Committed to git, so a fresh clone/deploy has full matching coverage immediately — no seed step needed. It does grow locally as OTX/ThreatFox pulls name new entities during scans (`add_known_entity`); commit it again whenever you want to publish an updated baseline.
- **`ioc_cache.db`** — `cache` (per-lookup result cache) and `history` (your scan history), plus the `app_config` config store above. Personal/per-deployment, gitignored, starts empty on every fresh deploy.

`IOC_REFERENCE_DB_PATH` overrides where `reference.db` is read from/written to (default: repo root), independent of `IOC_DB_PATH` below.

---

## Deployment

```bash
cp .env.example .env    # fill in your API keys
cd web/frontend && npm install && npm run build && cd ../..
uvicorn app:app --app-dir web --host 0.0.0.0 --port 8000
```

Config seeding happens automatically on startup (see [Config](#config) above) — no separate seed step needed, including on platforms that wipe the filesystem between deploys. `reference.db` ships committed in the repo, so entity-matching coverage is there from the first request too.

`IOC_DB_PATH` (see [cache.py](cache.py)) controls where `ioc_cache.db` is written — point it at a persistent location if your deploy target has an ephemeral filesystem (this is your scan history, cache, and accounts, so it's worth persisting; `reference.db` doesn't need this since it's committed to git and gets reset to the last commit on every redeploy anyway). `OLLAMA_URL`/`OLLAMA_MODEL` (see [llm/ioc_llm.py](llm/ioc_llm.py)) let the AI Analyst Summary reach an Ollama instance running elsewhere than `localhost:11434` — useful if it's not on the same host as the app.

Set `FRONTEND_URL` to your deployed URL (defaults to `http://localhost:8000`) — it's used to build the link inside the signup verification email, so on a real deploy it must point at the public host, not localhost. `JWT_SECRET`, `BREVO_API_KEY`, and `BREVO_SENDER_EMAIL` are required for accounts to work at all (see [Accounts](#accounts) above).

---

## Disclaimer

For educational and authorized security research only.
