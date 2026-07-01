# IOC Investigation Tool

A threat intelligence aggregator that checks IPs, domains, and file hashes against VirusTotal, AlienVault OTX, AbuseIPDB, Shodan, Censys, WHOIS, GreyNoise, URLhaus, URLScan, Hybrid Analysis, ThreatFox, Spamhaus DROP, and Google Intel, then issues a scored verdict. Co-mentioned IOCs discovered during a scan are automatically pivot-scanned.

---

## Quick start

```bash
pip install -r requirements.txt
```

Add a `.env` file:

```
VT_API_KEY=your_key
OTX_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
SHODAN_API_KEY=your_key
WHOIS_API_KEY=your_key
CENSYS_API_KEY=your_bearer_token
URLSCAN_API_KEY=your_key          # optional
HYBRID_API_KEY=your_key           # optional
URLHAUS_API_KEY=your_key          # optional; also used for ThreatFox
SCALESERP_KEY=your_key            # optional; enables Google dork search for Google Intel
SERPAPI_KEY=your_key              # optional; fallback Google search API for Google Intel
```

The Censys token is the Bearer token shown in your account at search.censys.io → API. Censys is optional — the tool works without it, but Shodan+Censys corroboration scoring requires it.

GreyNoise uses the free community endpoint and requires no API key.

Spamhaus DROP uses a public feed and requires no API key.

Google Intel falls back to free search backends (DuckDuckGo, `googlesearch-python`) when no API key is provided. ScaleSerp or SerpApi unlock full Google dork support.

Run (CLI):

```bash
python main.py
```

Run (Web UI):

```bash
cd web
uvicorn app:app --reload
```

Then open `http://localhost:8000` in your browser.

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

---

## How it scores

| Score | Verdict |
|-------|---------|
| 0 | Clean |
| 1–3 | Suspicious |
| 4–7 | Low risk |
| 8–11 | Medium risk |
| 12+ | High risk |

The **combined score** is the sum of all active sources' individual scores (capped at 20), plus WHOIS modifier (up to +2), Shodan+Censys corroboration bonus (up to +4), and pivot bonus (up to +6).

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

Noise-only pulses (honeypot sensors: `cowrie`, `suricata`, `dionaea`, `tpot`, etc.) are filtered before scoring.

| Signal | Points |
|--------|--------|
| Non-noise pulse count (1) | +1 |
| Non-noise pulse count (2–4) | +2 with qualitative signal / +1 volume-only |
| Non-noise pulse count (5–9) | +3 with qualitative signal / +1 volume-only |
| Non-noise pulse count (10+) | +4 with qualitative signal / +1 volume-only |
| Negative reputation | +1 |
| OTX reputation threat type (C2, botnet, phishing, malware distribution, etc.) | up to +4 (cap +4) |
| Recent activity indicator (2025 / 2026 in pulse name, tags, or references) | +1 |
| Pulse tags with weight ≥ 2 (e.g. c2, backdoor, trojan, phishing) | +2–4 each (cap +5) |
| Named APT actor (from known APT list) | +4 (cap +4) |
| Unique malware families from full pulse detail (1 / 2–3 / 4+) | +1 / +2 / +3 (cap +3) |
| ATT&CK technique IDs from full pulse detail (1 / 2–4 / 5+) | +1 / +2 / +3 (+1 for high-impact techniques, cap +3) |
| Passive DNS last seen ≤30 days | +1 |

Pulse volume alone is capped at +1 unless at least one **qualitative signal** is present (high-weight tag, APT actor, malware family, or ATT&CK technique). Qualitative signals unlock the tiered pulse bonus. Low-weight tags (`scanner`, `proxy`, `exploit`, etc.) never count — only tags with weight ≥ 2 in `config.json` contribute.

### AbuseIPDB (IPs only)

| Signal | Points |
|--------|--------|
| Abuse confidence score (40–79% / 80%+) | +1 / +2 |
| Distinct reporters (5+, 20+, 50+, 100+, 500+) | +1 / +2 / +3 / +4 / +5 |
| Last reported ≤7 / ≤30 days (requires ≥ 10 distinct reporters) | +2 / +1 |
| Tor exit node | +1 |
| High-severity attack types (e.g. Phishing, Hacking, SQL Injection) | +2 each (cap +4) |
| Medium-severity attack types (e.g. Brute-Force, SSH) | +1 each (cap +2) |

### Shodan (IPs only)

| Signal | Points |
|--------|--------|
| CVEs (1+, 3+, 5+) | +1 / +2 / +3 |
| Suspicious ports (e.g. 4444, 31337, 6667) | scored only via Shodan+Censys corroboration |
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

### Shodan + Censys corroboration (IPs only)

Nine cross-source signals confirm whether two independent scanners agree. Total bonus is capped at +4.

| Signal | Bonus |
|--------|-------|
| Suspicious port seen by both scanners (sum of port weights, cap 4) | +1–4 |
| CVE confirmed by both scanners | +1 |
| Suspicious product confirmed by both scanners | +1 |
| Matching product/version banner on the same port | +1 |
| TLS certificate fingerprint match | +2 |
| Service overlap ≥ 70% (excluding common ports, 3+ ports each side) | +1 |
| Both scanned within 7 days | +1 |
| Favicon hash match (Shodan vs Censys) | +1 |
| SSH host key fingerprint match (Shodan vs Censys) | +1 |

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

This bonus is added to the final combined score (after all per-source scores and corroboration) and is capped at the overall maximum of 20.

### Google Intel (IPs, domains, and hashes)

Google Intel searches threat intelligence sources (Securelist, Talos, Unit42, Mandiant, CrowdStrike, DFIR Report, any.run, MalwareBazaar, etc.) for mentions of the indicator using Google dorks. It uses ScaleSerp or SerpApi if configured, and falls back to free search backends (DuckDuckGo, `googlesearch-python`) otherwise.

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

Vendor name aliases (e.g. `ESET-NOD32` → `ESET`) are resolved via `config.json`.

---

## Project structure

| File | Responsibility |
|------|----------------|
| [main.py](main.py) | Input loop, history commands, brief and verbose report display |
| [detect.py](detect.py) | Detects whether input is an IP, domain, or hash |
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
| [sources/google_intel.py](sources/google_intel.py) | Google Intel — threat intel site searches via ScaleSerp / SerpApi / free backends; extracts malware families, APT actors, ATT&CK IDs, CVEs, and co-mentioned IOCs |
| [sources/pivot.py](sources/pivot.py) | Pivot scanner — collects co-mentioned IOCs from all sources and scans them against a subset of sources |
| [sources/scoring.py](sources/scoring.py) | Per-source scoring, combined verdict logic, Shodan+Censys corroboration, pivot scoring |
| [output.py](output.py) | History (save, list, retrieve, clear) |
| [cache.py](cache.py) | SQLite cache (`ioc_cache.db`), no expiry |
| [config.json](config.json) | Vendor tiers, tag weights, suspicious ports/products, trusted ASNs, APT actors |
| [web/app.py](web/app.py) | FastAPI backend — serves the React frontend and exposes scan/history endpoints |
| [web/frontend/](web/frontend/) | React + Vite frontend — browser-based UI for running scans and viewing history |

---

## Disclaimer

For educational and authorized security research only.
