# IOC Investigation Tool

A threat intelligence aggregator that checks IPs, domains, and file hashes against VirusTotal, AlienVault OTX, AbuseIPDB, Shodan, Censys, WHOIS, GreyNoise, URLhaus, URLScan, and Hybrid Analysis, then issues a scored verdict.

---

## Quick start

```bash
pip install requests python-dotenv
```

Add a `.env` file:

```
VT_API_KEY=your_key
OTX_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
SHODAN_API_KEY=your_key
WHOIS_API_KEY=your_key
CENSYS_API_TOKEN=your_bearer_token
URLSCAN_API_KEY=your_key          # optional
HYBRID_API_KEY=your_key           # optional
URLHAUS_API_KEY=your_key          # optional
```

The Censys token is the Bearer token shown in your account at search.censys.io → API. Censys is optional — the tool works without it, but Shodan+Censys corroboration scoring requires it.

GreyNoise uses the free community endpoint and requires no API key.

Run:

```bash
python main.py
```

---

## Usage

| Input | Action |
|-------|--------|
| IPv4 address | Check against VT, OTX, AbuseIPDB, Shodan, Censys, GreyNoise, URLhaus, and URLScan |
| Domain name | Check against VT, OTX, WHOIS, URLhaus, URLScan, and Hybrid Analysis |
| MD5 / SHA1 / SHA256 hash | Check against VT, OTX, and Hybrid Analysis |
| `verbose` | Switch to full breakdown view |
| `brief` | Switch to summary view (default) |
| `history` | List all past lookups |
| `history <n>` | Replay report for entry #n |
| `history clear` | Delete all history (prompts for confirmation) |
| `reset cache` | Clear all cached API results (prompts for confirmation) |
| `rescan <indicator>` | Delete cache and history for that indicator, then re-query all sources |
| `help` | Show command reference |
| `exit` / `quit` / `q` | Exit |

Results are saved to `ioc_cache.db` (SQLite). Results are cached indefinitely; use `cache clear` or `cache clear <ioc>` to invalidate entries manually.

---

## How it scores

| Score | Verdict |
|-------|---------|
| 0 | Clean |
| 1–3 | Suspicious |
| 4–7 | Low risk |
| 8–13 | Medium risk |
| 14+ | High risk |

The **combined score** is the sum of all active sources' individual scores (capped at 20), plus WHOIS modifier (up to +2) and Shodan+Censys corroboration bonus (up to +4).

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

Recency scoring only applies when there are active malicious detections **and** the detections clear a minimum threshold (`malicious ≥ 2`, or `tier1_hits ≥ 1`, or `tier2_hits ≥ 2`). Weak single-engine hits do not earn a recency bonus.

### AlienVault OTX

Noise-only pulses (honeypot sensors: `cowrie`, `suricata`, `dionaea`, `tpot`, etc.) are filtered before scoring.

| Signal | Points |
|--------|--------|
| Quality pulse count (20+ non-noise) | +1 |
| Negative reputation | +1 |
| Recent activity indicator (2025 / 2026 in pulse name, tags, or references) | +1 |
| Pulse tags matching threat categories | +1–4 each (cap +5) |
| Named APT actor (from known APT list) | +4 (cap +4) |
| Named malware family | +2 (cap +4) |
| Passive DNS last seen ≤30 days | +1 |

### AbuseIPDB (IPs only)

| Signal | Points |
|--------|--------|
| Abuse confidence score (40–79% / 80%+) | +1 / +2 |
| Distinct reporters (5+, 20+, 50+, 100+, 500+) | +1 / +2 / +3 / +4 / +5 |
| Last reported ≤7 / ≤30 days | +2 / +1 |
| Tor exit node | +1 |
| High-severity attack types (e.g. Phishing, Hacking, SQL Injection) | +2 each (cap +4) |
| Medium-severity attack types (e.g. Brute-Force, SSH) | +1 each (cap +2) |

### Shodan (IPs only)

| Signal | Points |
|--------|--------|
| CVEs (1+, 3+, 5+) | +1 / +2 / +3 |
| Suspicious ports (e.g. 4444, 31337, 6667) | +weight each (cap +4) |
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
| Phishing-keyword domains in scan (cap +4) | +2 each |

### WHOIS (domains only)

WHOIS is a supporting signal — it strengthens existing suspicion but cannot create it from nothing. The final score modifier is capped at +1 when the base score is weak (< 4) and +2 when real threat signal already exists (≥ 4). The WHOIS source verdict is capped at Medium risk.

| Signal | Points |
|--------|--------|
| Domain age < 7 days | +4 |
| Domain age 7–29 days | +3 |
| Domain age 30–89 days | +2 |
| Domain age 90–364 days | +1 |
| Domain age 365+ days | +0 |
| Privacy / proxy masking on registrant | +1 |
| No registrar found | +1 |

### Trusted ASNs

IPs on CDN or cloud-hosting ASNs (Cloudflare, Fastly, Akamai, AWS, Azure, Google Cloud) have the final combined verdict capped at Medium risk, regardless of the raw score.

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
| [sources/censys.py](sources/censys.py) | Censys v2 lookups — ports, services, CVEs, labels |
| [sources/whois.py](sources/whois.py) | WHOIS lookups — domain age, registrar, privacy masking |
| [sources/greynoise.py](sources/greynoise.py) | GreyNoise community lookups — classification, actor, CVE (IPs only) |
| [sources/urlhaus.py](sources/urlhaus.py) | URLhaus lookups — malicious URL count and threat type (IPs and domains) |
| [sources/urlscan.py](sources/urlscan.py) | URLScan lookups — malicious verdict, categories, phishing domains |
| [sources/hybrid.py](sources/hybrid.py) | Hybrid Analysis lookups — threat score and malware family (IPs, domains, hashes) |
| [sources/scoring.py](sources/scoring.py) | Per-source scoring, combined verdict logic, Shodan+Censys corroboration |
| [output.py](output.py) | History (save, list, retrieve, clear) |
| [cache.py](cache.py) | SQLite cache (`ioc_cache.db`), no expiry |
| [config.json](config.json) | Vendor tiers, tag weights, suspicious ports/products, trusted ASNs, APT actors |

---

## Disclaimer

For educational and authorized security research only.
