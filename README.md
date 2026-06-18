# IOC Investigation Tool

A threat intelligence aggregator that checks IPs, domains, and file hashes against VirusTotal, AlienVault OTX, AbuseIPDB, and Shodan, then issues a scored verdict.

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
```

Run:

```bash
python main.py
```

---

## Usage

| Input | Action |
|-------|--------|
| IPv4 address | Check against all four sources |
| Domain name | Check against VT and OTX |
| MD5 / SHA1 / SHA256 hash | Check against VT and OTX |
| `verbose` | Switch to full breakdown view |
| `brief` | Switch to summary view (default) |
| `mode [weighted\|worst_case\|average]` | Show or change verdict mode |
| `history` | List all past lookups |
| `history <n>` | Replay report for entry #n |
| `history clear` | Delete all history (prompts for confirmation) |
| `reset cache` | Clear all cached API results (prompts for confirmation) |
| `help` | Show command reference |
| `exit` / `quit` / `q` | Exit |

Results are saved to `ioc_cache.db` (SQLite). VT/OTX results are cached for 7 days.

---

## How it scores

| Score | Verdict |
|-------|---------|
| 0 | Clean |
| 1–2 | Suspicious |
| 3–4 | Low risk |
| 5–7 | Medium risk |
| 8+ | High risk |

The displayed **avg score** is the mean of all active sources' individual scores.

### VirusTotal

| Signal | Points |
|--------|--------|
| Malicious engine count (1+, 4+, 10+) | +1 / +2 / +3 |
| Suspicious engine count (3+) | +1 |
| Tier 1 vendor hits | +2 each (cap +6) |
| Tier 2 vendor hits | +1 each (cap +3) |
| Tier 3 vendor hits | +0.5 each (cap +2) |
| Behavioral tags (e.g. c2, botnet, phishing) | +1–4 each (cap +5) |
| Scan recency when malicious (≤7 / ≤30 / >180 days) | +2 / +1 / −1 |
| Harmless majority (30+ / 50+ engines clean) | −1 / −2 |

Confidence is tier-aware: 2+ Tier-1 hits → high; 1 Tier-1 or 2+ Tier-2 hits → medium.

### AlienVault OTX

Noise-only pulses (honeypot sensors: `cowrie`, `suricata`, `dionaea`, `tpot`, etc.) are filtered before scoring.

| Signal | Points |
|--------|--------|
| Quality pulse count (20+ non-noise) | +1 |
| Negative reputation | +1 |
| Recent pulse name (2025 / 2026) | +1 |
| Pulse tags matching threat categories | +1–4 each (cap +5) |
| Named adversary (known APT / other) | +4 / +2 (cap +4) |
| Named malware family | +2 (cap +4) |
| Passive DNS last seen ≤30 days | +1 |

Confidence is quality-driven: adversary/family attribution → high; tag matches → medium; any pulses → low.

### AbuseIPDB (IPs only)

| Signal | Points |
|--------|--------|
| Abuse confidence score (10+, 40+, 80+) | +1 / +2 / +3 |
| Distinct reporters ≥10 (even at 0% confidence) | +1 |
| Distinct reporters (10+, 50+) when confidence > 0 | +1 / +2 |
| Last reported ≤7 days / >180 days | +1 / −1 |
| Tor exit node | +1 |

### Shodan (IPs only)

| Signal | Points |
|--------|--------|
| CVEs (1+, 3+, 5+) | +1 / +2 / +3 |
| Suspicious ports (e.g. 4444, 31337, 6667) | +weight each (cap +4) |
| Malicious product in banner (e.g. Cobalt Strike, Sliver, XMRig) | +2–4 each (cap +6) |
| Shodan tags (e.g. compromised, c2, doublepulsar) | +1–4 each (cap +5) |
| No reverse-DNS hostname | +1 |

**Minimum evidence threshold:** open ports and a missing hostname alone never push the verdict above Clean. A non-clean verdict requires at least one CVE, suspicious product, or high-weight tag (weight ≥ 3).

**Trusted ASNs** (Cloudflare AS13335, Google AS15169, Amazon AS16509, Microsoft AS8075, Fastly AS54113, Akamai AS20940): port scoring and the hostname penalty are skipped. Only CVEs, confirmed malicious products, and tags with weight ≥ 3 are scored. The final verdict is globally capped at Medium risk.

---

## Vendor tiers

VirusTotal vendor hits are weighted by engine reputation (AV-Comparatives 2023–2025).

| Tier | Examples | Weight per hit |
|------|----------|---------------|
| Tier 1 | Bitdefender, ESET, Kaspersky, Avast, AVG, G Data, Norton, Microsoft, Palo Alto Networks, Symantec | +2 (cap 6) |
| Tier 2 | CrowdStrike, Sophos, Trend Micro, McAfee, Malwarebytes, F-Secure, Elastic, VIPRE, Emsisoft | +1 (cap 3) |
| Tier 3 | All other VT vendors | +0.5 (cap 2) |

Vendor name aliases (e.g. `ESET-NOD32` → `ESET`) are resolved via `config.json`.

---

## Verdict modes

Configured via `default_verdict_mode` in `config.json`:

| Mode | Behavior |
|------|----------|
| `weighted` **(default)** | Blends verdicts using fixed weights (VT 40%, OTX 25%, AbuseIPDB 15%, Shodan 20%), scaled by source reliability, renormalized for active sources |
| `worst_case` | Highest verdict across active sources — most conservative |
| `average` | Averages raw scores scaled by source reliability, then maps to a verdict |

**Source reliability** scales each source's contribution before blending:

| Source | Reliability |
|--------|------------|
| VirusTotal | 1.0 |
| OTX | 0.8 |
| Shodan | 0.7 |
| AbuseIPDB | 0.6 |

---

## Confidence

The displayed **Confidence** value is blended: it reconciles per-source detection quality against cross-source corroboration. A single high-signal source with weak consensus resolves to low/medium rather than high.

**Proximity-based consensus:** a source corroborates if its verdict is within one step of the final verdict (e.g. Medium supports a High final verdict).

---

## Project structure

| File | Responsibility |
|------|----------------|
| [main.py](main.py) | Input loop, history/mode commands, brief and verbose report display |
| [detect.py](detect.py) | Detects whether input is an IP, domain, or hash |
| [vt.py](vt.py) | VirusTotal lookups + rescan requests |
| [otx.py](otx.py) | AlienVault OTX lookups + passive DNS |
| [abuseipdb.py](abuseipdb.py) | AbuseIPDB lookups |
| [shodan.py](shodan.py) | Shodan lookups — open ports, CVEs, banners, tags |
| [scoring.py](scoring.py) | Per-source scoring, combined verdict logic |
| [output.py](output.py) | History (save, list, retrieve, clear) |
| [cache.py](cache.py) | SQLite cache (`ioc_cache.db`), 7-day TTL |
| [config.json](config.json) | Vendor tiers, tag weights, suspicious ports/products, trusted ASNs, APT actors, source reliability, verdict mode |

---

## Disclaimer

For educational and authorized security research only.
