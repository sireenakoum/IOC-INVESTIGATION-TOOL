# IOC Investigation Tool

> A threat intelligence tool that hunts down malicious IPs, domains, and file hashes so analysts don't have to do it manually.

## What it does

Give it an IP, domain, or file hash — it tells you if it's dangerous.

- Checks **VirusTotal** + **AlienVault OTX** + **AbuseIPDB**
- Requests a fresh VirusTotal re-scan before pulling the report, instead of relying purely on a stale cached result
- Gives a **verdict** (Clean / Suspicious / Low / Medium / High risk) with a configurable aggregation mode
- Shows **why** — full score breakdown per signal, per source
- Saves every lookup to a local SQLite database (`ioc_cache.db`) so history can be queried and replayed
- Caches VT/OTX results for 7 days to avoid repeat API calls

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
```

Run it:

```bash
python main.py
```

---

## Usage

At the prompt, enter any of the following:

| Input | Action |
|-------|--------|
| An IPv4 address | Check IP against all three sources |
| A domain name | Check domain against VT and OTX |
| An MD5/SHA1/SHA256 hash | Check file hash against VT and OTX |
| `history` | List all past lookups (newest first) |
| `history <n>` | Replay the full report for entry #n from history |
| `exit` / `quit` / `q` | Exit the tool |

---

## How it scores

Each source produces its own score and verdict, then they are combined into a final verdict.

| Score | Verdict |
|-------|---------|
| 0 | Clean |
| 1–2 | Suspicious |
| 3–4 | Low risk |
| 5–7 | Medium risk |
| 8+ | High risk |

### VirusTotal

| Signal | Points |
|--------|--------|
| Malicious engine count (1+, 4+, 10+) | +1 / +2 / +3 |
| Suspicious engine count (3+) | +1 |
| Tier 1 vendor hits | +2 each (cap +6) |
| Tier 2 vendor hits | +1 each (cap +3) |
| Tier 3 vendor hits | +0.5 each (cap +2) |
| Matching behavioral tags (e.g. c2, botnet, phishing) | +1–4 each (cap +5) |
| Scan recency when malicious (≤7 days / ≤30 days / >180 days) | +2 / +1 / -1 |
| Harmless majority (30+/50+ engines clean, no detections) | -1 / -2 |

### AlienVault OTX

OTX pulse and passive DNS signals are gated behind a VT score ≥ 1 to suppress false positives from unvetted community submissions. Adversary attribution and malware families fire independently.

| Signal | Points |
|--------|--------|
| Pulse count (1+, 10+) | +1 / +2 (gated) |
| Negative reputation | +1 |
| Recent pulse name containing 2025 or 2026 | +1 (gated) |
| Pulse tags matching threat categories | +1–4 each (cap +5, gated) |
| Named adversary (known APT / other) | +4 / +2 (cap +4) |
| Named malware family | +2 (cap +4) |
| Passive DNS last seen ≤30 days | +1 (gated) |

### AbuseIPDB (IPs only)

| Signal | Points |
|--------|--------|
| Abuse confidence score (10+, 40+, 80+) | +1 / +2 / +3 |
| Distinct reporters (10+, 50+) | +1 / +2 |
| Last reported ≤7 days / >180 days | +1 / -1 |
| Tor exit node | +1 |

---

## Vendor tiers

VirusTotal vendor hits are weighted by engine reputation, sourced from AV-Comparatives Consumer & Business Main-Test Series 2023–2025.

| Tier | Examples | Weight per hit |
|------|----------|---------------|
| Tier 1 | Bitdefender, ESET, Kaspersky, CrowdStrike, Norton, Avast | +2 (cap 6) |
| Tier 2 | Microsoft, Sophos, Trend Micro, Malwarebytes, Elastic | +1 (cap 3) |
| Tier 3 | All other VT vendors | +0.5 (cap 2) |

Vendor name aliases (e.g. `ESET-NOD32` → `ESET`) are resolved automatically via `config.json`.

---

## Verdict modes

The final verdict combines the three per-source scores. Three modes are available and set via `config.json` (`default_verdict_mode`):

| Mode | Behavior |
|------|----------|
| `worst_case` (default) | Takes the highest verdict across all active sources — most conservative |
| `average` | Averages raw scores then maps to a verdict — balances all sources equally |
| `weighted` | Blends verdicts using fixed weights (VT 50%, OTX 30%, AbuseIPDB 20%), renormalized when a source has no data |

Confidence is derived from cross-source corroboration: the more sources that agree on the final verdict, the higher the confidence.

---

## Project structure

| File | Responsibility |
|------|----------------|
| [main.py](main.py) | Input loop, history commands, report display |
| [detect.py](detect.py) | Detects whether input is an IP, domain, or hash |
| [vt.py](vt.py) | VirusTotal lookups + rescan requests |
| [otx.py](otx.py) | AlienVault OTX lookups |
| [abuseipdb.py](abuseipdb.py) | AbuseIPDB lookups — abuse score, report history, attack categories |
| [scoring.py](scoring.py) | Per-source scoring, vendor tier resolution, combined verdict logic |
| [output.py](output.py) | History table (save, list, retrieve entries) |
| [cache.py](cache.py) | SQLite-backed cache (`ioc_cache.db`) for VT/OTX results (7-day TTL) |
| [config.json](config.json) | Vendor tiers, tag weights, APT actor list, scoring caps, verdict mode |

---

## Roadmap

- CSV / PDF report export

---

## Disclaimer

For educational and authorized security research only.
