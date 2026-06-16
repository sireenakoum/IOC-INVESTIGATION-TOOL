# 🛡️ IOC Investigation Tool

> Built during my cybersecurity internship — a threat intelligence tool that hunts down malicious IPs, domains, and file hashes so analysts don't have to do it manually.

---

## 🔍 What it does

Give it an IP, domain, or file hash — it tells you if it's dangerous.

- Checks **VirusTotal** + **AlienVault OTX** simultaneously
- Gives a **verdict** (Clean / Suspicious / Medium / High risk)
- Shows **why** — full score breakdown per signal
- Caches results so repeat lookups are instant
- Exports reports to **JSON**, **CSV**, and **PDF**

---

## 🚀 Quick start

```bash
pip install requests python-dotenv fpdf2 aiohttp tqdm
```

Add a `.env` file:
VT_API_KEY=your_key
OTX_API_KEY=your_key

Run it:
```bash
python main2.py
```

---

## 🧠 How it scores

| Score | Verdict |
|-------|---------|
| 0 | ✅ Clean |
| 1–2 | ⚠️ Suspicious |
| 3–4 | 🟡 Low risk |
| 5–7 | 🟠 Medium risk |
| 8+ | 🔴 High risk |

---

## 🛠️ Built with

`Python` · `VirusTotal API` · `AlienVault OTX` · `SQLite` · `aiohttp` · `fpdf2`

---

## ⚠️ Disclaimer
For educational and authorized security research only.