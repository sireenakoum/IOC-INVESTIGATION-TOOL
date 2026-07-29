import sqlite3
import json
import datetime

from cache import DB_PATH
from sources.scoring import VERDICT_DISPLAY

def print_history():
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, indicator, verdict
        FROM history
        ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("  No past lookups found.")
        return

    print(f"\n  {'─'*45}")
    print(f"  Past Lookups")
    print(f"  {'─'*45}")

    for i, (timestamp, indicator, verdict) in enumerate(rows, 1):
        display = VERDICT_DISPLAY.get(verdict, verdict)
        print(f"  {i}. {indicator:<20} {display:<20} {timestamp}")

    print(f"  {'─'*45}\n")

_HISTORY_COLUMNS = [
    "id", "timestamp", "indicator", "vt_result", "otx_result", "abuse_result", "shodan_result", "verdict",
    "whois_result", "score", "per_source", "censys_result", "greynoise_result", "urlhaus_result", "urlscan_result",
    "hybrid_result", "spamhaus_drop_result", "threatfox_result", "google_intel_result", "pivot_result", "breakdown",
    "recommendation", "consensus_ratio", "triggered_by", "active_sources", "inactive_sources", "contribution",
    "ai_summary", "user_id",
]

def init_history_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            indicator   TEXT NOT NULL,
            vt_result   TEXT,
            otx_result  TEXT,
            abuse_result TEXT,
            shodan_result TEXT,
            verdict     TEXT,
            user_id     INTEGER,
            UNIQUE(indicator, user_id)
        )
    """)
    conn.commit()
    for col, col_type in [("whois_result", "TEXT"), ("score", "REAL"), ("per_source", "TEXT"), ("censys_result", "TEXT"),
                          ("greynoise_result", "TEXT"), ("urlhaus_result", "TEXT"), ("urlscan_result", "TEXT"), ("hybrid_result", "TEXT"),
                          ("spamhaus_drop_result", "TEXT"), ("threatfox_result", "TEXT"), ("google_intel_result", "TEXT"),
                          ("pivot_result", "TEXT"), ("breakdown", "TEXT"), ("recommendation", "TEXT"), ("consensus_ratio", "TEXT"),
                          ("triggered_by", "TEXT"), ("active_sources", "TEXT"), ("inactive_sources", "TEXT"), ("contribution", "TEXT"),
                          ("ai_summary", "TEXT"), ("user_id", "INTEGER")]:
        try:
            conn.execute(f"ALTER TABLE history ADD COLUMN {col} {col_type}")
            conn.commit()
        except sqlite3.OperationalError:
            pass

    _migrate_history_unique_constraint(conn)
    conn.close()

def _migrate_history_unique_constraint(conn):
    """Older installs created `history` with indicator alone UNIQUE, which
    forces every user to share one row per indicator (a second user's scan
    silently overwrites and reassigns the first user's row). Rebuild onto a
    table-level UNIQUE(indicator, user_id) so each user gets their own row.
    SQLite can't ALTER a column-level UNIQUE constraint away in place, so this
    recreates the table. Detected via the single-column unique autoindex that
    the old `indicator TEXT ... UNIQUE` declaration creates; once rebuilt, that
    autoindex is gone and this is a no-op on every subsequent call."""
    still_old = False
    for idx in conn.execute("PRAGMA index_list(history)").fetchall():
        idx_name, is_unique = idx[1], idx[2]
        if not is_unique:
            continue
        cols = [c[2] for c in conn.execute(f"PRAGMA index_info({idx_name})").fetchall()]
        if cols == ["indicator"]:
            still_old = True
            break
    if not still_old:
        return

    col_list = ", ".join(_HISTORY_COLUMNS)
    conn.execute("BEGIN")
    try:
        conn.execute("""
            CREATE TABLE history_new (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                indicator   TEXT NOT NULL,
                vt_result   TEXT,
                otx_result  TEXT,
                abuse_result TEXT,
                shodan_result TEXT,
                verdict     TEXT,
                whois_result TEXT, score REAL, per_source TEXT, censys_result TEXT, greynoise_result TEXT,
                urlhaus_result TEXT, urlscan_result TEXT, hybrid_result TEXT, spamhaus_drop_result TEXT,
                threatfox_result TEXT, google_intel_result TEXT, pivot_result TEXT, breakdown TEXT,
                recommendation TEXT, consensus_ratio TEXT, triggered_by TEXT, active_sources TEXT,
                inactive_sources TEXT, contribution TEXT, ai_summary TEXT, user_id INTEGER,
                UNIQUE(indicator, user_id)
            )
        """)
        conn.execute(f"INSERT INTO history_new ({col_list}) SELECT {col_list} FROM history")
        conn.execute("DROP TABLE history")
        conn.execute("ALTER TABLE history_new RENAME TO history")
        conn.commit()
    except Exception:
        conn.rollback()
        raise

def save_results(indicator, vt_result, otx_result, abuse_result, shodan_result, verdict, whois_result=None, score=None, per_source=None, censys_result=None,
                 greynoise_result=None, urlhaus_result=None, urlscan_result=None, hybrid_result=None, spamhaus_drop_result=None, threatfox_result=None,
                 google_intel_result=None, pivot_result=None, breakdown=None, recommendation=None, consensus_ratio=None, triggered_by=None,
                 active_sources=None, inactive_sources=None, contribution=None, user_id=None):
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO history (timestamp, indicator, vt_result, otx_result, abuse_result, shodan_result, verdict, whois_result, score, per_source, censys_result, greynoise_result, urlhaus_result, urlscan_result, hybrid_result, spamhaus_drop_result, threatfox_result, google_intel_result, pivot_result, breakdown, recommendation, consensus_ratio, triggered_by, active_sources, inactive_sources, contribution, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(indicator, user_id) DO UPDATE SET
            timestamp             = excluded.timestamp,
            vt_result             = excluded.vt_result,
            otx_result            = excluded.otx_result,
            abuse_result          = excluded.abuse_result,
            shodan_result         = excluded.shodan_result,
            verdict               = excluded.verdict,
            whois_result          = excluded.whois_result,
            score                 = excluded.score,
            per_source            = excluded.per_source,
            censys_result         = excluded.censys_result,
            greynoise_result      = excluded.greynoise_result,
            urlhaus_result        = excluded.urlhaus_result,
            urlscan_result        = excluded.urlscan_result,
            hybrid_result         = excluded.hybrid_result,
            spamhaus_drop_result  = excluded.spamhaus_drop_result,
            threatfox_result      = excluded.threatfox_result,
            google_intel_result   = excluded.google_intel_result,
            pivot_result          = excluded.pivot_result,
            breakdown             = excluded.breakdown,
            recommendation        = excluded.recommendation,
            consensus_ratio       = excluded.consensus_ratio,
            triggered_by          = excluded.triggered_by,
            active_sources        = excluded.active_sources,
            inactive_sources      = excluded.inactive_sources,
            contribution          = excluded.contribution
    """, (
        datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
        indicator,
        json.dumps(vt_result),
        json.dumps(otx_result),
        json.dumps(abuse_result),
        json.dumps(shodan_result),
        verdict,
        json.dumps(whois_result),
        score,
        json.dumps(per_source) if per_source is not None else None,
        json.dumps(censys_result),
        json.dumps(greynoise_result),
        json.dumps(urlhaus_result),
        json.dumps(urlscan_result),
        json.dumps(hybrid_result),
        json.dumps(spamhaus_drop_result),
        json.dumps(threatfox_result),
        json.dumps(google_intel_result),
        json.dumps(pivot_result),
        json.dumps(breakdown) if breakdown is not None else None,
        recommendation,
        consensus_ratio,
        json.dumps(triggered_by) if triggered_by is not None else None,
        json.dumps(active_sources) if active_sources is not None else None,
        json.dumps(inactive_sources) if inactive_sources is not None else None,
        json.dumps(contribution) if contribution is not None else None,
        user_id,
    ))
    conn.commit()

    total = cursor.execute("SELECT COUNT(*) FROM history").fetchone()[0]
    conn.close()

    print(f"  Result saved to database ({total} total)")

def save_ai_summary(indicator, summary, user_id=None):
    """Persist a generated AI summary for an indicator, without
    touching any other column. Called after generation succeeds, so
    the summary is cached and doesn't need regenerating on every view."""
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if user_id is not None:
        cursor.execute(
            "UPDATE history SET ai_summary = ? WHERE indicator = ? AND user_id = ?",
            (summary, indicator, user_id),
        )
    else:
        cursor.execute(
            "UPDATE history SET ai_summary = ? WHERE indicator = ?",
            (summary, indicator),
        )
    conn.commit()
    conn.close()

def get_history_count():
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]
    conn.close()
    return total

def clear_history():
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM history")
    conn.commit()
    conn.close()

def clear_indicator(indicator, user_id=None):
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if user_id is not None:
        cursor.execute("DELETE FROM history WHERE indicator = ? AND user_id = ?", (indicator, user_id))
    else:
        cursor.execute("DELETE FROM history WHERE indicator = ?", (indicator,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted

def get_last_result(indicator, user_id=None):
    """Return the most recent history record for an indicator, or None."""
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if user_id is not None:
        cursor.execute("""
            SELECT timestamp, indicator, vt_result, otx_result, abuse_result, shodan_result, verdict, whois_result, score, per_source, censys_result, greynoise_result, urlhaus_result, urlscan_result, hybrid_result, spamhaus_drop_result, threatfox_result, google_intel_result, pivot_result, breakdown, recommendation, consensus_ratio, triggered_by, active_sources, inactive_sources, contribution, ai_summary
            FROM history
            WHERE indicator = ? AND user_id = ?
            ORDER BY id DESC
            LIMIT 1
        """, (indicator, user_id))
    else:
        cursor.execute("""
            SELECT timestamp, indicator, vt_result, otx_result, abuse_result, shodan_result, verdict, whois_result, score, per_source, censys_result, greynoise_result, urlhaus_result, urlscan_result, hybrid_result, spamhaus_drop_result, threatfox_result, google_intel_result, pivot_result, breakdown, recommendation, consensus_ratio, triggered_by, active_sources, inactive_sources, contribution, ai_summary
            FROM history
            WHERE indicator = ?
            ORDER BY id DESC
            LIMIT 1
        """, (indicator,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    timestamp, ind, vt_json, otx_json, abuse_json, shodan_json, verdict, whois_json, score, per_source_json, censys_json, greynoise_json, urlhaus_json, urlscan_json, hybrid_json, spamhaus_json, threatfox_json, gi_json, pivot_json, breakdown_json, recommendation, consensus_ratio, triggered_by_json, active_sources_json, inactive_sources_json, contribution_json, ai_summary = row
    return {
        "timestamp":    timestamp,
        "indicator":    ind,
        "vt":           json.loads(vt_json)          if vt_json          else None,
        "otx":          json.loads(otx_json)         if otx_json         else None,
        "abuse":        json.loads(abuse_json)        if abuse_json        else None,
        "shodan":       json.loads(shodan_json)       if shodan_json       else None,
        "whois":        json.loads(whois_json)        if whois_json        else None,
        "censys":       json.loads(censys_json)       if censys_json       else None,
        "greynoise":    json.loads(greynoise_json)   if greynoise_json    else None,
        "urlhaus":      json.loads(urlhaus_json)     if urlhaus_json      else None,
        "urlscan":      json.loads(urlscan_json)     if urlscan_json      else None,
        "hybrid":       json.loads(hybrid_json)      if hybrid_json       else None,
        "spamhaus_drop": json.loads(spamhaus_json)  if spamhaus_json     else None,
        "threatfox":    json.loads(threatfox_json)  if threatfox_json    else None,
        "google_intel": json.loads(gi_json)          if gi_json           else None,
        "verdict":      verdict,
        "score":        score,
        "per_source":   json.loads(per_source_json) if per_source_json   else {},
        "pivot_result": json.loads(pivot_json)       if pivot_json        else None,
        "breakdown":    json.loads(breakdown_json)   if breakdown_json    else [],
        "recommendation":   recommendation,
        "consensus_ratio":  consensus_ratio,
        "triggered_by":     json.loads(triggered_by_json)     if triggered_by_json     else [],
        "active_sources":   json.loads(active_sources_json)   if active_sources_json   else [],
        "inactive_sources": json.loads(inactive_sources_json) if inactive_sources_json else [],
        "contribution":     json.loads(contribution_json)     if contribution_json     else {},
        "ai_summary":       ai_summary,
    }


def compare_results(old, new):
    """Return a dict of fields that changed between two result records."""
    changes = {}

    if old.get("verdict") != new.get("verdict"):
        changes["verdict"] = {
            "from": old.get("verdict"),
            "to":   new.get("verdict"),
        }

    old_score = old.get("score") or 0
    new_score = new.get("score") or 0
    if abs(new_score - old_score) > 1.0:
        changes["score"] = {
            "from": round(old_score, 1),
            "to":   round(new_score, 1),
        }

    old_sources = old.get("per_source") or {}
    new_sources = new.get("per_source") or {}
    source_changes = {}
    for source in new_sources:
        old_v = old_sources.get(source, {}).get("findings_label", "No Findings")
        new_v = new_sources.get(source, {}).get("findings_label", "No Findings")
        if old_v != new_v:
            source_changes[source] = {"from": old_v, "to": new_v}
    if source_changes:
        changes["sources"] = source_changes

    old_pivot = old.get("pivot_result")
    new_pivot = new.get("pivot_result")
    if old_pivot and new_pivot:
        old_mal = old_pivot.get("malicious_pivots", [])
        new_mal = new_pivot.get("malicious_pivots", [])
        if old_mal != new_mal:
            changes["pivot"] = {"from": old_mal, "to": new_mal}

    return changes


def build_evidence_rows(entry):
    """Flatten raw per-source evidence into (source, evidence_type, detail)
    rows for CSV export. Excludes any score/point values — pure evidence content only."""
    rows = []

    vt = entry.get("vt")
    if vt:
        for v in vt.get("malicious_vendors", []):
            rows.append(("VirusTotal", "Vendor Detection", f"{v.get('vendor')}: {v.get('name')}"))
        for tag in vt.get("tags", []):
            rows.append(("VirusTotal", "Tag", tag))
        for c in vt.get("comments", []):
            rows.append(("VirusTotal", "Community Comment", f"[{c.get('date')}] @{c.get('author')}: {c.get('text')}"))
        for rec in vt.get("dns_records", []):
            rows.append(("VirusTotal", "DNS Record", rec))
        relations = vt.get("relations", {})
        for item in relations.get("resolutions", []):
            rows.append(("VirusTotal", "Resolution", f"{item.get('hostname')} <-> {item.get('ip')}"))
        for item in relations.get("contacted_domains", []):
            rows.append(("VirusTotal", "Contacted Domain", item.get("id")))
        for item in relations.get("contacted_urls", []):
            rows.append(("VirusTotal", "Contacted URL", item.get("id")))

    otx = entry.get("otx")
    if otx:
        for p in otx.get("pulse_details", []):
            if p.get("adversary"):
                rows.append(("OTX", "Adversary Attribution", p["adversary"]))
            for tag in p.get("tags", []):
                rows.append(("OTX", "Pulse Tag", tag))
        for p in otx.get("pulses_detail", []):
            if p.get("description"):
                rows.append(("OTX", "Pulse Description", p["description"][:300]))
            for fam in p.get("malware_families") or []:
                rows.append(("OTX", "Malware Family", fam))
            for aid in p.get("attack_ids") or []:
                rows.append(("OTX", "ATT&CK Technique", aid))

    abuse = entry.get("abuse")
    if abuse:
        for name, count in abuse.get("top_categories", []):
            rows.append(("AbuseIPDB", "Attack Category", f"{name} ({count} reports)"))
        for r in abuse.get("reports", []):
            comment = (r.get("comment") or "").strip()
            if comment:
                rows.append(("AbuseIPDB", "Report Comment", f"[{r.get('reported_at', '')[:10]}] {comment[:200]}"))

    shodan = entry.get("shodan")
    if shodan:
        for tag in shodan.get("tags", []):
            rows.append(("Shodan", "Tag", tag))
        for cve in shodan.get("vulns", []):
            rows.append(("Shodan", "CVE", cve))
        for svc in shodan.get("services", []):
            label = f"{svc.get('product', '')} {svc.get('version', '')}".strip()
            rows.append(("Shodan", "Service", f"Port {svc.get('port')}: {label or 'unknown'}"))

    censys = entry.get("censys")
    if censys:
        for label in censys.get("labels", []):
            rows.append(("Censys", "Label", label))
        for cve in censys.get("vulns", []):
            rows.append(("Censys", "CVE", cve))

    whois = entry.get("whois")
    if whois:
        if whois.get("registrar"):
            rows.append(("WHOIS", "Registrar", whois["registrar"]))
        if whois.get("creation_date"):
            rows.append(("WHOIS", "Creation Date", whois["creation_date"]))
        if whois.get("privacy_masked"):
            rows.append(("WHOIS", "Privacy Masked", "Yes"))

    greynoise = entry.get("greynoise")
    if greynoise:
        if greynoise.get("classification"):
            rows.append(("GreyNoise", "Classification", greynoise["classification"]))
        if greynoise.get("actor"):
            rows.append(("GreyNoise", "Actor", greynoise["actor"]))
        for tag in greynoise.get("tags", []):
            rows.append(("GreyNoise", "Tag", tag))

    urlhaus = entry.get("urlhaus")
    if urlhaus:
        if urlhaus.get("threat"):
            rows.append(("URLhaus", "Threat Type", urlhaus["threat"]))
        for u in urlhaus.get("urls", []):
            rows.append(("URLhaus", "Malicious URL", f"[{u.get('url_status')}] {u.get('url')}"))

    threatfox = entry.get("threatfox")
    if threatfox:
        if threatfox.get("malware"):
            rows.append(("ThreatFox", "Malware Family", threatfox["malware"]))
        if threatfox.get("threat_type"):
            rows.append(("ThreatFox", "Threat Type", threatfox["threat_type"]))
        for tag in threatfox.get("tags", []):
            rows.append(("ThreatFox", "Tag", tag))

    urlscan = entry.get("urlscan")
    if urlscan:
        for cat in urlscan.get("categories", []):
            rows.append(("URLScan", "Category", cat))
        if urlscan.get("page_title"):
            rows.append(("URLScan", "Page Title", urlscan["page_title"]))
        for d in urlscan.get("domains", []):
            rows.append(("URLScan", "Associated Domain", d))

    hybrid = entry.get("hybrid")
    if hybrid:
        if hybrid.get("verdict"):
            rows.append(("Hybrid Analysis", "Verdict", hybrid["verdict"]))
        for fam in hybrid.get("family", []) or []:
            rows.append(("Hybrid Analysis", "Malware Family", fam))

    spamhaus = entry.get("spamhaus_drop")
    if spamhaus and spamhaus.get("listed"):
        rows.append(("Spamhaus DROP", "Listed ASN", f"{spamhaus.get('asname')} ({spamhaus.get('cc')})"))

    gi = entry.get("google_intel")
    if gi:
        for fam in gi.get("malware_families", []):
            rows.append(("Google Intel", "Malware Family", fam))
        for actor in gi.get("apt_actors", []):
            rows.append(("Google Intel", "APT Actor", actor))
        for aid in gi.get("attack_ids", []):
            rows.append(("Google Intel", "ATT&CK Technique", aid))
        for cve in gi.get("cve_ids", []):
            rows.append(("Google Intel", "CVE", cve))
        for hit in gi.get("severity_hits", []):
            rows.append(("Google Intel", "Severity Signal", hit))

    return rows


def build_llm_training_json(entry):
    """Condensed export matching generate_summary()'s expected input shape
    in ioc_llm.py, for use as fine-tuning training data. Only includes
    sources where has_data is True, and uses the exact findings_label
    string already produced by the scoring pipeline — never invents labels.
    """
    per_source = entry.get("per_source") or {}
    sources = {}
    for name, src in per_source.items():
        if not isinstance(src, dict) or not src.get("has_data"):
            continue
        sources[name] = {
            "findings": src.get("findings_label"),
        }

    return {
        "indicator":       entry.get("indicator"),
        "overall_verdict": entry.get("verdict"),
        "overall_score":   entry.get("score"),
        "sources":         sources,
    }


def build_comment_training_data(entry):
    """Raw comment/report text only, for scan_comment_text() training —
    kept separate from build_llm_training_json() on purpose, since these
    two functions are trained on different input shapes and shouldn't be
    mixed in the same dataset."""
    comments = []

    vt = entry.get("vt")
    if vt:
        for c in vt.get("comments", []):
            text = (c.get("text") or "").strip()
            if text:
                comments.append(text)

    abuse = entry.get("abuse")
    if abuse:
        for r in abuse.get("reports", []):
            text = (r.get("comment") or "").strip()
            if text:
                comments.append(text)

    return {
        "indicator": entry.get("indicator"),
        "comments":  comments,
    }


def _cap_list(lst, limit=8):
    if not isinstance(lst, list) or len(lst) <= limit:
        return lst
    capped = lst[:limit]
    capped.append(f"... and {len(lst) - limit} more")
    return capped


def build_detailed_report_json(entry):
    """Structured report combining every source's raw evidence and
    per-source scoring, sized down the same way as the LLM digest
    (see build_llm_report_digest) so the downloadable export and the
    LLM input always match. Field names are taken directly from each
    source module's return dict, not guessed."""
    per_source = entry.get("per_source") or {}
    per_source_summary = {}
    for name, src in per_source.items():
        if not isinstance(src, dict) or not src.get("has_data"):
            continue
        fields = {
            "findings_label": src.get("findings_label"),
            "findings_tier":  src.get("findings_tier"),
            "verdict":        src.get("verdict"),
        }
        per_source_summary[name] = {k: v for k, v in fields.items() if v is not None}

    report = {
        "indicator":           entry.get("indicator"),
        "verdict":             entry.get("verdict"),
        "score":               entry.get("score"),
        "timestamp":           entry.get("timestamp"),
        "per_source_summary":  per_source_summary,
        "recommendation":      entry.get("recommendation"),
        "consensus_ratio":     entry.get("consensus_ratio"),
        "triggered_by":        entry.get("triggered_by") or [],
        "active_sources":      entry.get("active_sources") or [],
        "inactive_sources":    entry.get("inactive_sources") or [],
        "contribution":        entry.get("contribution") or {},
    }

    vt = entry.get("vt")
    if vt:
        resolutions = [
            {"hostname": r.get("hostname"), "ip": r.get("ip")}
            for r in vt.get("relations", {}).get("resolutions", [])
        ]
        if len(resolutions) > 5:
            n = len(resolutions) - 5
            resolutions = resolutions[:5] + [{"hostname": f"... and {n} more", "ip": None}]

        comments = vt.get("comments", [])
        seen = set()
        deduped_comments = []
        for c in comments:
            text = c.get("text", "") if isinstance(c, dict) else str(c)
            if text not in seen:
                seen.add(text)
                deduped_comments.append(c)
        if len(deduped_comments) > 2:
            n = len(deduped_comments) - 2
            deduped_comments = deduped_comments[:2] + [{"text": f"... and {n} more comment(s), omitted"}]

        report["vt_section"] = {
            "malicious":         vt.get("malicious"),
            "suspicious":        vt.get("suspicious"),
            "harmless":          vt.get("harmless"),
            "undetected":        vt.get("undetected"),
            "malicious_vendors": [
                {"vendor": v.get("vendor"), "name": v.get("name")}
                for v in vt.get("malicious_vendors", [])
            ],
            "tags":              vt.get("tags", []),
            "last_scan_date":    vt.get("last_scan_date"),
            "dns_records":       vt.get("dns_records", []),
            "comments":          deduped_comments,
            "resolutions":       resolutions,
            "country":           vt.get("country"),
            "asn":               vt.get("asn"),
            "registrar":         vt.get("registrar"),
            "creation_date":     vt.get("creation_date"),
        }

    otx = entry.get("otx")
    if otx:
        passive_dns = otx.get("passive_dns", [])
        if len(passive_dns) > 5:
            n = len(passive_dns) - 5
            passive_dns = passive_dns[:5] + [{"hostname": f"... and {n} more", "address": None}]

        otx_section = {
            "pulse_count":             otx.get("pulse_count"),
            "non_noise_count":         otx.get("non_noise_count"),
            "pulses_detail": [
                {
                    "description":       p.get("description"),
                    "tags":              p.get("tags", []),
                    "adversary":         p.get("adversary"),
                    "malware_families":  p.get("malware_families", []),
                }
                for p in otx.get("pulses_detail", [])
            ],
            "passive_dns":             passive_dns,
            "reputation_threat_score": otx.get("reputation_threat_score"),
            "reputation_threat_type":  otx.get("reputation_threat_type"),
            "indicator_description":  otx.get("indicator_description"),
        }
        # country/asn only present on OTX results for IP indicators
        if "country" in otx:
            otx_section["country"] = otx.get("country")
        if "asn" in otx:
            otx_section["asn"] = otx.get("asn")
        report["otx_section"] = otx_section

    abuse = entry.get("abuse")
    if abuse:
        report["abuse_section"] = {
            "abuse_score":    abuse.get("abuse_score"),
            "total_reports":  abuse.get("total_reports"),
            "distinct_users": abuse.get("distinct_users"),
            "isp":            abuse.get("isp"),
            "is_tor":         abuse.get("is_tor"),
            "country":        abuse.get("country"),
            "top_categories": abuse.get("top_categories", []),
            "reports":        abuse.get("reports", []),
        }

    shodan = entry.get("shodan")
    if shodan:
        report["shodan_section"] = {
            "tags":     shodan.get("tags", []),
            "vulns":    shodan.get("vulns", []),
            "services": shodan.get("services", []),
        }

    censys = entry.get("censys")
    if censys:
        report["censys_section"] = {
            "labels": censys.get("labels", []),
            "vulns":  censys.get("vulns", []),
        }

    whois = entry.get("whois")
    if whois:
        report["whois_section"] = {
            "registrar":      whois.get("registrar"),
            "creation_date":  whois.get("creation_date"),
            "privacy_masked": whois.get("privacy_masked"),
        }

    greynoise = entry.get("greynoise")
    if greynoise:
        report["greynoise_section"] = {
            "classification": greynoise.get("classification"),
            "actor":          greynoise.get("actor"),
            "tags":           greynoise.get("tags", []),
        }

    urlhaus = entry.get("urlhaus")
    if urlhaus:
        report["urlhaus_section"] = {
            "threat": urlhaus.get("threat"),
            "urls":   urlhaus.get("urls", []),
        }

    threatfox = entry.get("threatfox")
    if threatfox:
        report["threatfox_section"] = {
            "malware":     threatfox.get("malware"),
            "threat_type": threatfox.get("threat_type"),
            "tags":        threatfox.get("tags", []),
        }

    urlscan = entry.get("urlscan")
    if urlscan:
        report["urlscan_section"] = {
            "malicious":  urlscan.get("malicious"),
            "categories": urlscan.get("categories", []),
            "page_title": urlscan.get("page_title"),
            "server":     urlscan.get("server"),
            "domains":    urlscan.get("domains", []),
        }

    hybrid = entry.get("hybrid")
    if hybrid:
        report["hybrid_section"] = {
            "verdict": hybrid.get("verdict"),
            "family":  hybrid.get("family") or [],
        }

    spamhaus = entry.get("spamhaus_drop")
    if spamhaus and spamhaus.get("listed"):
        report["spamhaus_section"] = {
            "listed": True,
            "asname": spamhaus.get("asname"),
            "cc":     spamhaus.get("cc"),
            "domain": spamhaus.get("domain"),
            "rir":    spamhaus.get("rir"),
        }

    gi = entry.get("google_intel")
    if gi:
        co_iocs = gi.get("co_iocs") or {}
        report["google_intel_section"] = {
            "malware_families": _cap_list(gi.get("malware_families", [])),
            "apt_actors":       _cap_list(gi.get("apt_actors", [])),
            "attack_ids":       _cap_list(gi.get("attack_ids", [])),
            "cve_ids":          _cap_list(gi.get("cve_ids", [])),
            "severity_hits":    _cap_list(gi.get("severity_hits", [])),
            "co_iocs": {
                "ips":     len(co_iocs.get("ips") or []),
                "domains": len(co_iocs.get("domains") or []),
                "hashes":  len(co_iocs.get("hashes") or []),
            },
        }

    pivot = entry.get("pivot_result")
    if pivot:
        report["pivot_section"] = {
            "pivot_iocs":        pivot.get("pivot_iocs", []),
            "malicious_pivots":  pivot.get("malicious_pivots", []),
            "suspicious_pivots": pivot.get("suspicious_pivots", []),
        }

    return report


def build_llm_report_digest(entry):
    """LLM prompt input. Identical to build_detailed_report_json's output —
    kept as a separate name since the two call sites (downloadable export vs.
    LLM input) are conceptually distinct, even though they now render the
    same JSON."""
    return build_detailed_report_json(entry)


def get_history_entry(n):
    """Return the nth history entry (1-indexed, newest first), or None if out of range."""
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, indicator, vt_result, otx_result, abuse_result, shodan_result, verdict, whois_result, score, per_source, censys_result, greynoise_result, urlhaus_result, urlscan_result, hybrid_result, spamhaus_drop_result, threatfox_result, google_intel_result, pivot_result, breakdown, recommendation, consensus_ratio, triggered_by, active_sources, inactive_sources, contribution, ai_summary
        FROM history
        ORDER BY id DESC
        LIMIT 1 OFFSET ?
    """, (n - 1,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    timestamp, indicator, vt_json, otx_json, abuse_json, shodan_json, verdict, whois_json, score, per_source_json, censys_json, greynoise_json, urlhaus_json, urlscan_json, hybrid_json, spamhaus_json, threatfox_json, gi_json, pivot_json, breakdown_json, recommendation, consensus_ratio, triggered_by_json, active_sources_json, inactive_sources_json, contribution_json, ai_summary = row
    return {
        "timestamp":    timestamp,
        "indicator":    indicator,
        "vt":           json.loads(vt_json)          if vt_json          else None,
        "otx":          json.loads(otx_json)         if otx_json         else None,
        "abuse":        json.loads(abuse_json)       if abuse_json       else None,
        "shodan":       json.loads(shodan_json)      if shodan_json      else None,
        "whois":        json.loads(whois_json)       if whois_json       else None,
        "censys":       json.loads(censys_json)      if censys_json      else None,
        "greynoise":    json.loads(greynoise_json)   if greynoise_json   else None,
        "urlhaus":      json.loads(urlhaus_json)     if urlhaus_json     else None,
        "urlscan":      json.loads(urlscan_json)     if urlscan_json     else None,
        "hybrid":       json.loads(hybrid_json)      if hybrid_json      else None,
        "spamhaus_drop": json.loads(spamhaus_json)  if spamhaus_json    else None,
        "threatfox":    json.loads(threatfox_json)  if threatfox_json   else None,
        "google_intel": json.loads(gi_json)          if gi_json          else None,
        "verdict":      verdict,
        "score":        score,
        "per_source":   json.loads(per_source_json) if per_source_json  else {},
        "pivot_result": json.loads(pivot_json)       if pivot_json       else None,
        "breakdown":    json.loads(breakdown_json)   if breakdown_json   else [],
        "recommendation":   recommendation,
        "consensus_ratio":  consensus_ratio,
        "triggered_by":     json.loads(triggered_by_json)     if triggered_by_json     else [],
        "active_sources":   json.loads(active_sources_json)   if active_sources_json   else [],
        "inactive_sources": json.loads(inactive_sources_json) if inactive_sources_json else [],
        "contribution":     json.loads(contribution_json)     if contribution_json     else {},
        "ai_summary":       ai_summary,
    }
