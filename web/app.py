from dotenv import load_dotenv
load_dotenv()

import sys
import os
import threading
from io import StringIO
_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _root_dir)
os.environ["IOC_DB_PATH"] = os.path.join(_root_dir, "ioc_cache.db")

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor
from pydantic import BaseModel

from detect import detect_type
from sources.vt import vt_check
from sources.otx import otx_check
from sources.abuseipdb import abuseipdb_check
from sources.shodan import shodan_check
from sources.censys import censys_check
from sources.whois import whois_check
from sources.greynoise import greynoise_check
from sources.urlhaus import urlhaus_check
from sources.urlscan import urlscan_check
from sources.hybrid import hybrid_check
from sources.threatfox import threatfox_check
from sources.spamhaus import spamhaus_asn_check
from sources.google_intel import query_google_intel
from sources.scoring import combined_verdict, load_config
from sources.pivot import extract_pivot_iocs, run_pivot_scan
from cache import clear_indicator_cache
from output import get_history_entry, get_history_count, get_last_result, save_results, clear_indicator
from main import display_report

_root_dir   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_static_dir = os.path.join(os.path.dirname(__file__), "frontend", "dist")

config = load_config(os.path.join(_root_dir, "config.json"))

# Serialises /api/report so concurrent requests don't race on main.VERBOSE
_report_lock = threading.Lock()

app = FastAPI()
app.mount("/assets", StaticFiles(directory=os.path.join(_static_dir, "assets")), name="assets")


@app.get("/")
def root():
    return FileResponse(os.path.join(_static_dir, "index.html"))


@app.get("/api/ping")
def ping():
    return {"status": "ok"}


@app.get("/api/history")
def history():
    entries = []
    for n in range(1, 51):
        row = get_history_entry(n)
        if row is None:
            continue
        entries.append({
            "indicator": row.get("indicator") or "",
            "verdict":   row.get("verdict") or "",
            "score":     row.get("score"),
            "timestamp": row.get("timestamp") or "",
        })
    return entries


class ScanRequest(BaseModel):
    indicator: str


@app.post("/api/scan")
def scan(body: ScanRequest):
    indicator = body.indicator.strip()
    ind_type  = detect_type(indicator)

    if ind_type is None:
        raise HTTPException(status_code=400, detail="Invalid indicator")

    vt           = vt_check(indicator, ind_type)
    otx          = otx_check(indicator, ind_type)
    abuse        = abuseipdb_check(indicator, ind_type)
    shodan       = shodan_check(indicator, ind_type)
    whois        = whois_check(indicator, ind_type)
    censys       = censys_check(indicator, ind_type)
    greynoise    = greynoise_check(indicator, ind_type)
    urlhaus      = urlhaus_check(indicator, ind_type)
    threatfox    = threatfox_check(indicator, ind_type)
    urlscan      = urlscan_check(indicator, ind_type)
    hybrid       = hybrid_check(indicator, ind_type)
    google_intel = query_google_intel(indicator, ind_type, config=config)

    _asn = (
        (shodan.get("asn") if isinstance(shodan, dict) else None) or
        (censys.get("asn") if isinstance(censys, dict) else None) or
        (vt.get("asn")     if isinstance(vt, dict)     else None)
    )
    spamhaus_drop = spamhaus_asn_check(_asn) if _asn else None

    sources_results = {
        "vt": vt, "otx": otx, "google_intel": google_intel,
        "threatfox": threatfox, "urlhaus": urlhaus, "urlscan": urlscan,
        "censys": censys, "shodan": shodan,
    }
    pivot_iocs, sources_map = extract_pivot_iocs(sources_results, indicator)
    pivot = run_pivot_scan(pivot_iocs, sources_map, config, indicator)

    verdict_result = combined_verdict(
        vt, otx, abuse, shodan,
        whois=whois, censys=censys, greynoise=greynoise,
        urlhaus=urlhaus, urlscan=urlscan, hybrid=hybrid,
        spamhaus_drop=spamhaus_drop, threatfox=threatfox,
        google_intel=google_intel, config=config,
        pivot_result=pivot,
    )

    save_results(
        indicator, vt, otx, abuse, shodan,
        verdict_result["final_verdict"],
        whois,
        score=verdict_result["score"],
        per_source=verdict_result["per_source"],
        censys_result=censys,
        greynoise_result=greynoise,
        urlhaus_result=urlhaus,
        urlscan_result=urlscan,
        hybrid_result=hybrid,
        spamhaus_drop_result=spamhaus_drop,
        threatfox_result=threatfox,
        google_intel_result=google_intel,
        pivot_result=pivot,
    )

    return {
        "indicator":        indicator,
        "ind_type":         ind_type,
        "verdict":          verdict_result["final_verdict"],
        "score":            verdict_result["score"],
        "recommendation":   verdict_result["recommendation"],
        "consensus_ratio":  verdict_result["consensus_ratio"],
        "contribution":     verdict_result["contribution"],
        "per_source":       verdict_result["per_source"],
        "breakdown":        verdict_result["breakdown"],
        "triggered_by":     verdict_result["triggered_by"],
        "active_sources":   verdict_result["active_sources"],
        "inactive_sources": verdict_result["inactive_sources"],
        "vt":               vt,
        "otx":              otx,
        "abuse":            abuse,
        "shodan":           shodan,
        "censys":           censys,
        "whois":            whois,
        "greynoise":        greynoise,
        "urlhaus":          urlhaus,
        "urlscan":          urlscan,
        "hybrid":           hybrid,
        "threatfox":        threatfox,
        "spamhaus_drop":    spamhaus_drop,
        "google_intel":     google_intel,
        "pivot":            pivot,
    }


@app.post("/api/scan/stream")
async def scan_stream(body: ScanRequest):
    indicator = body.indicator.strip()
    ind_type  = detect_type(indicator)

    if ind_type is None:
        raise HTTPException(status_code=400, detail="Invalid indicator")

    async def generate():
        results = {}

        sources = [
            ("vt",           vt_check,           (indicator, ind_type)),
            ("otx",          otx_check,           (indicator, ind_type)),
            ("abuse",        abuseipdb_check,     (indicator, ind_type)),
            ("shodan",       shodan_check,        (indicator, ind_type)),
            ("censys",       censys_check,        (indicator, ind_type)),
            ("whois",        whois_check,         (indicator, ind_type)),
            ("greynoise",    greynoise_check,     (indicator, ind_type)),
            ("urlhaus",      urlhaus_check,       (indicator, ind_type)),
            ("threatfox",    threatfox_check,     (indicator, ind_type)),
            ("urlscan",      urlscan_check,       (indicator, ind_type)),
            ("hybrid",       hybrid_check,        (indicator, ind_type)),
            ("google_intel", lambda ind, t: query_google_intel(ind, t, config=config), (indicator, ind_type)),
        ]

        def run_source(key, fn, args):
            try:
                return key, fn(*args)
            except Exception as e:
                print(f"  [{key}] Error: {e}")
                return key, None

        with ThreadPoolExecutor(max_workers=6) as executor:
            future_to_key = {
                executor.submit(run_source, key, fn, args): key
                for key, fn, args in sources
            }

            pending = set(future_to_key.keys())
            while pending:
                await asyncio.sleep(0.1)
                done = {f for f in pending if f.done()}
                pending -= done
                for future in done:
                    key, data = future.result()
                    results[key] = data
                    try:
                        yield json.dumps({"type": "source", "key": key, "data": data}) + "\n"
                    except GeneratorExit:
                        # Client disconnected — cancel remaining futures and stop
                        for f in pending:
                            f.cancel()
                        return

        _asn = (
            (results.get("shodan") or {}).get("asn") or
            (results.get("censys") or {}).get("asn") or
            (results.get("vt")     or {}).get("asn")
        )
        spamhaus_drop = spamhaus_asn_check(_asn) if _asn else None
        results["spamhaus_drop"] = spamhaus_drop

        sources_results = {
            "vt":           results.get("vt"),
            "otx":          results.get("otx"),
            "google_intel": results.get("google_intel"),
            "threatfox":    results.get("threatfox"),
            "urlhaus":      results.get("urlhaus"),
            "urlscan":      results.get("urlscan"),
            "censys":       results.get("censys"),
            "shodan":       results.get("shodan"),
        }
        pivot_iocs, sources_map = extract_pivot_iocs(sources_results, indicator)
        pivot = run_pivot_scan(pivot_iocs, sources_map, config, indicator)

        verdict_result = combined_verdict(
            results.get("vt"), results.get("otx"),
            results.get("abuse"), results.get("shodan"),
            whois=results.get("whois"), censys=results.get("censys"),
            greynoise=results.get("greynoise"), urlhaus=results.get("urlhaus"),
            urlscan=results.get("urlscan"), hybrid=results.get("hybrid"),
            spamhaus_drop=spamhaus_drop, threatfox=results.get("threatfox"),
            google_intel=results.get("google_intel"), config=config,
            pivot_result=pivot,
        )

        save_results(
            indicator, results.get("vt"), results.get("otx"),
            results.get("abuse"), results.get("shodan"),
            verdict_result["final_verdict"], results.get("whois"),
            score=verdict_result["score"],
            per_source=verdict_result["per_source"],
            censys_result=results.get("censys"),
            greynoise_result=results.get("greynoise"),
            urlhaus_result=results.get("urlhaus"),
            urlscan_result=results.get("urlscan"),
            hybrid_result=results.get("hybrid"),
            spamhaus_drop_result=spamhaus_drop,
            threatfox_result=results.get("threatfox"),
            google_intel_result=results.get("google_intel"),
            pivot_result=pivot,
        )

        yield json.dumps({
            "type":             "final",
            "indicator":        indicator,
            "ind_type":         ind_type,
            "verdict":          verdict_result["final_verdict"],
            "score":            verdict_result["score"],
            "recommendation":   verdict_result["recommendation"],
            "consensus_ratio":  verdict_result["consensus_ratio"],
            "contribution":     verdict_result["contribution"],
            "per_source":       verdict_result["per_source"],
            "breakdown":        verdict_result["breakdown"],
            "triggered_by":     verdict_result["triggered_by"],
            "active_sources":   verdict_result["active_sources"],
            "inactive_sources": verdict_result["inactive_sources"],
            "vt":               results.get("vt"),
            "otx":              results.get("otx"),
            "abuse":            results.get("abuse"),
            "shodan":           results.get("shodan"),
            "censys":           results.get("censys"),
            "whois":            results.get("whois"),
            "greynoise":        results.get("greynoise"),
            "urlhaus":          results.get("urlhaus"),
            "urlscan":          results.get("urlscan"),
            "hybrid":           results.get("hybrid"),
            "threatfox":        results.get("threatfox"),
            "spamhaus_drop":    spamhaus_drop,
            "google_intel":     results.get("google_intel"),
            "pivot":            pivot,
        }) + "\n"

    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control":     "no-cache",
            "Connection":        "keep-alive",
        }
    )


@app.post("/api/clear")
def clear(body: ScanRequest):
    indicator = body.indicator.strip()
    clear_indicator_cache(indicator)
    clear_indicator(indicator)
    return {"status": "cleared"}


@app.post("/api/rescan")
def rescan(body: ScanRequest):
    indicator = body.indicator.strip()
    ind_type  = detect_type(indicator)

    if ind_type is None:
        raise HTTPException(status_code=400, detail="Invalid indicator")

    clear_indicator_cache(indicator)
    clear_indicator(indicator)

    return scan(body)


@app.post("/api/result")
def get_result(body: ScanRequest):
    indicator = body.indicator.strip()
    ind_type  = detect_type(indicator)
    if ind_type is None:
        raise HTTPException(status_code=400, detail="Invalid indicator")

    entry = get_last_result(indicator)
    if not entry:
        raise HTTPException(status_code=404, detail="No saved result for this indicator.")

    return {
        "indicator":        indicator,
        "ind_type":         ind_type,
        "verdict":          entry.get("verdict"),
        "score":            entry.get("score"),
        "per_source":       entry.get("per_source") or {},
        "recommendation":   None,
        "consensus_ratio":  None,
        "contribution":     None,
        "breakdown":        None,
        "triggered_by":     None,
        "active_sources":   None,
        "inactive_sources": None,
        "vt":               entry.get("vt"),
        "otx":              entry.get("otx"),
        "abuse":            entry.get("abuse"),
        "shodan":           entry.get("shodan"),
        "censys":           entry.get("censys"),
        "whois":            entry.get("whois"),
        "greynoise":        entry.get("greynoise"),
        "urlhaus":          entry.get("urlhaus"),
        "urlscan":          entry.get("urlscan"),
        "hybrid":           entry.get("hybrid"),
        "threatfox":        entry.get("threatfox"),
        "spamhaus_drop":    entry.get("spamhaus_drop"),
        "google_intel":     entry.get("google_intel"),
        "pivot":            entry.get("pivot_result"),
    }


@app.post("/api/report")
def get_report(body: ScanRequest):
    indicator = body.indicator.strip()
    ind_type  = detect_type(indicator)
    if ind_type is None:
        raise HTTPException(status_code=400, detail="Invalid indicator")

    entry = get_last_result(indicator)
    if not entry:
        raise HTTPException(status_code=404, detail="No scan found for this indicator. Scan it first.")

    import main as _main

    captured   = StringIO()
    old_stdout = sys.stdout
    sys.stdout = captured
    try:
        with _report_lock:
            old_verbose   = _main.VERBOSE
            _main.VERBOSE = True
            try:
                display_report(
                    indicator, ind_type,
                    entry.get("vt"), entry.get("otx"), entry.get("abuse"), entry.get("shodan"),
                    whois=entry.get("whois"), censys=entry.get("censys"),
                    greynoise=entry.get("greynoise"), urlhaus=entry.get("urlhaus"),
                    urlscan=entry.get("urlscan"), hybrid=entry.get("hybrid"),
                    spamhaus_drop=entry.get("spamhaus_drop"),
                    threatfox=entry.get("threatfox"),
                    google_intel=entry.get("google_intel"),
                    pivot_result=entry.get("pivot_result"),
                )
            finally:
                _main.VERBOSE = old_verbose
    finally:
        sys.stdout = old_stdout

    return {"report": captured.getvalue()}


@app.get("/{full_path:path}")
def spa_fallback(_: str):
    return FileResponse(os.path.join(_static_dir, "index.html"))


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, loop="asyncio")