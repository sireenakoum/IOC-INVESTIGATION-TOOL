from dotenv import load_dotenv
load_dotenv()

import sys
import os
import re
import csv
import io
import threading
import sqlite3
import secrets
from io import StringIO
from datetime import datetime, timedelta
_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _root_dir)
os.environ.setdefault("IOC_DB_PATH", os.path.join(_root_dir, "ioc_cache.db"))

# Self-heals a wiped/fresh ioc_cache.db (e.g. Render's free tier resets the
# filesystem on every redeploy). Must run before ANY `sources.*` import below
# — sources/scoring.py loads config at its own import time (module-level
# `NOISE_TAGS = load_config()[...]`), which otherwise crashes the whole
# import chain (detect -> sources.otx -> sources.scoring) before this file
# even reaches its own load_config() call. Not an @app.on_event startup
# hook either, for the same reason: that fires after imports finish.
from sources.app_config import ensure_seeded
ensure_seeded()

from sources.users import ensure_users_seeded
_bootstrap_invite_token = ensure_users_seeded()

from report_files import init_reports_table, cleanup_expired_reports
init_reports_table()
cleanup_expired_reports()  # self-heal: sweep anything orphaned by a previous crash/restart

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse, Response
from fastapi import Depends, Request
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
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
from cache import clear_indicator_cache, ADMIN_USER_ID
from output import init_history_table, get_last_result, save_results, clear_indicator, build_evidence_rows, build_detailed_report_json, build_llm_report_digest, save_ai_summary
from llm.ioc_llm import generate_detailed_verdict, stream_detailed_verdict, CancelToken
from docx_export import build_docx_report
from report_files import save_generated_report, get_generated_report
from starlette.concurrency import iterate_in_threadpool
from main import display_report
from sources.users import pwd_context, log_activity, ROLES, STATUSES, EVENT_TYPES, ADMIN_ONLY_EVENT_TYPES, BOOTSTRAP_ADMIN_EMAIL

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from jose import jwt
from typing import Optional

import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:8000")

def send_verification_email(to_email: str, token: str):
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key['api-key'] = BREVO_API_KEY
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

    verify_link = f"{FRONTEND_URL}/api/auth/verify?token={token}"

    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": to_email}],
        sender={"email": BREVO_SENDER_EMAIL, "name": "IOC Investigator"},
        subject="Verify your email",
        html_content=f"""
            <p>Click the link below to verify your email and activate your account:</p>
            <p><a href="{verify_link}">{verify_link}</a></p>
        """,
    )

    try:
        api_instance.send_transac_email(send_smtp_email)
    except ApiException as e:
        print(f"Failed to send verification email: {e}")


def _brevo_configured() -> bool:
    return bool(BREVO_API_KEY and BREVO_SENDER_EMAIL)


def _email_button(link: str, label: str) -> str:
    return (
        f'<a href="{link}" '
        'style="display:inline-block;padding:10px 20px;background:#4edea3;'
        'color:#003824;text-decoration:none;border-radius:2px;font-weight:700;'
        'font-family:sans-serif;">'
        f'{label}</a>'
    )


def send_invite_email(to_email: str, token: str):
    """Admin-created-user invite: expected, first-contact mail, so it's
    onboarding-toned with no security disclaimer. Distinct from
    send_password_reset_email's copy/subject — see that function's
    docstring for why they're kept separate."""
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key['api-key'] = BREVO_API_KEY
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

    invite_link = f"{FRONTEND_URL}/?invite={token}"

    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": to_email}],
        sender={"email": BREVO_SENDER_EMAIL, "name": "IOC Investigator"},
        subject="You've been added to IOC Investigator",
        html_content=f"""
            <p>An administrator created an account for you on IOC Investigator — a tool
            for checking IPs, domains, and file hashes against threat-intel sources and
            getting a scored verdict.</p>
            <p>{_email_button(invite_link, "Set your password")}</p>
            <p style="color:#86948a;font-size:12px;">
              Or paste this link into your browser: {invite_link}
            </p>
        """,
    )

    try:
        api_instance.send_transac_email(send_smtp_email)
    except ApiException as e:
        print(f"Failed to send invite email: {e}")


def send_password_reset_email(to_email: str, token: str):
    """Password-reset mail: kept deliberately separate from send_invite_email.
    A reset the recipient didn't ask for needs to read as unmistakably
    different from routine onboarding mail, so the recipient can tell it
    apart from an attack — neutral/security-toned subject and copy, and it
    never states whether the reset was self- or admin-triggered."""
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key['api-key'] = BREVO_API_KEY
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

    reset_link = f"{FRONTEND_URL}/?invite={token}"

    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": to_email}],
        sender={"email": BREVO_SENDER_EMAIL, "name": "IOC Investigator"},
        subject="Reset your password",
        html_content=f"""
            <p>A password reset was requested for your IOC Investigator account.</p>
            <p>{_email_button(reset_link, "Reset your password")}</p>
            <p style="color:#86948a;font-size:12px;">
              Or paste this link into your browser: {reset_link}
            </p>
            <p style="color:#86948a;font-size:12px;">
              This link expires in 1 hour and can only be used once.
            </p>
            <p>If you didn't request this, you can ignore this email — your password
            hasn't changed.</p>
        """,
    )

    try:
        api_instance.send_transac_email(send_smtp_email)
    except ApiException as e:
        print(f"Failed to send password reset email: {e}")


_root_dir   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_static_dir = os.path.join(os.path.dirname(__file__), "frontend", "dist")

config = load_config()

# Serialises /api/report so concurrent requests don't race on main.VERBOSE
_report_lock = threading.Lock()

# Shared for the lifetime of the process; reused across every scan request.
_scan_executor = ThreadPoolExecutor(max_workers=6)

# ── API key auth (legacy single-key / external tools) ──────────────────────
API_KEY = os.environ.get("API_KEY")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def _resolve_api_key(x_api_key: str):
    """Shared resolution for verify_api_key: which user (if any) an
    X-API-Key belongs to, and its role — plus rejecting suspended accounts
    here so every X-API-Key route gets that for free. Returns (user_id,
    role); role is 'Admin' for the shared service key, which has no
    per-user row to look a role up against."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    if API_KEY and x_api_key == API_KEY:
        return ADMIN_USER_ID, "Admin"

    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()
    row = cur.execute("SELECT id, role, status FROM users WHERE api_key = ?", (x_api_key,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    user_id, role, status = row
    if (status or "Active") == "Suspended":
        raise HTTPException(status_code=403, detail="Account suspended")
    return user_id, role or "Analyst"


def verify_api_key(x_api_key: str = Depends(api_key_header)):
    """Validate X-API-Key and resolve which user (if any) it belongs to.

    Accepts two kinds of key:
      - the shared server-wide API_KEY env var (legacy/service credential —
        used by external tools with no specific account; scoped calls fall
        back to unscoped behavior for these, same as the CLI)
      - a per-user key from users.api_key (browser UI sends the logged-in
        user's own key) — resolves to that user's id for data scoping.

    Returns the owning user_id — ADMIN_USER_ID for the shared service key.
    """
    user_id, _role = _resolve_api_key(x_api_key)
    return user_id

# ── Password hashing ────────────────────────────────────────────────────────
# pwd_context now lives in sources/users.py (imported above) so both this
# file and sources/users.py hash/verify with the exact same CryptContext.

# ── Session tokens (JWT) — MUST be defined before any route that uses them ──
JWT_SECRET = os.environ.get("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24 * 7  # session stays valid for 7 days

def create_session_token(user_id: int, email: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)
    payload = {"user_id": user_id, "email": email, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

bearer_scheme = HTTPBearer(auto_error=False)

def verify_session_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

    token = credentials.credentials

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # JWTs here are stateless (no server-side revocation list), so a role
    # or suspension change made after a token was issued wouldn't otherwise
    # take effect until it expires (up to JWT_EXPIRE_HOURS later) — look
    # both up fresh on every request instead of trusting the token's claims.
    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    row = conn.execute(
        "SELECT role, status, name, must_change_password FROM users WHERE id = ?",
        (payload["user_id"],),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    role, status, name, must_change_password = row
    if (status or "Active") == "Suspended":
        raise HTTPException(status_code=403, detail="Account suspended")

    return {
        "user_id": payload["user_id"],
        "email": payload["email"],
        "role": role or "Analyst",
        "name": name or "",
        "must_change_password": bool(must_change_password),
    }


def require_roles(*roles):
    """Dependency factory for role-gated routes, e.g.
    Depends(require_roles('Admin')) or Depends(require_roles('Admin', 'Analyst'))."""
    def checker(session: dict = Depends(verify_session_token)) -> dict:
        if session["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return session
    return checker

app = FastAPI()
app.mount("/assets", StaticFiles(directory=os.path.join(_static_dir, "assets")), name="assets")

def get_api_key(request: Request = None, *args, **kwargs):
    if request is not None:
        return request.headers.get("x-api-key", "anon")
    return "anon"

limiter = Limiter(key_func=get_api_key)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.get("/")
def root():
    return FileResponse(os.path.join(_static_dir, "index.html"))


@app.get("/api/ping")
def ping():
    return {"status": "ok"}


@app.get("/api/history", include_in_schema=False)
def history(offset: int = 0, limit: int = 50, session=Depends(verify_session_token)):
    user_id = session["user_id"]
    init_history_table()

    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) FROM history WHERE user_id = ?", (user_id,)).fetchone()[0]
    rows = cur.execute("""
        SELECT indicator, verdict, score, timestamp
        FROM history
        WHERE user_id = ?
        ORDER BY timestamp DESC, id DESC
        LIMIT ? OFFSET ?
    """, (user_id, limit, offset)).fetchall()
    verdict_rows = cur.execute("""
        SELECT verdict, COUNT(*) FROM history WHERE user_id = ? GROUP BY verdict
    """, (user_id,)).fetchall()
    conn.close()

    entries = [
        {
            "indicator": row[0] or "",
            "verdict":   row[1] or "",
            "score":     row[2],
            "timestamp": row[3] or "",
        }
        for row in rows
    ]
    # Aggregated over the full history table (not just this page), so
    # verdict-distribution totals stay accurate regardless of pagination.
    verdict_counts = {(v or "no_data"): c for v, c in verdict_rows}

    return {
        "entries": entries,
        "total": total,
        "has_more": offset + limit < total,
        "verdict_counts": verdict_counts,
    }


class ScanRequest(BaseModel):
    indicator: str

class DocxDownloadRequest(BaseModel):
    token: str

class SignupRequest(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class CreateUserRequest(BaseModel):
    name: str
    email: str
    role: str

class RoleUpdateRequest(BaseModel):
    role: str

class StatusUpdateRequest(BaseModel):
    status: str

class AcceptInviteRequest(BaseModel):
    token: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@app.post("/api/scan")
@limiter.limit("10/minute")
def scan(body: ScanRequest, request: Request, user_id=Depends(verify_api_key)):
    indicator = body.indicator.strip()
    ind_type  = detect_type(indicator)

    if ind_type is None:
        raise HTTPException(status_code=400, detail="Invalid indicator")

    log_activity(user_id, "Scan run", indicator)

    vt           = vt_check(indicator, ind_type, user_id=user_id)
    otx          = otx_check(indicator, ind_type, user_id=user_id)
    abuse        = abuseipdb_check(indicator, ind_type, user_id=user_id)
    shodan       = shodan_check(indicator, ind_type, user_id=user_id)
    whois        = whois_check(indicator, ind_type, user_id=user_id)
    censys       = censys_check(indicator, ind_type, user_id=user_id)
    greynoise    = greynoise_check(indicator, ind_type, user_id=user_id)
    urlhaus      = urlhaus_check(indicator, ind_type, user_id=user_id)
    threatfox    = threatfox_check(indicator, ind_type, user_id=user_id)
    urlscan      = urlscan_check(indicator, ind_type, user_id=user_id)
    hybrid       = hybrid_check(indicator, ind_type, user_id=user_id)
    google_intel = query_google_intel(indicator, ind_type, config=config, user_id=user_id)

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
    pivot_iocs, sources_map, relation_map = extract_pivot_iocs(sources_results, indicator)
    pivot = run_pivot_scan(pivot_iocs, sources_map, config, indicator, relation_map, user_id=user_id)

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
        breakdown=verdict_result["breakdown"],
        recommendation=verdict_result["recommendation"],
        consensus_ratio=verdict_result["consensus_ratio"],
        triggered_by=verdict_result["triggered_by"],
        active_sources=verdict_result["active_sources"],
        inactive_sources=verdict_result["inactive_sources"],
        contribution=verdict_result["contribution"],
        user_id=user_id,
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
@limiter.limit("10/minute")
async def scan_stream(body: ScanRequest, request: Request, user_id=Depends(verify_api_key)):
    indicator = body.indicator.strip()
    ind_type  = detect_type(indicator)

    if ind_type is None:
        raise HTTPException(status_code=400, detail="Invalid indicator")

    log_activity(user_id, "Scan run", indicator)

    async def generate():
        results = {}
        cancelled = threading.Event()

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
            ("google_intel", lambda ind, t, **kw: query_google_intel(ind, t, config=config, **kw), (indicator, ind_type)),
        ]

        def run_source(key, fn, args):
            try:
                return key, fn(*args, user_id=user_id)
            except Exception as e:
                print(f"  [{key}] Error: {e}")
                return key, None

        future_to_key = {}
        for key, fn, args in sources:
            if cancelled.is_set():
                break
            future_to_key[_scan_executor.submit(run_source, key, fn, args)] = key

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
                    # Client disconnected — stop launching new work and cancel
                    # any not-yet-started futures. Already-running futures can't
                    # be force-killed, so they're left to finish and discarded
                    # using the shared executor's threads; their results are
                    # simply never read.
                    cancelled.set()
                    for f in pending:
                        f.cancel()
                    return

        if cancelled.is_set():
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
        pivot_iocs, sources_map, relation_map = extract_pivot_iocs(sources_results, indicator)
        pivot = run_pivot_scan(pivot_iocs, sources_map, config, indicator, relation_map, user_id=user_id)

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
            breakdown=verdict_result["breakdown"],
            recommendation=verdict_result["recommendation"],
            consensus_ratio=verdict_result["consensus_ratio"],
            triggered_by=verdict_result["triggered_by"],
            active_sources=verdict_result["active_sources"],
            inactive_sources=verdict_result["inactive_sources"],
            contribution=verdict_result["contribution"],
            user_id=user_id,
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
def clear(body: ScanRequest, user_id=Depends(verify_api_key)):
    indicator = body.indicator.strip()
    clear_indicator_cache(indicator, user_id=user_id)
    clear_indicator(indicator, user_id=user_id)
    return {"status": "cleared"}


@app.post("/api/cache/clear")
def clear_cache_only(body: ScanRequest, user_id=Depends(verify_api_key)):
    """Bust the per-source cache ahead of a rescan without touching saved
    history. save_results() upserts on indicator, so the old history row
    is safely overwritten once the rescan completes on its own — deleting
    it up front would lose the last saved result if the rescan is aborted."""
    indicator = body.indicator.strip()
    clear_indicator_cache(indicator, user_id=user_id)
    return {"status": "cache_cleared"}


@app.post("/api/rescan")
def rescan(body: ScanRequest, request: Request, user_id=Depends(verify_api_key)):
    indicator = body.indicator.strip()
    ind_type  = detect_type(indicator)

    if ind_type is None:
        raise HTTPException(status_code=400, detail="Invalid indicator")

    clear_indicator_cache(indicator, user_id=user_id)

    return scan(body, request, user_id)


@app.post("/api/result")
def get_result(body: ScanRequest, user_id=Depends(verify_api_key)):
    indicator = body.indicator.strip()
    ind_type  = detect_type(indicator)
    if ind_type is None:
        raise HTTPException(status_code=400, detail="Invalid indicator")

    entry = get_last_result(indicator, user_id=user_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No saved result for this indicator.")

    return {
        "indicator":        indicator,
        "ind_type":         ind_type,
        "verdict":          entry.get("verdict"),
        "score":            entry.get("score"),
        "per_source":       entry.get("per_source") or {},
        "recommendation":   entry.get("recommendation"),
        "consensus_ratio":  entry.get("consensus_ratio"),
        "contribution":     entry.get("contribution"),
        "breakdown":        entry.get("breakdown") or [],
        "triggered_by":     entry.get("triggered_by"),
        "active_sources":   entry.get("active_sources"),
        "inactive_sources": entry.get("inactive_sources"),
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
        "ai_summary":       entry.get("ai_summary"),
    }


@app.post("/api/pivot/status")
def get_pivot_status(body: ScanRequest, user_id=Depends(verify_api_key)):
    """Live scanned/unscanned status for every pivot IOC recorded in an
    indicator's last stored pivot scan.

    Pivot scans snapshot 'pivot_from_full_scan' at the moment the *parent*
    indicator was scanned — that snapshot never updates on its own, even if
    the user later scans one of those pivot IOCs directly. This endpoint
    re-checks each pivot IOC's current status via get_last_result() only
    (same reuse check _scan_single_pivot uses — 'has a full scan on
    record'), so the pivot map can reflect newly-scanned IOCs on demand.

    Pure database reads: no vt_check/otx_check/etc., no run_pivot_scan, no
    new history rows written. Never triggers a scan of anything."""
    indicator = body.indicator.strip()
    entry = get_last_result(indicator, user_id=user_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No scan found for this indicator. Scan it first.")

    pivot = entry.get("pivot_result") or {}
    pivot_iocs = pivot.get("pivot_iocs") or []

    statuses = {}
    for ioc in pivot_iocs:
        ioc_entry = get_last_result(ioc, user_id=user_id)
        if ioc_entry and ioc_entry.get("verdict") is not None:
            statuses[ioc] = {
                "scanned":   True,
                "verdict":   ioc_entry.get("verdict"),
                "score":     ioc_entry.get("score"),
                "timestamp": ioc_entry.get("timestamp"),
            }
        else:
            statuses[ioc] = {"scanned": False}

    return {"statuses": statuses}


@app.post("/api/report")
def get_report(body: ScanRequest, user_id=Depends(verify_api_key)):
    indicator = body.indicator.strip()
    ind_type  = detect_type(indicator)
    if ind_type is None:
        raise HTTPException(status_code=400, detail="Invalid indicator")

    entry = get_last_result(indicator, user_id=user_id)
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


@app.post("/api/report/csv")
def get_report_csv(body: ScanRequest, user_id=Depends(verify_api_key)):
    indicator = body.indicator.strip()
    entry = get_last_result(indicator, user_id=user_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No scan found for this indicator. Scan it first.")

    rows = build_evidence_rows(entry)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Source", "Evidence Type", "Detail"])
    writer.writerows(rows)
    return {"csv": output.getvalue()}


@app.post("/api/report/json")
def get_report_json(body: ScanRequest, user_id=Depends(verify_api_key)):
    """Full structured report export for an indicator's last scan."""
    indicator = body.indicator.strip()
    entry = get_last_result(indicator, user_id=user_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No scan found for this indicator. Scan it first.")

    entry["indicator"] = indicator  # get_last_result doesn't include this key itself
    return build_detailed_report_json(entry)


@app.post("/api/report/digest")
def get_report_digest(body: ScanRequest, user_id=Depends(verify_api_key)):
    """Trimmed structured report export for LLM prompt input."""
    indicator = body.indicator.strip()
    entry = get_last_result(indicator, user_id=user_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No scan found for this indicator. Scan it first.")

    entry["indicator"] = indicator  # get_last_result doesn't include this key itself
    return build_llm_report_digest(entry)


@app.post("/api/report/docx")
def get_report_docx(body: ScanRequest, user_id=Depends(verify_api_key)):
    """Word (.docx) export of an indicator's last scan. Renders the
    already-generated report — the same digest facts and the same
    ai_summary text already shown in the app — into a formatted document.
    Does not trigger a scan or an LLM call; if the AI summary hasn't been
    generated yet for this scan, the export isn't available yet (mirrors
    the frontend's disabled-export-button state, in case this endpoint is
    hit directly)."""
    indicator = body.indicator.strip()
    entry = get_last_result(indicator, user_id=user_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No scan found for this indicator. Scan it first.")
    if not entry.get("ai_summary"):
        raise HTTPException(status_code=409, detail="AI summary hasn't finished generating yet for this scan.")

    entry["indicator"] = indicator
    try:
        buf = build_docx_report(entry, indicator)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    try:
        log_activity(user_id, "Report exported", f"{indicator} (Word)")
    except Exception as e:
        # Non-fatal — the export itself already succeeded above. Most likely
        # cause is "Report exported" not yet being a recognized EVENT_TYPES
        # entry in sources/users.py; flagging rather than silently swallowing.
        print(f"[get_report_docx] activity log failed (is 'Report exported' in EVENT_TYPES?): {e}")

    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", indicator)
    filename = f"{safe_name}-report.docx"
    return Response(
        content=buf.read(),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/report/docx/generate")
def generate_report_docx(body: ScanRequest, user_id=Depends(verify_api_key)):
    """Builds the same Word report as /api/report/docx, but writes it to
    disk and registers a download token instead of returning the bytes
    directly. Called automatically by the frontend right after the AI
    summary finishes streaming, so a persistent "report ready"
    notification can offer a download link independent of that original
    request. Manual Export-menu downloads still go through
    /api/report/docx and never touch disk.
    """
    indicator = body.indicator.strip()
    entry = get_last_result(indicator, user_id=user_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No scan found for this indicator. Scan it first.")
    if not entry.get("ai_summary"):
        raise HTTPException(status_code=409, detail="AI summary hasn't finished generating yet for this scan.")

    entry["indicator"] = indicator
    try:
        buf = build_docx_report(entry, indicator)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", indicator)
    token, filename = save_generated_report(buf.read(), indicator, user_id, safe_name)

    try:
        log_activity(user_id, "Report exported", f"{indicator} (Word)")
    except Exception as e:
        print(f"[generate_report_docx] activity log failed (is 'Report exported' in EVENT_TYPES?): {e}")

    return {"token": token, "filename": filename, "indicator": indicator}


@app.post("/api/report/docx/download")
def download_report_docx(body: DocxDownloadRequest, user_id=Depends(verify_api_key)):
    """Downloads a report previously written by /api/report/docx/generate.
    404s if the token is unknown, belongs to another user, or has aged
    past the retention window and been swept — same response either way
    so a bad/expired token can't be used to probe what exists."""
    result = get_generated_report(body.token, user_id)
    if not result:
        raise HTTPException(status_code=404, detail="Report not found or has expired. Generate it again.")
    path, filename = result
    with open(path, "rb") as f:
        content = f.read()
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/report/ai-summary")
def get_ai_summary(body: ScanRequest, user_id=Depends(verify_api_key)):
    """AI-generated analyst summary for an indicator's last scan."""
    indicator = body.indicator.strip()
    entry = get_last_result(indicator, user_id=user_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No scan found for this indicator. Scan it first.")

    entry["indicator"] = indicator
    digest = build_llm_report_digest(entry)
    summary = generate_detailed_verdict(digest)
    if summary:
        save_ai_summary(indicator, summary, user_id=user_id)
    return {"summary": summary}


@app.post("/api/report/ai-summary/stream")
def get_ai_summary_stream(body: ScanRequest, user_id=Depends(verify_api_key)):
    """Streamed AI-generated analyst summary for an indicator's last scan.

    stream_detailed_verdict's LLM calls are blocking `requests` calls to
    Ollama, so this runs on a worker thread (via iterate_in_threadpool)
    rather than the event loop. cancel_token is the only thing that can
    reach across into that thread: if the client disconnects (e.g. the
    "Stop generating" button aborts the fetch), the async generator below
    gets GeneratorExit at its current `yield`, and the `finally` calls
    cancel_token.abort() — which stops every subsequent Ollama call from
    ever starting and makes the currently in-flight one stop between
    chunks (near-instant once it's actively streaming tokens; bounded by
    Ollama's own latency in the rarer case where it's still blocked
    waiting on the first byte of that one call — see CancelToken's
    docstring for why that residual gap exists). Without this, the sync
    generator would just keep running every remaining section to
    completion in its worker thread regardless of the client disconnecting,
    since threads can't be force-killed.
    """
    indicator = body.indicator.strip()
    entry = get_last_result(indicator, user_id=user_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No scan found for this indicator. Scan it first.")

    entry["indicator"] = indicator
    digest = build_llm_report_digest(entry)
    cancel_token = CancelToken()

    async def generate():
        chunks = []
        completed = False
        try:
            async for chunk in iterate_in_threadpool(stream_detailed_verdict(digest, cancel_token=cancel_token)):
                chunks.append(chunk)
                yield chunk
            completed = True
        finally:
            cancel_token.abort()
        if completed:
            final = "".join(chunks).strip()
            if final:
                save_ai_summary(indicator, final, user_id=user_id)

    return StreamingResponse(generate(), media_type="text/plain")


# ── Auth routes ──────────────────────────────────────────────────────────────

@app.post("/api/auth/signup")
def signup(body: SignupRequest):
    name = body.name.strip()
    email = body.email.strip().lower()
    password = body.password

    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()

    existing = cur.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = pwd_context.hash(password)
    api_key = secrets.token_hex(32)
    verification_token = secrets.token_urlsafe(32)
    created_at = datetime.utcnow().isoformat()

    # Self-service signup predates the Users & Activity Log feature and stays
    # open (nothing in the spec says to close it) — but it's still how
    # someone gets an account to use the scanner at all, so it needs a role
    # that can actually run scans. Defaulting to Analyst preserves that
    # existing behavior; Admins can promote afterward from the Users page.
    # Only the admin-only /api/admin/users flow lets the creator pick a
    # role up front (Analyst or Admin).
    cur.execute(
        "INSERT INTO users (name, email, password_hash, api_key, created_at, is_verified, verification_token, role, status) VALUES (?, ?, ?, ?, ?, 0, ?, 'Analyst', 'Active')",
        (name, email, password_hash, api_key, created_at, verification_token),
    )
    user_id = cur.lastrowid
    conn.commit()
    conn.close()

    log_activity(user_id, "Account created", "Self-signup")

    send_verification_email(email, verification_token)

    return {"email": email, "message": "Please check your email to verify your account."}

@app.get("/api/auth/verify")
def verify_email(token: str):
    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()

    row = cur.execute("SELECT id, is_verified FROM users WHERE verification_token = ?", (token,)).fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired verification link")

    user_id, is_verified = row
    if is_verified:
        conn.close()
        return {"message": "Email already verified. You can log in."}

    cur.execute("UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    return {"message": "Email verified successfully. You can now log in."}

@app.post("/api/auth/login")
def login(body: LoginRequest):
    email = body.email.strip().lower()
    password = body.password

    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()
    row = cur.execute(
        "SELECT id, password_hash, is_verified, role, status, name, must_change_password FROM users WHERE email = ?",
        (email,),
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user_id, password_hash, is_verified, role, status, name, must_change_password = row
    if not pwd_context.verify(password, password_hash):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not is_verified:
        conn.close()
        raise HTTPException(status_code=403, detail="Please finish activating your account (check your email) before logging in")

    if (status or "Active") == "Suspended":
        conn.close()
        raise HTTPException(status_code=403, detail="This account has been suspended")

    cur.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"), user_id))
    conn.commit()
    conn.close()

    log_activity(user_id, "Login")

    token = create_session_token(user_id, email)
    return {
        "token": token,
        "email": email,
        "role": role or "Analyst",
        "name": name or "",
        "must_change_password": bool(must_change_password),
    }


@app.get("/api/auth/me", include_in_schema=False)
def get_me(session=Depends(verify_session_token)):
    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()
    row = cur.execute("SELECT api_key FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()

    return {
        "user_id": session["user_id"],
        "email": session["email"],
        "role": session["role"],
        "name": session["name"],
        "must_change_password": session["must_change_password"],
        "api_key": row[0] if row else None,
    }


@app.post("/api/auth/regenerate-key", include_in_schema=False)
def regenerate_key(session=Depends(verify_session_token)):
    new_key = secrets.token_hex(32)

    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()
    cur.execute("UPDATE users SET api_key = ? WHERE id = ?", (new_key, session["user_id"]))
    conn.commit()
    conn.close()

    return {"api_key": new_key}

@app.delete("/api/auth/delete-account", include_in_schema=False)
def delete_account(session=Depends(verify_session_token)):
    user_id = session["user_id"]

    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()

    # Same "don't zero out Admins" guard the admin-panel role/status changes
    # enforce (see update_user_role/update_user_status below) — this is the
    # one other place a user can remove their own Admin-ness in one step.
    # The bootstrap admin is additionally never deletable, by anyone,
    # including themselves — see sources/users.py's ensure_users_seeded().
    row = cur.execute("SELECT role, is_bootstrap FROM users WHERE id = ?", (user_id,)).fetchone()
    if row and row[1]:
        conn.close()
        raise HTTPException(status_code=403, detail="The bootstrap admin account cannot be deleted")
    if row and row[0] == "Admin":
        active_admins = cur.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'Admin' AND (status IS NULL OR status = 'Active')"
        ).fetchone()[0]
        if active_admins <= 1:
            conn.close()
            raise HTTPException(status_code=400, detail="You are the only remaining Admin — promote another user before deleting your account")

    email = session["email"]

    cur.execute("DELETE FROM history WHERE user_id = ?", (user_id,))
    cur.execute("DELETE FROM cache WHERE user_id = ?", (user_id,))
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))

    conn.commit()
    conn.close()

    # activity_log rows are intentionally kept (not cascaded) so this event —
    # and the user's prior history — stays visible in the Admin log after the
    # row is gone; the email is embedded in details since the user_id will no
    # longer resolve via the users JOIN in _query_activity.
    log_activity(user_id, "Account deleted", f"Self-deleted ({email})")

    return {"message": "Account deleted"}


@app.post("/api/auth/logout", include_in_schema=False)
def logout(session=Depends(verify_session_token)):
    """Records the Logout event. Session JWTs are stateless here (no
    server-side revocation list — see verify_session_token), so this can't
    actually invalidate the token early; the frontend discards it
    client-side right after calling this. A token that's never explicitly
    logged out of (browser closed, etc.) just expires silently after
    JWT_EXPIRE_HOURS with no corresponding Logout row — the existing session
    mechanism has no hook to observe that, so it isn't logged either."""
    log_activity(session["user_id"], "Logout")
    return {"message": "Logged out"}


@app.post("/api/auth/accept-invite", include_in_schema=False)
def accept_invite(body: AcceptInviteRequest):
    """Completes both the admin-invite flow (new user sets their first
    password) and the email-based admin-reset-password flow (existing user
    sets a replacement) — both hand out the same kind of one-time
    invite_token, so one endpoint covers both (see create_user /
    admin_reset_password)."""
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()
    row = cur.execute(
        "SELECT id, email, invite_token_expires FROM users WHERE invite_token = ?", (body.token,)
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired invite link")
    user_id, email, expires = row
    if expires and datetime.utcnow() > datetime.fromisoformat(expires):
        cur.execute("UPDATE users SET invite_token = NULL, invite_token_expires = NULL WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired invite link")

    password_hash = pwd_context.hash(body.password)
    cur.execute("""
        UPDATE users SET password_hash = ?, is_verified = 1, invite_token = NULL,
                          invite_token_expires = NULL, must_change_password = 0
        WHERE id = ?
    """, (password_hash, user_id))
    conn.commit()
    conn.close()

    log_activity(user_id, "Login")
    token = create_session_token(user_id, email)
    return {"token": token, "email": email}


@app.post("/api/auth/change-password", include_in_schema=False)
def change_password(body: ChangePasswordRequest, session=Depends(verify_session_token)):
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()
    row = cur.execute("SELECT password_hash FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if not row or not pwd_context.verify(body.current_password, row[0]):
        conn.close()
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    new_hash = pwd_context.hash(body.new_password)
    cur.execute(
        "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
        (new_hash, session["user_id"]),
    )
    conn.commit()
    conn.close()
    return {"message": "Password changed"}


# ── Admin: user management ──────────────────────────────────────────────────
# All routes below require the Admin role (Depends(require_roles("Admin"))),
# enforced server-side regardless of what the UI shows/hides — see
# require_roles() above.

def _active_admin_count(cur) -> int:
    return cur.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'Admin' AND (status IS NULL OR status = 'Active')"
    ).fetchone()[0]


@app.post("/api/admin/users")
def create_user(body: CreateUserRequest, session=Depends(require_roles("Admin"))):
    email = body.email.strip().lower()
    name = body.name.strip()
    role = body.role

    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    if role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of {ROLES}")
    if email == BOOTSTRAP_ADMIN_EMAIL:
        raise HTTPException(status_code=400, detail="This account is reserved for the bootstrap admin")

    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()
    existing = cur.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    api_key = secrets.token_hex(32)
    created_at = datetime.utcnow().isoformat()
    creator_label = session["name"] or session["email"]

    if _brevo_configured():
        # Invite-link flow: the app already has Brevo wired up for
        # verification emails, so reuse it rather than a temp password.
        # password_hash is an unusable random placeholder until accept-invite.
        invite_token = secrets.token_urlsafe(32)
        placeholder_hash = pwd_context.hash(secrets.token_hex(32))
        cur.execute("""
            INSERT INTO users (email, password_hash, api_key, created_at, is_verified,
                                role, status, name, created_by, invite_token)
            VALUES (?, ?, ?, ?, 0, ?, 'Active', ?, ?, ?)
        """, (email, placeholder_hash, api_key, created_at, role, name, session["user_id"], invite_token))
        new_user_id = cur.lastrowid
        conn.commit()
        conn.close()
        log_activity(new_user_id, "Account created", f"Created by {creator_label}")
        send_invite_email(email, invite_token)
        return {"email": email, "role": role, "invited": True, "message": "Invite email sent."}
    else:
        # No email sending configured — hand back a one-time temp password
        # for the admin to share out of band; forced change on first login.
        temp_password = secrets.token_urlsafe(9)
        password_hash = pwd_context.hash(temp_password)
        cur.execute("""
            INSERT INTO users (email, password_hash, api_key, created_at, is_verified,
                                role, status, name, created_by, must_change_password)
            VALUES (?, ?, ?, ?, 1, ?, 'Active', ?, ?, 1)
        """, (email, password_hash, api_key, created_at, role, name, session["user_id"]))
        new_user_id = cur.lastrowid
        conn.commit()
        conn.close()
        log_activity(new_user_id, "Account created", f"Created by {creator_label}")
        return {
            "email": email, "role": role, "invited": False, "temp_password": temp_password,
            "message": "Share this temporary password with the user — it will not be shown again.",
        }


@app.get("/api/admin/users")
def list_users(session=Depends(require_roles("Admin"))):
    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    rows = conn.execute("""
        SELECT id, name, email, role, status, created_at, last_login, is_bootstrap
        FROM users ORDER BY created_at DESC
    """).fetchall()
    conn.close()
    return {
        "users": [
            {
                "id": r[0], "name": r[1] or "", "email": r[2], "role": r[3],
                "status": r[4] or "Active", "created_at": r[5], "last_login": r[6],
                "is_bootstrap": bool(r[7]),
            }
            for r in rows
        ]
    }


@app.get("/api/admin/users/{user_id}")
def get_user_detail(user_id: int, session=Depends(require_roles("Admin"))):
    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    row = conn.execute("""
        SELECT id, name, email, role, status, created_at, last_login, created_by, is_bootstrap
        FROM users WHERE id = ?
    """, (user_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    created_by_email = None
    if row[7] is not None:
        cb = conn.execute("SELECT email FROM users WHERE id = ?", (row[7],)).fetchone()
        created_by_email = cb[0] if cb else None
    conn.close()

    return {
        "id": row[0], "name": row[1] or "", "email": row[2], "role": row[3],
        "status": row[4] or "Active", "created_at": row[5], "last_login": row[6],
        "created_by": created_by_email, "is_bootstrap": bool(row[8]),
    }


@app.patch("/api/admin/users/{user_id}/role")
def update_user_role(user_id: int, body: RoleUpdateRequest, session=Depends(require_roles("Admin"))):
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of {ROLES}")

    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()
    row = cur.execute("SELECT role, is_bootstrap FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    current_role, is_bootstrap = row
    if is_bootstrap:
        conn.close()
        raise HTTPException(status_code=403, detail="The bootstrap admin's role cannot be changed")

    # "Don't let an admin demote themselves if they're the only remaining
    # Admin" — only fires on self-targeted demotion; an admin demoting a
    # *different* admin always leaves at least the acting admin behind.
    if user_id == session["user_id"] and current_role == "Admin" and body.role != "Admin":
        if _active_admin_count(cur) <= 1:
            conn.close()
            raise HTTPException(status_code=400, detail="You are the only remaining Admin — promote another user first")

    cur.execute("UPDATE users SET role = ? WHERE id = ?", (body.role, user_id))
    conn.commit()
    conn.close()
    return {"id": user_id, "role": body.role}


@app.patch("/api/admin/users/{user_id}/status")
def update_user_status(user_id: int, body: StatusUpdateRequest, session=Depends(require_roles("Admin"))):
    if body.status not in STATUSES:
        raise HTTPException(status_code=400, detail=f"Status must be one of {STATUSES}")

    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()
    row = cur.execute("SELECT role, is_bootstrap FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    current_role, is_bootstrap = row
    if is_bootstrap:
        conn.close()
        raise HTTPException(status_code=403, detail="The bootstrap admin cannot be suspended")

    if user_id == session["user_id"] and current_role == "Admin" and body.status == "Suspended":
        if _active_admin_count(cur) <= 1:
            conn.close()
            raise HTTPException(status_code=400, detail="You are the only remaining Admin — promote another user before suspending yourself")

    cur.execute("UPDATE users SET status = ? WHERE id = ?", (body.status, user_id))
    conn.commit()
    conn.close()
    return {"id": user_id, "status": body.status}


@app.post("/api/admin/users/{user_id}/reset-password")
def admin_reset_password(user_id: int, session=Depends(require_roles("Admin"))):
    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    cur = conn.cursor()
    row = cur.execute("SELECT email, is_bootstrap FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    email, is_bootstrap = row
    if is_bootstrap:
        conn.close()
        raise HTTPException(status_code=403, detail="The bootstrap admin's password can't be reset by other admins")

    if _brevo_configured():
        # Old password stops working the moment is_verified flips to 0
        # (login requires both a matching hash and is_verified) — the
        # account is locked until the link below is used, same as any
        # password-reset flow that invalidates the old credential up front.
        reset_token = secrets.token_urlsafe(32)
        reset_expires = (datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        cur.execute(
            "UPDATE users SET invite_token = ?, invite_token_expires = ?, is_verified = 0 WHERE id = ?",
            (reset_token, reset_expires, user_id),
        )
        conn.commit()
        conn.close()
        send_password_reset_email(email, reset_token)
        return {"email": email, "invited": True, "message": "Password reset link sent."}
    else:
        temp_password = secrets.token_urlsafe(9)
        password_hash = pwd_context.hash(temp_password)
        cur.execute(
            "UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?",
            (password_hash, user_id),
        )
        conn.commit()
        conn.close()
        return {
            "email": email, "invited": False, "temp_password": temp_password,
            "message": "Share this temporary password with the user — it will not be shown again.",
        }


# ── Activity log ─────────────────────────────────────────────────────────────

def _query_activity(user_id=None, event_type=None, date_from=None, date_to=None, offset=0, limit=50, exclude_event_types=()):
    if event_type and event_type not in EVENT_TYPES:
        raise HTTPException(status_code=400, detail=f"event_type must be one of {EVENT_TYPES}")

    conn = sqlite3.connect(os.environ["IOC_DB_PATH"])
    where, params = [], []
    if user_id is not None:
        where.append("a.user_id = ?")
        params.append(user_id)
    if event_type:
        where.append("a.event_type = ?")
        params.append(event_type)
    for excluded in exclude_event_types:
        where.append("a.event_type != ?")
        params.append(excluded)
    if date_from:
        where.append("a.timestamp >= ?")
        params.append(date_from)
    if date_to:
        # Inclusive of the whole end date — callers pass a bare YYYY-MM-DD.
        where.append("a.timestamp <= ?")
        params.append(date_to if len(date_to) > 10 else f"{date_to}T23:59:59")
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""

    total = conn.execute(f"SELECT COUNT(*) FROM activity_log a {where_sql}", params).fetchone()[0]
    rows = conn.execute(f"""
        SELECT a.id, a.timestamp, a.event_type, a.details, a.user_id, u.name, u.email
        FROM activity_log a
        LEFT JOIN users u ON u.id = a.user_id
        {where_sql}
        ORDER BY a.timestamp DESC
        LIMIT ? OFFSET ?
    """, params + [limit, offset]).fetchall()
    conn.close()

    entries = [
        {
            "id": r[0], "timestamp": r[1], "event_type": r[2], "details": r[3],
            "user_id": r[4], "user_name": r[5] or "", "user_email": r[6] or "(deleted user)",
        }
        for r in rows
    ]
    return {"entries": entries, "total": total, "has_more": offset + len(entries) < total}


@app.get("/api/admin/activity")
def get_activity_log(
    user_id: Optional[int] = None,
    event_type: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
    session=Depends(require_roles("Admin")),
):
    """Global activity log across all users — Admin only; Analysts get
    their own activity via /api/activity/me instead."""
    return _query_activity(user_id=user_id, event_type=event_type, date_from=date_from, date_to=date_to, offset=offset, limit=limit)


@app.get("/api/admin/users/{user_id}/activity")
def get_user_activity(
    user_id: int,
    event_type: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
    session=Depends(require_roles("Admin")),
):
    return _query_activity(user_id=user_id, event_type=event_type, date_from=date_from, date_to=date_to, offset=offset, limit=limit)


@app.get("/api/activity/me")
def get_my_activity(
    event_type: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
    session=Depends(require_roles("Admin", "Analyst")),
):
    """Self-scoped activity for Analysts (and Admins viewing their own).
    Account created/deleted are Admin-log-only (see ADMIN_ONLY_EVENT_TYPES)
    — excluded here regardless of the event_type filter passed in."""
    return _query_activity(
        user_id=session["user_id"], event_type=event_type, date_from=date_from, date_to=date_to,
        offset=offset, limit=limit, exclude_event_types=ADMIN_ONLY_EVENT_TYPES,
    )


# ── SPA fallback — MUST stay last so it doesn't shadow any route above ──────
@app.get("/{full_path:path}")
def spa_fallback(_: str):
    return FileResponse(os.path.join(_static_dir, "index.html"))


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, loop="asyncio")