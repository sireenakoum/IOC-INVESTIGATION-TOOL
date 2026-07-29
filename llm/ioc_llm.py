import json
import os
import re
import threading
import requests

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b-instruct")
TEMPERATURE = 0.2
TIMEOUT_SECS = 120
NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "8192"))

IDENTIFIER_PATTERNS = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "ipv4": re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    # Domain/hostname pattern — useful for corroborating infra-recon sources
    # like Shodan/Censys against DNS/passive-DNS data elsewhere. Requires a
    # letter-containing label plus a real-looking TLD to avoid matching
    # version strings or IDs that happen to contain dots.
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|co|info|biz|it|ru|cn|de|uk|us|xyz|top|site|online|club|app)\b",
        re.IGNORECASE,
    ),
}


# ==========================================================================
# DETERMINISTIC LAYER — no LLM involved. These functions are the source of
# truth for every fact that must be exactly correct: scalars, pivot
# classification, source labels/counts, google_intel counts, and literal
# cross-section overlap detection. An LLM cannot corrupt these because it
# never generates them.
# ==========================================================================

def _safe_call(func, *args, fallback="", label=""):
    """Runs func(*args); on any exception, logs the full traceback and
    returns fallback instead of propagating. Used to isolate faults so one
    broken field/section can't take down the entire report."""
    try:
        return func(*args)
    except Exception as e:
        import traceback
        print(f"[{label or getattr(func, '__name__', 'unknown')}] {traceback.format_exc()}")
        return fallback


def _fmt_scalar(v):
    return str(v)


def _classify_verdict(verdict):
    """Maps the JSON's own verdict field to a plain-language risk tier for
    the Final Assessment's own conclusion (kept separate from — and never
    replacing — the literal verdict field, which is always also stated
    verbatim elsewhere). Three tiers: Malicious, Suspicious, Clean.
    Falls back to echoing the raw verdict string if it doesn't match any
    known tier, rather than guessing."""
    v = (verdict or "").strip().lower()
    if v in ("high", "critical", "severe"):
        return "Malicious"
    if v in ("medium", "moderate", "elevated", "mid"):
        return "Suspicious"
    if v in ("low", "none", "clean", "benign", "negligible", "minimal"):
        return "Clean"
    return verdict or "Unclassified"


def _compute_pivot_facts(pivot_section):
    if not pivot_section:
        return {"performed": False}
    iocs = pivot_section.get("pivot_iocs") or []
    if not iocs:
        return {"performed": False}
    malicious = set(pivot_section.get("malicious_pivots") or [])
    suspicious = set(pivot_section.get("suspicious_pivots") or [])
    mal_list = [i for i in iocs if i in malicious]
    susp_list = [i for i in iocs if i in suspicious and i not in malicious]
    return {
        "performed": True,
        "total_checked": len(iocs),
        "malicious": mal_list,
        "suspicious": susp_list,
    }


def _compute_source_checklist(digest):
    active = digest.get("active_sources") or []
    per_source = digest.get("per_source_summary") or {}
    return [
        {"source": name, "findings_label": per_source.get(name, {}).get("findings_label", "")}
        for name in active
    ]


def _parse_list_with_more(items):
    """Handles '... and N more' placeholder entries: strips them from the
    named list but adds their count to the total."""
    clean, extra = [], 0
    for i in items or []:
        m = re.match(r"^\.\.\.\s*and\s+(\d+)\s+more", str(i), flags=re.IGNORECASE)
        if m:
            extra += int(m.group(1))
        else:
            clean.append(i)
    return clean, len(clean) + extra


def _compute_google_intel_facts(gi):
    if not gi:
        return {}
    facts = {}
    for field in ("malware_families", "apt_actors", "cve_ids"):
        clean, total = _parse_list_with_more(gi.get(field))
        facts[field] = {"first_three": clean[:3], "total_count": total}
    if gi.get("severity_hits"):
        facts["severity_hits"] = list(gi["severity_hits"])
    if gi.get("co_iocs"):
        facts["co_iocs"] = gi["co_iocs"]
    return facts


def _stringify_section_values(section):
    """Flatten a section (dict/list/scalar) into a list of plain strings,
    for identifier scanning."""
    out = []
    if isinstance(section, dict):
        for v in section.values():
            out.extend(_stringify_section_values(v))
    elif isinstance(section, list):
        for v in section:
            out.extend(_stringify_section_values(v))
    elif section is not None:
        out.append(str(section))
    return out


def _find_cross_section_overlaps(digest):
    """Finds identifiers (IPs, SHA256 hashes, CVE IDs, domains) that appear
    verbatim in two or more different sections. Returns a dict:
    identifier -> sorted list of section names it was found in.
    This is the ONLY thing that counts as valid corroboration.

    The scan list is every "_section" key actually present in the digest,
    EXCEPT pivot_section — pivot IOCs are a derived/secondary check run
    against this indicator, not an independent source, so a match between
    pivot_section and another section isn't source corroboration (it would
    just mean the pivot scan and some source are describing the same
    hash/IP, which is expected and not meaningful evidence of agreement
    between two sources).

    Filtering isn't done by active_sources: a source can be labeled
    "inactive" (e.g. zero pulses) while its section still holds real data
    (e.g. OTX's passive_dns), and that data can still genuinely corroborate
    another source; filtering it out would silently lose real evidence.
    This also means Shodan/Censys (or any future source) get included
    automatically the moment their section data exists, with no
    per-source hardcoding needed.

    Excludes the indicator's own value (digest["indicator"]) from the result
    — that value trivially appears in nearly every section describing it
    (e.g. an IP being investigated will show up in resolutions, page
    titles, abuse reports, etc. across sources just because it's the thing
    being looked up), which is tautological, not corroboration between
    independent sources."""
    sections_to_scan = [k for k in digest.keys() if k.endswith("_section") and k != "pivot_section"]
    indicator_value = str(digest.get("indicator", "")).strip().lower()

    found = {}  # identifier -> set(section_name)
    for sec_name in sections_to_scan:
        sec = digest.get(sec_name)
        if not sec:
            continue
        blob = " ".join(_stringify_section_values(sec))
        idents = set()
        for kind, pattern in IDENTIFIER_PATTERNS.items():
            idents.update(m.group(0) for m in pattern.finditer(blob))
        for ident in idents:
            found.setdefault(ident, set()).add(sec_name)

    # Comment-embedded claims: only a curated set of high-signal labels are
    # checked (malware/threat-type names), to avoid false positives from
    # generic short values like "domain" or "100%" matching unrelated text.
    claim_labels_of_interest = {"malware", "threat type", "ioc"}
    for label, value in _extract_comment_claims(digest):
        if label.strip().lower() not in claim_labels_of_interest:
            continue
        if len(value) < 5 or value.replace("%", "").replace(".", "").isdigit():
            continue
        secs_with_value = set()
        for sec_name in sections_to_scan:
            sec = digest.get(sec_name)
            if not sec:
                continue
            blob = " ".join(_stringify_section_values(sec))
            if value.lower() in blob.lower():
                secs_with_value.add(sec_name)
        if len(secs_with_value) >= 2:
            found.setdefault(value, set()).update(secs_with_value)

    return {
        k: sorted(v) for k, v in found.items()
        if len(v) >= 2 and k.strip().lower() != indicator_value
    }


def _extract_comment_claims(digest):
    """Extracts '**Label:** value' structured claims from VT community
    comments (a common format for pasted third-party threat intel reports).
    Returns a list of (label, value) tuples. Purely deterministic regex
    extraction — no LLM involvement, so it can't fabricate a claim the
    comment doesn't actually contain."""
    claims = []
    comments = (digest.get("vt_section") or {}).get("comments") or []
    for c in comments:
        text = c.get("text", "") if isinstance(c, dict) else str(c)
        for label, value in re.findall(r"\*\*(.+?):\*\*\s*(.+)", text):
            value = value.strip().strip("`")
            if value:
                claims.append((label.strip(), value))
    return claims


# ==========================================================================
# LLM LAYER — small, isolated, single-purpose calls. Each one is sanitized
# and has a safe deterministic fallback so a malformed generation can never
# corrupt the report or introduce a contradiction.
# ==========================================================================

def _sanitize_snippet(text, max_sentences=2):
    if not text:
        return ""
    text = text.strip()
    text = re.sub(r"^#{1,6}\s.*$", "", text, flags=re.MULTILINE)  # strip stray headers
    text = re.sub(r"[\[\]{}]", "", text)  # strip brackets/braces
    text = re.sub(r"\bnull\b|\bNone\b", "", text, flags=re.IGNORECASE)
    text = text.strip().strip("\n")
    # Keep only the first N sentences to prevent runaway generation.
    sentences = re.split(r"(?<=[.!?])\s+", text)
    text = " ".join(sentences[:max_sentences]).strip()
    return text


_DEFAULT_SNIPPET_SYSTEM = (
    "You are a concise cyberthreat analyst. Respond with plain prose only: "
    "1-2 sentences, no headers, no markdown lists, no brackets, no restating "
    "raw field names. Do not invent facts beyond what is given in the prompt."
)


class CancelToken:
    """Cross-thread cancellation handle for a single AI-summary generation.

    The blocking Ollama HTTP calls run on a worker thread (via FastAPI's
    threadpool), while the request-disconnect check runs on the event loop
    thread — so aborting needs to reach across threads. Setting `cancelled`
    is checked before every new Ollama call and between every streamed
    chunk of the current one, so cancellation takes effect immediately
    while tokens are actively arriving (the normal case — verified this is
    sub-10ms once streaming is underway). Closing whatever `response` is
    currently registered is best-effort cleanup on top of that: it
    releases the connection promptly when a chunk is already sitting in
    the socket buffer, but if a call happens to be blocked waiting on
    Ollama for its very first byte, the close doesn't reliably interrupt
    that read on Windows — cancellation of that one in-flight call then
    lands as soon as Ollama responds, not instantly. Either way, no
    *further* calls are ever started once cancelled."""

    def __init__(self):
        self.cancelled = threading.Event()
        self._lock = threading.Lock()
        self._response = None

    def set_response(self, resp):
        with self._lock:
            self._response = resp

    def abort(self):
        self.cancelled.set()
        with self._lock:
            resp = self._response
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _ollama_collect(prompt, num_predict, system, cancel_token=None):
    """Blocking call that returns Ollama's full response text (or None on
    failure/cancellation). Internally issues the request with stream=True
    even though the caller wants the whole text at once — that's the only
    way to register the in-flight `requests.Response` on cancel_token so an
    external abort() can close the socket and interrupt a call that's
    already blocked mid-read, rather than only being able to stop it
    between whole (non-streamed) calls."""
    if cancel_token and cancel_token.cancelled.is_set():
        return None
    resp = None
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "system": system,
                "prompt": prompt,
                "stream": True,
                "options": {"temperature": TEMPERATURE, "num_predict": num_predict, "num_ctx": NUM_CTX},
            },
            timeout=TIMEOUT_SECS,
            stream=True,
        )
        if cancel_token:
            cancel_token.set_response(resp)
        resp.raise_for_status()
        pieces = []
        for line in resp.iter_lines():
            if cancel_token and cancel_token.cancelled.is_set():
                return None
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            pieces.append(data.get("response", ""))
            if data.get("done"):
                break
        return "".join(pieces)
    except Exception as e:
        print(f"[_ollama_collect] {e}")
        return None
    finally:
        if cancel_token:
            cancel_token.set_response(None)
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _llm_snippet(prompt, num_predict=100, fallback="", max_sentences=2, system=None, cancel_token=None):
    text = _ollama_collect(prompt, num_predict, system or _DEFAULT_SNIPPET_SYSTEM, cancel_token=cancel_token)
    if text is None:
        return fallback
    cleaned = _sanitize_snippet(text, max_sentences=max_sentences)
    return cleaned if cleaned else fallback


def _llm_snippet_stream(prompt, num_predict=100, fallback="", cancel_token=None):
    """Same purpose as _llm_snippet, but yields text as Ollama generates it
    (token/word level) instead of blocking for the full completion. Used by
    stream_detailed_verdict so the LLM-backed sentences actually stream
    live rather than appearing as one pasted-in block.

    Trade-off vs _llm_snippet: sentence-count capping and header/bracket
    stripping can only be done reliably on complete text, so this variant
    does lighter on-the-fly cleanup (dropping literal bracket characters
    per chunk) and relies on num_predict + the system prompt's '1-2
    sentences' instruction to bound length, rather than trimming after the
    fact. If nothing is received at all, it yields the fallback once —
    unless cancel_token fired, in which case there's no point substituting
    a fallback for text nobody asked to keep reading."""
    if cancel_token and cancel_token.cancelled.is_set():
        return
    received_any = False
    resp = None
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "system": _DEFAULT_SNIPPET_SYSTEM,
                "prompt": prompt,
                "stream": True,
                "options": {"temperature": TEMPERATURE, "num_predict": num_predict, "num_ctx": NUM_CTX},
            },
            timeout=TIMEOUT_SECS,
            stream=True,
        )
        if cancel_token:
            cancel_token.set_response(resp)
        resp.raise_for_status()
        for line in resp.iter_lines():
            if cancel_token and cancel_token.cancelled.is_set():
                return
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            chunk = data.get("response", "")
            if chunk:
                # Light on-the-fly cleanup only — full sentence-capping isn't
                # possible mid-stream without buffering, which would defeat
                # the point of streaming.
                chunk = re.sub(r"[\[\]{}]", "", chunk)
                chunk = re.sub(r"\bnull\b|\bNone\b", "", chunk, flags=re.IGNORECASE)
                if chunk:
                    received_any = True
                    yield chunk
            if data.get("done"):
                break
    except Exception as e:
        print(f"[_llm_snippet_stream] {e}")
    finally:
        if cancel_token:
            cancel_token.set_response(None)
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass
    if not received_any and fallback and not (cancel_token and cancel_token.cancelled.is_set()):
        yield fallback


def _source_evidence_prompt(source, label, section_key, section_data):
    prompt = (
        f"Source: {source}. Its findings_label is \"{label}\".\n"
        f"Its detail data ({section_key}): {json.dumps(section_data)[:1500]}\n\n"
        f"In 1-2 sentences, state a concrete detail from this data and explain what it "
        f"indicates about risk. Do not mention any source other than {source}. Do not state "
        f"a verdict or severity word other than what is already in the findings_label."
    )
    return prompt, ""  # fallback is empty: no interpretation is safer than a wrong one


def _source_evidence_snippet(source, label, section_key, section_data):
    if not section_data:
        return ""
    prompt, fallback = _source_evidence_prompt(source, label, section_key, section_data)
    return _llm_snippet(prompt, num_predict=100, fallback=fallback)


def _source_evidence_snippet_stream(source, label, section_key, section_data, cancel_token=None):
    if not section_data:
        return
    prompt, fallback = _source_evidence_prompt(source, label, section_key, section_data)
    yield from _llm_snippet_stream(prompt, num_predict=100, fallback=fallback, cancel_token=cancel_token)


def _classify_tier_word(word):
    w = (word or "").strip().upper()
    return {"MALICIOUS": "Malicious", "SUSPICIOUS": "Suspicious", "CLEAN": "Clean"}.get(w)


def _independent_assessment_prompt(digest, overlaps):
    """Builds a prompt containing ONLY raw evidence — deliberately withholds
    the JSON's own verdict/score/recommendation — so the model forms a
    genuinely independent judgment rather than just echoing what it's told.
    Response format is fixed (TIER: / REASONING:) so it can be parsed
    reliably without an LLM having to self-report structured data.

    Deliberately qualitative, not quantitative — and deliberately
    label-free: neither per-source findings_label/verdict strings (e.g.
    "High Risk Findings") nor any numeric count (detection counts, vendor
    counts, pulse counts, abuse scores, "N total entries", etc.) reach this
    prompt anywhere. A findings_label is itself a pre-digested conclusion —
    handing it over would let the model just echo/lean on that conclusion
    instead of reasoning from evidence, which defeats the point of an
    "independent" assessment. Numeric counts have the same shortcut
    problem: they'd let the model do simple threshold math (e.g. "5
    vendors flagged -> malicious") instead of reasoning about what the
    evidence actually describes. What IS given is qualitative/descriptive
    per-source evidence (named vendors and their detection labels, tags,
    registrar, resolutions, pulse descriptions, category names, etc. — see
    _qualitative_source_facts) plus booleans and names for pivot/overlap
    facts.

    Python-side validation of the model's response (see
    _get_independent_assessment) still checks the real findings_label/
    findings_tier data from the digest afterward, to catch the model
    fabricating a denial or fabricating risk that isn't there — that
    ground truth is just never shown to the model itself here.

    source_interpretations is deliberately NOT threaded into this prompt
    (unlike an earlier version of this function): those interpretive
    sentences are written by _source_evidence_snippet, which is explicitly
    allowed to reference each source's findings_label and counts. Passing
    them in here as "prior interpretations" grounding would leak that
    label/count information back in through the back door, undermining the
    whole point of this being a label-free, count-free prompt. If someone
    wants to re-add prior-interpretation grounding later, it needs its own
    label/number-scrubbing pass first — don't just wire it back in."""
    active_sources = digest.get("active_sources") or []
    pivot_facts = _compute_pivot_facts(digest.get("pivot_section"))
    context = {
        "per_source_evidence": {
            source: _qualitative_source_facts(source, digest) for source in active_sources
        },
        "pivot_scan_performed": bool(pivot_facts.get("performed")),
        "pivot_found_malicious": bool(pivot_facts.get("malicious")),
        "pivot_found_suspicious": bool(pivot_facts.get("suspicious")),
        "literal_cross_source_overlaps": list(overlaps.keys()),
    }
    pivot_weighting_line = (
        "- A pivot IOC being found malicious carries more weight than one merely flagged "
        "suspicious.\n" if pivot_facts.get("performed") else ""
    )
    reasoning_context = (
        "Some context to help you reason about this — not rules to mechanically apply, just "
        "considerations worth weighing as you form your own judgment:\n"
        "- Different sources check fundamentally different things. A content or infrastructure "
        "scanner finding nothing doesn't mean a reputation/abuse-report source's evidence is "
        "wrong or should be discounted — they're looking at different signals, so one finding "
        "nothing isn't evidence against what another one did find.\n"
        "- A source with no evidence listed may simply mean that source hasn't been updated "
        "with current data on this indicator yet, or doesn't track this type of activity at "
        "all — it is not positive evidence of safety. Do not let sources with no evidence walk "
        "back, dilute, or outweigh genuine risk indicated by evidence other sources already "
        "reported; the risky facts that exist don't become less real just because other "
        "sources are silent. But if NO source shows any concerning evidence, there is no pivot "
        "risk, and there is no cross-source overlap, that is what a Clean indicator looks "
        "like — absence of any risk signal is not itself grounds for Suspicious.\n"
        "- A literal cross-source overlap (the same identifier appearing independently in "
        "multiple sections) is a meaningfully stronger signal than sources merely describing "
        "similarly concerning things in general terms, since it means multiple independent "
        "systems converged on the exact same specific data point.\n"
        f"{pivot_weighting_line}"
        "Weigh these considerations however you judge they apply here — you are not bound to a "
        "formula, and different evidence patterns can reasonably support different conclusions."
    )

    prompt = (
        f"Evidence (a pre-existing verdict/score exists but is deliberately withheld from you "
        f"here — form your own independent judgment from this raw evidence only): "
        f"{json.dumps(context)}\n\n"
        f"{reasoning_context}\n\n"
        f"Based ONLY on this evidence, classify this indicator's risk as exactly one of: "
        f"MALICIOUS, SUSPICIOUS, or CLEAN. Respond in exactly this format and nothing else:\n"
        f"TIER: <your classification>\n"
        f"REASONING: <2-3 sentences explaining your classification, citing the specific "
        f"evidence above>\n\n"
        f"Your REASONING must be factually consistent with the 'per_source_evidence' given "
        f"above — check it before you write. Do not claim a source found or showed something "
        f"that isn't in its evidence list, and do not deny or contradict something that is."
    )
    return prompt


def _get_independent_assessment(digest, overlaps, cancel_token=None, source_interpretations=None):
    """Blocking call: returns (tier, reasoning) or (None, None) if the call
    fails, is cancelled, or the response can't be parsed into the required
    format. A parse failure is treated as 'no independent assessment
    available' — the caller falls back to the plain deterministic sentence,
    same as any other failure mode, rather than guessing at malformed
    output.

    source_interpretations is accepted (callers already pass it through
    from _render_source_findings) but deliberately NOT forwarded into
    _independent_assessment_prompt — see that function's docstring for why
    it would leak label/count information back into a prompt that's meant
    to be free of both. The parameter is kept here so callers don't need
    to change, and so this isn't silently re-wired later without
    re-reading that reasoning."""
    prompt = _independent_assessment_prompt(digest, overlaps)
    text = _ollama_collect(
        prompt, num_predict=180,
        system=(
            "You are an independent cyberthreat analyst reviewing raw evidence. You "
            "have NOT been told any pre-existing verdict — form your own genuine "
            "judgment strictly from the evidence given, weighing the considerations in "
            "the prompt as context for your own reasoning rather than as rules to "
            "mechanically apply. Respond in exactly the requested format, nothing else, "
            "no extra commentary before or after."
        ),
        cancel_token=cancel_token,
    )
    if text is None:
        return None, None

    tier_match = re.search(r"TIER:\s*(MALICIOUS|SUSPICIOUS|CLEAN)", text, re.IGNORECASE)
    if not tier_match:
        return None, None
    tier = _classify_tier_word(tier_match.group(1))
    reasoning_match = re.search(r"REASONING:\s*(.+)", text, re.IGNORECASE | re.DOTALL)
    reasoning = _sanitize_snippet(reasoning_match.group(1), max_sentences=3) if reasoning_match else ""

    checklist = _compute_source_checklist(digest)
    per_source_labels = {item["source"]: item["findings_label"] for item in checklist}
    labels_indicate_risk = any(
        re.search(r"high risk|medium risk", lbl, re.IGNORECASE)
        for lbl in per_source_labels.values()
    )
    denies_a_source = any(
        _reasoning_denies_source_findings(reasoning, src, lbl)
        for src, lbl in per_source_labels.items()
    )
    if labels_indicate_risk and (_CONTRADICTS_RISK_LABELS.search(reasoning) or denies_a_source):
        # The model claimed no risk was found while a source label plainly
        # says otherwise — a fabricated premise, not just a style issue.
        # Discard the whole assessment rather than show reasoning built on
        # a false statement; caller falls back to the deterministic tier.
        # Two checks catch different phrasing shapes: _CONTRADICTS_RISK_LABELS
        # matches known fixed templates ("no sources found malicious"),
        # while _reasoning_denies_source_findings generalizes to any
        # paraphrase that names a specific risk-labeled source and negates
        # a risk word near it in the same sentence — this is what caught
        # phrasings like "do not contain any high-risk findings from
        # VirusTotal" that no fixed template matched.
        print(f"[_get_independent_assessment] discarded: reasoning denies source findings: {reasoning!r}")
        return None, None

    pivot_facts = _compute_pivot_facts(digest.get("pivot_section"))
    pivot_actually_risky = bool(pivot_facts.get("malicious")) or bool(pivot_facts.get("suspicious"))
    if not pivot_actually_risky and _CLAIMS_PIVOT_RISK.search(reasoning):
        # Same failure mode as the label check above, but for the pivot
        # scan: the model claimed pivot IOCs were flagged when
        # pivot_section actually shows none — a fabricated premise about
        # evidence that was never given.
        print(f"[_get_independent_assessment] discarded: reasoning claims pivot risk not in evidence: {reasoning!r}")
        return None, None

    per_source = digest.get("per_source_summary") or {}
    any_source_flagged = any(
        per_source.get(item["source"], {}).get("findings_tier") not in (None, "none")
        for item in checklist
    )
    no_evidence_at_all = not any_source_flagged and not pivot_actually_risky and not overlaps
    if no_evidence_at_all and tier in ("Suspicious", "Malicious"):
        # Mirror image of the checks above: instead of denying risk that's
        # actually present, this is claiming risk that isn't present
        # anywhere in the evidence it was given — zero flagged sources, no
        # risky pivots, no overlaps. That's what Clean looks like; caller
        # falls back to the deterministic tier.
        print(f"[_get_independent_assessment] discarded: elevated tier with zero supporting evidence: {reasoning!r}")
        return None, None

    return tier, reasoning


_CONTRADICTS_RISK_LABELS = re.compile(
    r"no\s+sources?\s+found\s+(?:any\s+)?malicious|"
    r"none\s+of\s+the\s+sources?\s+found\s+(?:any\s+)?malicious|"
    r"no\s+malicious\s+activity\s+was\s+found|"
    r"no\s+source\s+(?:has\s+)?(?:identified|detected|reported)\s+(?:any\s+)?malicious",
    re.IGNORECASE,
)

# Generalized backstop for the same failure mode as _CONTRADICTS_RISK_LABELS
# above, but phrasing-agnostic: rather than matching a fixed set of exact
# templates (which a paraphrasing model will eventually slip past — e.g. "do
# not contain any high-risk findings from VirusTotal" matched none of the
# fixed templates above), this flags any sentence that names a risk-labeled
# source AND has a negation word within ~60 characters *before* a risk-related
# word. It only fires when the source's own findings_label indicates risk,
# so it never penalizes a model correctly describing a genuinely clean
# source as having no findings.
#
# Deliberately one-directional (negation ... risk-word, not the reverse).
# The reverse direction ("risk-word ... negation-word") was tried and
# produces false positives on legitimate hedging like "VirusTotal reported a
# High Risk Findings label ..., but without corroborating pivot evidence I
# weigh this as suspicious" — the negation there modifies an unrelated noun
# phrase ("corroborating pivot evidence"), not the risk label itself, but
# pure proximity matching can't tell the difference. Every real denial in
# the wild puts the negation immediately before what it's denying, so the
# one-directional form still catches the actual failure mode without that
# false-positive class.
_NEGATION_NEAR_RISK = re.compile(
    r"\b(?:no|not|none|without|lacks?|lacking|does\s*n[o']?t|do\s*n[o']?t)\b(.{0,60}?)"
    r"\b(?:risk|malicious|findings?)\b",
    re.IGNORECASE,
)

# A hedge conjunction between the negation word and the risk word is a
# strong signal the negation is modifying something else entirely (e.g.
# "not X, but without corroborating Y, [risk-word]") rather than denying
# the risk finding itself. Disqualify the match in that case.
_HEDGE_CONJUNCTIONS = re.compile(r"\b(?:but|however|though|although|yet)\b", re.IGNORECASE)


def _reasoning_denies_source_findings(reasoning, source, label):
    """True if `reasoning` contains a sentence that names `source` and
    negates a risk word near it, while `label` (that source's own
    findings_label) indicates risk. This is purely a factual-contradiction
    check — it says nothing about whether the model's chosen TIER agrees
    with the label. A model that weighs a High Risk label against other
    evidence and still lands on Suspicious is exercising legitimate
    independent judgment, not contradicting anything, as long as it doesn't
    also write a sentence claiming that source found no risk/malicious/
    findings — that combination doesn't trip this check."""
    if not re.search(r"high risk|medium risk", label or "", re.IGNORECASE):
        return False
    for sentence in re.split(r"(?<=[.!?])\s+", reasoning or ""):
        if source.lower() not in sentence.lower():
            continue
        match = _NEGATION_NEAR_RISK.search(sentence)
        if match and not _HEDGE_CONJUNCTIONS.search(match.group(1)):
            return True
    return False

_CLAIMS_PIVOT_RISK = re.compile(
    r"pivot\s+(?:ioc|scan|indicator)s?.{0,40}?"
    r"(?:flagg|identif|report|convergen|found).{0,40}?"
    r"(?:malicious|suspicious)",
    re.IGNORECASE,
)


def _build_ai_final_assessment(digest, overlaps, cancel_token=None, source_interpretations=None):
    """Returns (tier, sentence) for the Final Assessment's headline
    conclusion. Unlike the old gated version, the AI's own independent
    classification IS the headline now — it is no longer discarded when it
    disagrees with the JSON's verdict field. The JSON's verdict is still
    always shown separately (as reference data, not as an overriding
    authority), so nothing is hidden; but the "Overall Assessment" the
    reader sees is the AI's own judgment.

    Falls back to the deterministic verdict-derived tier ONLY if the AI
    call fails outright or its response can't be parsed into a valid tier —
    there must always be a headline tier shown, and a broken LLM call is
    the one case where there's no AI opinion to report at all."""
    deterministic_tier = _classify_verdict(digest.get("verdict"))
    ai_tier, ai_reasoning = _safe_call(
        _get_independent_assessment, digest, overlaps, cancel_token, source_interpretations,
        fallback=(None, None), label="_get_independent_assessment",
    )
    if ai_tier and ai_reasoning:
        sentence = (
            f"Based on independent review of the evidence above, this indicator is assessed as "
            f"{ai_tier.lower()}: {ai_reasoning}"
        )
        return ai_tier, sentence

    # AI call failed or unparseable — no independent opinion available, so
    # fall back to the deterministic tier as the only tier we can report.
    sentence = f"Based on the evidence discussed above, this indicator presents as {deterministic_tier.lower()}."
    return deterministic_tier, sentence


def _closing_recommendation_prompt(digest, overlaps, tier=None):
    checklist = _compute_source_checklist(digest)
    pivot_facts = _compute_pivot_facts(digest.get("pivot_section"))
    tier = tier or _classify_verdict(digest.get("verdict"))
    per_source = digest.get("per_source_summary") or {}
    flagged_sources = [
        c["source"] for c in checklist
        if per_source.get(c["source"], {}).get("findings_tier") not in (None, "none")
    ]
    context = {
        "risk_tier": tier,  # Malicious / Suspicious / Clean — may be the AI's own independent conclusion, not necessarily the JSON's raw verdict
        "sources_that_actually_flagged_something": flagged_sources,
        "sources_with_no_findings": [c["source"] for c in checklist if c["source"] not in flagged_sources],
        "pivot_found_malicious": bool(pivot_facts.get("malicious")) if pivot_facts.get("performed") else False,
        "has_literal_overlap": bool(overlaps),
    }

    tier_guidance = {
        "Malicious": (
            "This is a Malicious-tier indicator. Recommend concrete containment/escalation "
            "steps (e.g. blocking, isolating affected systems, cross-referencing pivot data)."
        ),
        "Suspicious": (
            "This is a Suspicious-tier indicator, not confirmed malicious. Recommend "
            "proportionate verification steps (e.g. monitoring, additional lookups) rather "
            "than urgent containment language — do not recommend blocking or quarantine as "
            "if this were confirmed malicious."
        ),
        "Clean": (
            "This is a Clean-tier indicator with no meaningful findings. Recommend routine, "
            "low-effort follow-up only (e.g. no action needed beyond standard monitoring "
            "cadence, or a brief note that this can be closed out). Do NOT recommend "
            "escalation, containment, blocking, quarantine, investigating lateral movement, "
            "or 'validating the detection' — there is no detection to validate. Keep it short."
        ),
    }.get(tier, "")

    stale_data_note = (
        "Note: sources listed in 'sources_with_no_findings' may simply lack current data on "
        "this indicator, or not track this type of activity at all — that is not evidence of "
        "safety. Do not let their silence soften your recommendation below what the risk_tier "
        "and the sources that DID flag something already warrant; keep the recommendation "
        "grounded in the risk that was actually found."
    )

    prompt = (
        f"Evidence summary: {json.dumps(context)}\n\n"
        f"{tier_guidance}\n\n"
        f"{stale_data_note}\n\n"
        f"Write a 2-4 sentence (fewer for a Clean verdict) practical recommendation for a "
        f"security analyst's next steps, grounded specifically in this evidence. Use the exact "
        f"source names given above — never say 'both' unless exactly two sources are "
        f"named, and never describe a source in 'sources_with_no_findings' as having 'flagged' "
        f"or 'detected' anything, since it explicitly found nothing. Do not just repeat "
        f"'escalate immediately' verbatim as a generic line regardless of risk tier — match the "
        f"urgency of your recommendation to the risk_tier given above. Write your own "
        f"recommended action even if it differs in emphasis or urgency from a generic "
        f"escalation instruction — but never mention, flag, or draw attention to the fact that "
        f"your recommendation might differ from any other stated recommendation. Do not use "
        f"phrases like 'unlike the stated recommendation', 'in contrast to', 'differs from the "
        f"JSON's recommendation', or similar — just state your own guidance plainly, as if no "
        f"comparison were being made."
    )

    fallback_by_tier = {
        "Malicious": (
            "Given the evidence above, the analyst should block the indicator at the network "
            "perimeter, cross-reference the flagged pivot hashes against internal telemetry, "
            "and monitor for further activity from the named sources' detections."
        ),
        "Suspicious": (
            "Given the mixed evidence above, the analyst should monitor this indicator and "
            "verify the flagged findings against additional sources before deciding on "
            "containment action."
        ),
        "Clean": (
            "No meaningful findings were identified for this indicator; no action is required "
            "beyond routine monitoring."
        ),
    }
    fallback = fallback_by_tier.get(tier, fallback_by_tier["Malicious"])
    return prompt, fallback


def _closing_recommendation(digest, overlaps, tier=None):
    prompt, fallback = _closing_recommendation_prompt(digest, overlaps, tier=tier)
    text = _llm_snippet(prompt, num_predict=160, fallback=fallback)
    return _scrub_recommendation_mismatch_language(text)


def _closing_recommendation_stream(digest, overlaps, tier=None, cancel_token=None):
    """Streams the closing recommendation at sentence granularity rather
    than token-by-token: the mismatch-scrub safety net needs a complete
    sentence to decide whether to drop it, so we buffer only until each
    sentence boundary, check it, then yield immediately. This is still far
    more granular than waiting for the entire 2-4 sentence block."""
    prompt, fallback = _closing_recommendation_prompt(digest, overlaps, tier=tier)
    buffer = ""
    got_any = False
    for chunk in _llm_snippet_stream(prompt, num_predict=160, fallback="", cancel_token=cancel_token):
        buffer += chunk
        while True:
            m = re.search(r"[.!?]\s+", buffer)
            if not m:
                break
            sentence, buffer = buffer[:m.end()], buffer[m.end():]
            if not _MISMATCH_PHRASES.search(sentence):
                got_any = True
                yield sentence
    if buffer.strip() and not _MISMATCH_PHRASES.search(buffer):
        got_any = True
        yield buffer
    if not got_any and not (cancel_token and cancel_token.cancelled.is_set()):
        yield fallback


_MISMATCH_PHRASES = re.compile(
    r"(?:unlike|in contrast to|differs? from|contrary to|as opposed to|"
    r"diverges? from|deviat\w* from)\s+(?:the\s+)?(?:JSON'?s?\s+)?"
    r"(?:own\s+)?(?:stated\s+)?recommendation",
    re.IGNORECASE,
)


def _scrub_recommendation_mismatch_language(text):
    """Safety net: if the model still flags a mismatch with the JSON's own
    recommendation field despite the prompt instruction, drop that sentence
    rather than let it through. Splits on sentence boundaries and removes
    only the offending sentence(s), keeping the rest intact."""
    if not text or not _MISMATCH_PHRASES.search(text):
        return text
    sentences = re.split(r"(?<=[.!?])\s+", text)
    kept = [s for s in sentences if not _MISMATCH_PHRASES.search(s)]
    return " ".join(kept).strip()


# ==========================================================================
# DETERMINISTIC RENDERERS — build each report section as exact text.
# ==========================================================================

def _render_pivot_analysis(digest):
    facts = _compute_pivot_facts(digest.get("pivot_section"))
    if not facts.get("performed"):
        return "No pivot scan was performed, as pivot_section.pivot_iocs contains no entries."

    lines = [
        f"A pivot scan was performed, checking {facts['total_checked']} pivot IOC"
        f"{'s' if facts['total_checked'] != 1 else ''} per pivot_section.pivot_iocs."
    ]
    if facts["malicious"]:
        joined = ", ".join(f"`{h}`" for h in facts["malicious"])
        lines.append(
            f"pivot_section.malicious_pivots shows {len(facts['malicious'])} of these IOC"
            f"{'s' if len(facts['malicious']) != 1 else ''} flagged malicious: {joined}."
        )
    else:
        lines.append("pivot_section.malicious_pivots contains no entries — no malicious pivots were found.")

    if facts["suspicious"]:
        joined = ", ".join(f"`{h}`" for h in facts["suspicious"])
        lines.append(
            f"pivot_section.suspicious_pivots shows {len(facts['suspicious'])} additional IOC"
            f"{'s' if len(facts['suspicious']) != 1 else ''} flagged suspicious: {joined}."
        )
    else:
        lines.append("pivot_section.suspicious_pivots contains no entries — no suspicious pivots were found.")

    return " ".join(lines)


def _render_vt_detail(data, include_counts=True):
    """include_counts=False drops every purely-numeric magnitude (detection
    counts, vendor/record counts) while keeping named/descriptive content
    (vendor names + their labels, tags, registrar, resolutions, dns records,
    comment claims) intact. Used by _qualitative_source_facts for the
    independent Final Assessment prompt; every other caller keeps the
    default (True) and sees unchanged output."""
    if not data:
        return []
    lines = []
    if include_counts:
        mal, susp, harm, undet = data.get("malicious"), data.get("suspicious"), data.get("harmless"), data.get("undetected")
        counts = [(n, v) for n, v in (("malicious", mal), ("suspicious", susp), ("harmless", harm), ("undetected", undet)) if v is not None]
        if counts:
            lines.append("Detection counts (vt_section): " + ", ".join(f"{v} {n}" for n, v in counts) + ".")
    vendors = data.get("malicious_vendors") or []
    if vendors:
        names = []
        for v in vendors[:3]:
            if isinstance(v, dict):
                names.append(f"{v.get('vendor', 'unknown vendor')} ({v.get('name', 'unspecified')})")
            else:
                names.append(str(v))
        if include_counts:
            lines.append(
                f"vt_section.malicious_vendors flags this indicator via {len(vendors)} vendor(s), "
                f"including {', '.join(names)}."
            )
        else:
            lines.append(f"vt_section.malicious_vendors flags this indicator via vendors including {', '.join(names)}.")
    if data.get("tags"):
        lines.append(f"vt_section.tags lists: {', '.join(data['tags'])}.")
    if data.get("registrar"):
        lines.append(f"vt_section.registrar shows the domain is registered through {data['registrar']}.")
    if data.get("creation_date"):
        lines.append(f"vt_section.creation_date is {data['creation_date']}.")
    resolutions = data.get("resolutions") or []
    if resolutions:
        ips = ", ".join(r.get("ip", "") for r in resolutions if isinstance(r, dict) and r.get("ip"))
        if ips:
            lines.append(f"vt_section.resolutions shows the domain resolving to {ips}.")
    dns = data.get("dns_records") or []
    if dns:
        if include_counts:
            lines.append(f"vt_section.dns_records lists {len(dns)} record(s), including {'; '.join(dns[:3])}.")
        else:
            lines.append(f"vt_section.dns_records includes {'; '.join(dns[:3])}.")
    comments = data.get("comments") or []
    if comments:
        if include_counts:
            lines.append(f"vt_section.comments contains {len(comments)} community-submitted comment(s).")
        for i, c in enumerate(comments[:2], 1):
            summary = _summarize_vt_comment(c)
            if summary:
                lines.append(f"A community-submitted comment (#{i}) reports: {summary}")
    return lines


def _summarize_vt_comment(comment):
    """Deterministically extracts structured '**Label:** value' claims from
    a VT community comment (a common format for pasted third-party threat
    intel, e.g. ThreatFox reports). Returns a plain-prose summary, clearly
    framed as a community submission rather than VirusTotal's own
    detection — per-source attribution matters here because a comment's
    text is often *about* a different source entirely."""
    if not isinstance(comment, dict):
        return ""
    text = comment.get("text", "")
    if not text:
        return ""
    claims = re.findall(r"\*\*(.+?):\*\*\s*(.+)", text)
    if not claims:
        return ""
    parts = []
    for label, value in claims[:6]:
        value = value.strip().strip("`")
        label = label.strip()
        if value and label.lower() not in ("tags",):  # tags rendered separately below, avoid duplicate noise
            parts.append(f"{label}: {value}")
    if not parts:
        return ""
    date = comment.get("date", "")
    author = comment.get("author", "")
    attribution = f" (dated {date}, submitted by {author})" if date or author else ""
    note = (
        "This is a third-party claim embedded in the comment text, not VirusTotal's own "
        "automated detection — it may be quoting or referencing another source entirely."
    )
    return f"{'; '.join(parts)}{attribution}. {note}"


def _render_otx_detail(data, include_counts=True):
    if not data:
        return []
    lines = []
    pulse_count = data.get("pulse_count")
    if include_counts and pulse_count:
        lines.append(f"otx_section.pulse_count reports {pulse_count} pulse(s).")
    pulses = data.get("pulses_detail") or []
    for i, p in enumerate(pulses[:3], 1):
        desc = p.get("description") if isinstance(p, dict) else None
        if desc:
            lines.append(f"OTX's pulse {i} describes: {desc}")
    if include_counts and data.get("reputation_threat_score") is not None:
        lines.append(f"otx_section.reputation_threat_score is {data['reputation_threat_score']}.")
    if data.get("reputation_threat_type"):
        lines.append(f"otx_section.reputation_threat_type is {data['reputation_threat_type']}.")
    pdns = data.get("passive_dns") or []
    if pdns:
        examples = "; ".join(f"{r.get('record_type')}: {r.get('address')}" for r in pdns[:3])
        if include_counts:
            lines.append(f"otx_section.passive_dns lists {len(pdns)} record(s), including {examples}.")
        else:
            lines.append(f"otx_section.passive_dns includes {examples}.")
    return lines


def _render_urlscan_detail(data, include_counts=True):
    if not data:
        return []
    lines = []
    if data.get("categories"):
        lines.append(f"urlscan_section.categories lists: {', '.join(data['categories'])}.")
    if data.get("page_title"):
        lines.append(f"urlscan_section.page_title is \"{data['page_title']}\".")
    if data.get("server"):
        lines.append(f"urlscan_section.server identifies the hosting software as {data['server']}.")
    if data.get("domains"):
        if include_counts:
            lines.append(f"urlscan_section.domains lists {len(data['domains'])} associated domain(s): {', '.join(data['domains'][:3])}.")
        else:
            lines.append(f"urlscan_section.domains lists associated domain(s): {', '.join(data['domains'][:3])}.")
    return lines


def _render_google_intel_detail(data, include_counts=True):
    facts = _compute_google_intel_facts(data)
    if not facts:
        return []
    lines = []
    if "malware_families" in facts and facts["malware_families"]["total_count"]:
        f = facts["malware_families"]
        if include_counts:
            lines.append(
                f"google_intel_section.malware_families names {', '.join(f['first_three'])} "
                f"among {f['total_count']} total entries."
            )
        else:
            lines.append(f"google_intel_section.malware_families names {', '.join(f['first_three'])}.")
    if "apt_actors" in facts and facts["apt_actors"]["total_count"]:
        f = facts["apt_actors"]
        if include_counts:
            lines.append(
                f"google_intel_section.apt_actors names {', '.join(f['first_three'])} "
                f"among {f['total_count']} total entries."
            )
        else:
            lines.append(f"google_intel_section.apt_actors names {', '.join(f['first_three'])}.")
    if "cve_ids" in facts and facts["cve_ids"]["total_count"]:
        f = facts["cve_ids"]
        if include_counts:
            lines.append(
                f"google_intel_section.cve_ids names {', '.join(f['first_three'])} "
                f"among {f['total_count']} total entries."
            )
        else:
            lines.append(f"google_intel_section.cve_ids names {', '.join(f['first_three'])}.")
    if facts.get("severity_hits"):
        lines.append(f"google_intel_section.severity_hits lists {', '.join(facts['severity_hits'])}.")
    if facts.get("co_iocs"):
        if include_counts:
            parts = [f"{v} {k}" for k, v in facts["co_iocs"].items() if v]
            if parts:
                lines.append(f"google_intel_section.co_iocs reports {', '.join(parts)}.")
        else:
            keys = [k for k, v in facts["co_iocs"].items() if v]
            if keys:
                lines.append(f"google_intel_section.co_iocs reports the presence of: {', '.join(keys)}.")
    return lines


def _render_generic_detail(section_key, data, include_counts=True):
    """Fallback for any source not explicitly handled above (AbuseIPDB, Shodan,
    Censys, GreyNoise, URLhaus, ThreatFox, Hybrid, or any future source) —
    walks the section's own fields and reports whatever is genuinely present,
    without inventing structure that field doesn't have.

    include_counts=False additionally drops list-length numbers and bare
    numeric scalars (score-shaped fields, port numbers, etc.) — for an
    arbitrary/unknown source shape there's no reliable way to tell a
    meaningful count/score apart from an innocuous one, so every raw
    numeric scalar is conservatively excluded rather than guessed at."""
    if not data or not isinstance(data, dict):
        return []
    lines = []
    for key, value in data.items():
        if value is None or value == "" or value == [] or value == {}:
            continue
        if isinstance(value, list):
            if all(isinstance(v, (str, int, float)) for v in value):
                shown = ", ".join(str(v) for v in value[:3])
                if include_counts:
                    lines.append(f"{section_key}.{key} lists {len(value)} entr{'y' if len(value)==1 else 'ies'}: {shown}{'...' if len(value) > 3 else ''}.")
                else:
                    lines.append(f"{section_key}.{key} lists: {shown}{', ...' if len(value) > 3 else ''}.")
            elif include_counts:
                lines.append(f"{section_key}.{key} contains {len(value)} entr{'y' if len(value)==1 else 'ies'}.")
            # else (include_counts=False): a list of non-primitive entries has
            # nothing qualitative to report beyond its size, which is exactly
            # what this mode excludes — contributes no line.
        elif isinstance(value, dict):
            continue  # nested dicts need source-specific handling; skip rather than dump raw structure
        elif isinstance(value, bool):
            lines.append(f"{section_key}.{key} is {value}.")
        elif isinstance(value, (int, float)):
            if include_counts:
                lines.append(f"{section_key}.{key} is {value}.")
            # else: bare numeric scalar dropped — see docstring.
        else:
            lines.append(f"{section_key}.{key} is {value}.")
    return lines


def _render_abuse_detail(data, include_counts=True):
    if not data:
        return []
    lines = []
    if include_counts and data.get("abuse_score") is not None:
        lines.append(f"abuse_section.abuse_score is {data['abuse_score']} out of 100.")
    if include_counts and (data.get("total_reports") is not None or data.get("distinct_users") is not None):
        parts = []
        if data.get("total_reports") is not None:
            parts.append(f"{data['total_reports']} total report(s)")
        if data.get("distinct_users") is not None:
            parts.append(f"from {data['distinct_users']} distinct reporter(s)")
        lines.append("abuse_section shows " + " ".join(parts) + ".")
    if data.get("isp"):
        lines.append(f"abuse_section.isp identifies the hosting provider as {data['isp']}.")
    if data.get("country"):
        lines.append(f"abuse_section.country is {data['country']}.")
    if data.get("is_tor") is not None:
        lines.append(f"abuse_section.is_tor is {data['is_tor']}.")
    categories = data.get("top_categories") or []
    if categories:
        if include_counts:
            cat_str = ", ".join(f"{name} ({count})" for name, count in categories[:5] if isinstance(name, str))
        else:
            cat_str = ", ".join(name for name, _count in categories[:5] if isinstance(name, str))
        if cat_str:
            lines.append(f"abuse_section.top_categories reports: {cat_str}.")
    reports = data.get("reports") or []
    if reports:
        dates = [r.get("reported_at") for r in reports if isinstance(r, dict) and r.get("reported_at")]
        if dates:
            if include_counts:
                lines.append(
                    f"abuse_section.reports contains {len(reports)} individual report(s) shown, "
                    f"most recent at {max(dates)} and earliest shown at {min(dates)}."
                )
            else:
                lines.append(
                    f"abuse_section.reports shows activity most recently at {max(dates)} "
                    f"and earliest (among those shown) at {min(dates)}."
                )
    return lines


# Aliases per source: the same source can appear under different section key
# names depending on the feed's naming convention (e.g. AbuseIPDB data has
# been seen under both "abuseipdb_section" and "abuse_section"). All
# candidates are tried in order and the first key actually present in the
# digest wins, so a naming variant never silently falls back to "no data".
SOURCE_KEY_ALIASES = {
    "VirusTotal": ["vt_section", "virustotal_section"],
    "OTX": ["otx_section"],
    "URLScan": ["urlscan_section"],
    "Google Intel": ["google_intel_section", "googleintel_section"],
    "AbuseIPDB": ["abuse_section", "abuseipdb_section"],
    "Shodan": ["shodan_section"],
    "Censys": ["censys_section"],
    "GreyNoise": ["greynoise_section"],
    "URLhaus": ["urlhaus_section"],
    "ThreatFox": ["threatfox_section"],
    "Hybrid": ["hybrid_section"],
}


# Maps a source name (as it appears in active_sources) to its detail
# renderer. Section key resolution goes through SOURCE_KEY_ALIASES /
# _resolve_section_key below, not a single hardcoded key.
SOURCE_DETAIL_MAP = {
    "VirusTotal": _render_vt_detail,
    "OTX": _render_otx_detail,
    "URLScan": _render_urlscan_detail,
    "Google Intel": _render_google_intel_detail,
    "AbuseIPDB": _render_abuse_detail,
    "Shodan": _render_generic_detail,
    "Censys": _render_generic_detail,
    "GreyNoise": _render_generic_detail,
    "URLhaus": _render_generic_detail,
    "ThreatFox": _render_generic_detail,
    "Hybrid": _render_generic_detail,
}


def _guess_section_key(source_name):
    return re.sub(r"\s+", "_", source_name.strip().lower()) + "_section"


def _resolve_section_key(source, digest):
    """Tries every known alias for this source's section key, in order, and
    returns the first one actually present (and non-empty) in the digest.
    Falls back to a best-guess key derived from the source name if no known
    alias matches — that guessed key may still not exist, which is fine;
    callers handle a missing/empty section gracefully."""
    candidates = SOURCE_KEY_ALIASES.get(source, [])
    for key in candidates:
        if digest.get(key):
            return key
    guessed = _guess_section_key(source)
    if digest.get(guessed):
        return guessed
    # Nothing matched — return the first known alias (or the guess) so
    # calling code still has a sensible key name to reference/log, even
    # though digest.get(key) on it will be None/empty.
    return candidates[0] if candidates else guessed


def _render_source_detail_lines(source, digest):
    key = _resolve_section_key(source, digest)
    data = digest.get(key)
    renderer = SOURCE_DETAIL_MAP.get(source, _render_generic_detail)
    if renderer is _render_generic_detail:
        return _render_generic_detail(key, data)
    return renderer(data)


def _qualitative_source_facts(source, digest):
    """Same per-source detail extraction as _render_source_detail_lines
    (Source Findings' own facts), but with include_counts=False so every
    purely-numeric magnitude — detection counts, vendor/record counts,
    abuse scores, report totals, "among N total entries" — is stripped,
    leaving only named/descriptive/structural facts.

    Used ONLY by _independent_assessment_prompt (the independent Final
    Assessment call): that call is meant to form its MALICIOUS/SUSPICIOUS/
    CLEAN judgment from what the evidence actually describes, not from a
    magnitude that lets it shortcut to threshold math ("5 vendors flagged
    -> malicious") instead of reasoning about content. Every other caller
    (Source Findings, Corroboration) keeps using
    _render_source_detail_lines / _render_source_detail_lines's full,
    count-inclusive output — this function does not change what readers
    see there."""
    key = _resolve_section_key(source, digest)
    data = digest.get(key)
    if not data:
        return []
    renderer = SOURCE_DETAIL_MAP.get(source, _render_generic_detail)
    if renderer is _render_generic_detail:
        return _render_generic_detail(key, data, include_counts=False)
    return renderer(data, include_counts=False)


def _render_executive_summary_highlights(digest, overlaps):
    """Deterministic cross-section highlights — same guarantee-by-construction
    as every other numeric fact in this report, just surfaced earlier so the
    reader gets the shape of the evidence before reading each subsection."""
    checklist = _compute_source_checklist(digest)
    total_active = len(checklist)
    per_source = digest.get("per_source_summary") or {}
    flagged = [
        c["source"] for c in checklist
        if per_source.get(c["source"], {}).get("findings_tier") not in (None, "none")
    ]

    parts = []
    if total_active:
        parts.append(
            f"Of {total_active} active source{'s' if total_active != 1 else ''} "
            f"({', '.join(c['source'] for c in checklist)}), "
            f"{len(flagged)} returned a non-none finding tier"
            f"{' (' + ', '.join(flagged) + ')' if flagged else ''}."
        )

    pivot_facts = _compute_pivot_facts(digest.get("pivot_section"))
    if pivot_facts.get("performed"):
        mal_n = len(pivot_facts["malicious"])
        susp_n = len(pivot_facts["suspicious"])
        parts.append(
            f"pivot_section shows {mal_n} of {pivot_facts['total_checked']} checked pivot IOC(s) "
            f"flagged malicious" + (f" and {susp_n} flagged suspicious" if susp_n else "") + "."
        )

    if overlaps:
        idents = ", ".join(f"`{k}`" for k in overlaps.keys())
        parts.append(f"A literal cross-section match was found for {idents} — see Corroboration Assessment.")
    else:
        parts.append("No literal cross-section identifier match was found; see Corroboration Assessment for detail.")

    return " ".join(parts)


def _executive_summary_synthesis_prompt(digest, overlaps):
    checklist = _compute_source_checklist(digest)
    pivot_facts = _compute_pivot_facts(digest.get("pivot_section"))
    context = {
        "verdict": digest.get("verdict"),
        "triggered_by": digest.get("triggered_by"),
        "sources_with_labels": {c["source"]: c["findings_label"] for c in checklist},
        "pivot_found_malicious": bool(pivot_facts.get("malicious")) if pivot_facts.get("performed") else False,
        "has_literal_overlap": bool(overlaps),
    }
    prompt = (
        f"Evidence summary: {json.dumps(context)}\n\n"
        f"In 1-2 sentences, frame the overall shape of this evidence for a reader about to read "
        f"the full report below (what kind of picture it paints), without repeating the raw "
        f"numbers already given and without stating your own verdict word."
    )
    return prompt, ""


def _executive_summary_synthesis(digest, overlaps):
    prompt, fallback = _executive_summary_synthesis_prompt(digest, overlaps)
    return _llm_snippet(prompt, num_predict=90, fallback=fallback)


def _executive_summary_synthesis_stream(digest, overlaps, cancel_token=None):
    prompt, fallback = _executive_summary_synthesis_prompt(digest, overlaps)
    yield from _llm_snippet_stream(prompt, num_predict=90, fallback=fallback, cancel_token=cancel_token)


def _render_source_findings(digest):
    """Every active source gets equal, full treatment: its findings_label,
    every concrete deterministic fact from its own section (guaranteed
    correct, same mechanism as pivot/google_intel), and one short LLM
    interpretive sentence at the end. Google Intel is no longer special —
    it uses the exact same subsection pattern as every other source.

    Returns (block_text, interpretations) — interpretations is
    {source: interpretation_text} for every source that got a non-empty
    interpretive sentence. This is handed forward as grounding to the
    independent Final Assessment call, so it can't later contradict, in its
    own words, interpretive sentences it already wrote about the same
    evidence earlier in the same report."""
    checklist = _compute_source_checklist(digest)
    blocks = []
    interpretations = {}
    for item in checklist:
        source, label = item["source"], item["findings_label"]
        try:
            key = _resolve_section_key(source, digest)
            data = digest.get(key)
            detail_lines = _render_source_detail_lines(source, digest)
            interpretation = _source_evidence_snippet(source, label, key, data) if detail_lines else ""

            block = [f"## {source}", f"**Findings:** {label}."]
            if detail_lines:
                block.extend(f"- {line}" for line in detail_lines)
            else:
                block.append(f"No further detail is available in {key} beyond the findings label.")
            if interpretation:
                block.append(interpretation)
                interpretations[source] = interpretation
            blocks.append("\n".join(block))
        except Exception:
            import traceback
            print(f"[_render_source_findings:{source}] {traceback.format_exc()}")
            # Fault isolation: this source's detail rendering broke, but the
            # label itself is always safe to print — don't let one bad
            # source's data shape drop it (or everything after it) from the
            # report entirely.
            blocks.append(f"## {source}\n**Findings:** {label}.\n(Additional detail could not be rendered for this source.)")
    return "\n\n".join(blocks), interpretations


def _corroboration_analysis_prompt(digest, overlaps):
    """Grounds the model in facts already deterministically extracted: the
    real literal overlaps found (with the indicator's own trivial value
    already excluded upstream) and each source's own deterministic detail
    lines. The AI does the actual judgment of whether/how sources
    corroborate or complement each other — Python only supplies the vetted
    facts, it doesn't assemble the verdict on corroboration itself."""
    checklist = _compute_source_checklist(digest)
    source_evidence = {}
    for item in checklist:
        source = item["source"]
        lines = _render_source_detail_lines(source, digest)
        if lines:
            source_evidence[source] = lines[:4]

    prompt = (
        f"The indicator being investigated is: {json.dumps(digest.get('indicator', ''))}. Its "
        f"own value (this exact IP/domain/hash) will naturally appear across multiple sources' "
        f"data simply because they are all describing the same thing being looked up — that is "
        f"NOT corroboration and must never be cited as a relationship or overlap. Only "
        f"corroboration involving a DIFFERENT value (a different hash, a different IP, a "
        f"malware name, an actor name, a domain other than the indicator itself, etc.) counts.\n\n"
        f"Literal identifiers already confirmed (by exact string match) to appear in more than "
        f"one section — these are given as verified fact, not for you to re-derive, and the "
        f"indicator's own value has already been excluded from this list: "
        f"{json.dumps(overlaps)}\n\n"
        f"Evidence already established per source: {json.dumps(source_evidence)}\n\n"
        f"Write a short Corroboration Assessment (3-5 sentences) analyzing whether these "
        f"sources genuinely support each other. Cover:\n"
        f"1. If the literal identifiers dict above is non-empty, name the exact overlapping "
        f"value(s) and which sections they appear in, exactly as given — never invent an "
        f"overlap not listed there, and never cite the indicator's own value (even if you "
        f"notice it repeated across sources' raw evidence below) as if it were a meaningful "
        f"overlap.\n"
        f"2. Separately, identify at most 2 cases where two DIFFERENT sources report DIFFERENT "
        f"facts that nonetheless describe or reinforce the same underlying behavior pattern "
        f"(e.g. one reports a technique, another independently reports a related effect on the "
        f"SAME activity). Name both sources for each case you find. Do NOT treat two sources "
        f"merely sharing a severity label (e.g. both 'high risk') as a relationship — a real, "
        f"specific, nameable link is required. CRITICALLY: do not treat two sources as related "
        f"just because both happen to mention malware, actors, or threats in general — if source "
        f"A names one specific malware/actor (e.g. \"ClearFake\") and source B independently "
        f"names a DIFFERENT specific malware/actor (e.g. \"Bobik\" or \"MSUPDATER\"), those are "
        f"two different, unrelated entities and must NOT be described as reinforcing each other "
        f"or describing the 'same behavior pattern' — that is a category-level fallacy, not a "
        f"real link. A genuine relationship requires the SAME specific named entity, technique, "
        f"or activity appearing from two angles — not two different named things that both "
        f"happen to be in the general category of 'malware' or 'threat actor'. If a name (like "
        f"\"ClearFake\") already appears in the literal identifiers list above, do not also "
        f"invent a separate complementary link involving that same name paired with an unrelated "
        f"different name from another source. Do NOT use speculative bridging language like "
        f"'if X is happening, it could indicate Y' or 'this suggests that' to connect two facts "
        f"that aren't actually linked — a relationship must be a direct factual reinforcement, "
        f"not a hypothetical chain of reasoning you construct.\n"
        f"3. If neither a literal overlap nor a genuine behavioral relationship exists, say "
        f"plainly that corroboration is limited or not established — do not manufacture a "
        f"connection just to avoid saying so."
    )
    return prompt


_SEVERITY_ONLY_CLAIM = re.compile(
    r"both\s+.{0,60}?"
    r"(?:flagg\w*|rat\w*|label\w*|report\w*|found|assess\w*)\s+.{0,40}?"
    r"(?:high|medium|low|malicious)\s*(?:-|\s)?risk.{0,60}?"
    r"(?:corroborat\w*|confirm\w*|reinforc\w*|support\w* each other|agree\w*)",
    re.IGNORECASE,
)


def _scrub_severity_only_claims(text):
    """Backstop for the same failure mode _scrub_recommendation_mismatch_language
    guards against elsewhere: the prompt instructs the model not to treat two
    sources sharing a severity label as a relationship, but a small model can
    still ignore that. This catches the most common phrasing pattern
    ('X and Y both flagged this as high risk, corroborating each other') and
    drops that sentence. It's a regex heuristic, not full semantic filtering
    — it won't catch every phrasing, but it catches the obvious template."""
    if not text or not _SEVERITY_ONLY_CLAIM.search(text):
        return text
    sentences = re.split(r"(?<=[.!?])\s+", text)
    kept = [s for s in sentences if not _SEVERITY_ONLY_CLAIM.search(s)]
    return " ".join(kept).strip()


def _render_corroboration_deterministic_fallback(overlaps):
    """Plain-text description of the literal overlaps, used ONLY as a
    fallback if the AI call fails — the AI is now the primary author of
    this section, not Python, per design; this exists purely so the
    section is never empty if Ollama is unreachable."""
    if not overlaps:
        return (
            "No literal shared value (identical hash, IP, or CVE) was found verbatim across "
            "two different sections of the JSON. Corroboration is therefore limited to the "
            "consensus_ratio alone; agreement between sources on severity is not, by itself, "
            "evidence of a shared data point."
        )
    lines = ["The following identifiers appear verbatim in more than one section:"]
    for ident, secs in overlaps.items():
        if len(secs) == 2:
            joined = f"both {secs[0]} and {secs[1]}"
        else:
            joined = ", ".join(secs[:-1]) + f", and {secs[-1]}"
        lines.append(f"- `{ident}` appears in {joined}.")
    return "\n".join(lines)


def _render_corroboration(digest, cancel_token=None):
    overlaps = _find_cross_section_overlaps(digest)
    fallback = _render_corroboration_deterministic_fallback(overlaps)
    prompt = _corroboration_analysis_prompt(digest, overlaps)
    system = (
        "You are a precise cyberthreat analyst assessing whether sources corroborate or "
        "complement each other. You only ever describe overlaps or relationships that are "
        "explicitly given to you or clearly grounded in the evidence — you never invent a "
        "connection, and shared severity alone is never sufficient. If nothing qualifies, you "
        "say plainly that corroboration is limited."
    )
    text = _llm_snippet(prompt, num_predict=280, fallback=fallback, max_sentences=6, system=system, cancel_token=cancel_token)
    text = _scrub_severity_only_claims(text)
    if not text:
        text = fallback
    return text, overlaps


def render_report(digest):
    checklist = _compute_source_checklist(digest)
    verdict = digest.get("verdict") or ""
    score = _fmt_scalar(digest.get("score", ""))
    consensus = digest.get("consensus_ratio", "")
    triggered_by = digest.get("triggered_by") or []
    recommendation_field = digest.get("recommendation", "")

    corro_result = _safe_call(_render_corroboration, digest,
                               fallback="Corroboration Assessment could not be generated due to an internal error; check server logs.",
                               label="_render_corroboration")
    if isinstance(corro_result, tuple):
        corro_text, overlaps = corro_result
    else:
        corro_text, overlaps = corro_result, {}

    highlights = _safe_call(_render_executive_summary_highlights, digest, overlaps,
                             fallback="", label="_render_executive_summary_highlights")
    synthesis = _safe_call(_executive_summary_synthesis, digest, overlaps,
                            fallback="", label="_executive_summary_synthesis")
    exec_summary = (
        f"The indicator `{digest.get('indicator', '')}` carries a verdict of {verdict} with a "
        f"score of {score}. The consensus_ratio is {consensus}, with triggered_by consisting of "
        f"{', '.join(triggered_by) if triggered_by else 'no sources'}. The JSON's own "
        f"recommendation is: {recommendation_field}."
        + (f"\n\n{highlights}" if highlights else "")
        + (f"\n\n{synthesis}" if synthesis else "")
    )

    source_findings_result = _safe_call(
        _render_source_findings, digest,
        fallback=("Source Findings could not be generated due to an internal error; check server logs.", {}),
        label="_render_source_findings",
    )
    if isinstance(source_findings_result, tuple):
        source_findings, source_interpretations = source_findings_result
    else:
        source_findings, source_interpretations = source_findings_result, {}
    pivot_analysis = _safe_call(
        _render_pivot_analysis, digest,
        fallback="Pivot Analysis could not be generated due to an internal error; check server logs.",
        label="_render_pivot_analysis",
    )
    deterministic_tier = _classify_verdict(verdict)
    ai_final_tier, conclusion_sentence = _safe_call(
        _build_ai_final_assessment, digest, overlaps, None, source_interpretations,
        fallback=(deterministic_tier, f"Based on the evidence discussed above, this indicator presents as {deterministic_tier.lower()}."),
        label="_build_ai_final_assessment",
    )

    closing_rec = _safe_call(
        _closing_recommendation, digest, overlaps, ai_final_tier,
        fallback=(
            "Given the flagged findings above, the analyst should validate each source's "
            "detections against internal telemetry and take action consistent with the "
            "JSON's own recommendation."
        ),
        label="_closing_recommendation",
    )

    final_assessment = (
        f"**Overall Assessment: {ai_final_tier}**\n\n"
        f"{conclusion_sentence} For reference, the JSON's own fields report: verdict "
        f"\"{verdict}\", score {score}, consensus_ratio {consensus}, and triggered_by "
        f"consisting of {', '.join(triggered_by) if triggered_by else 'no sources'}."
        f"\n\n{closing_rec}"
    )

    return (
        f"# Executive Summary\n{exec_summary}\n\n"
        f"# Source Findings\n{source_findings}\n\n"
        f"# Pivot Analysis\n{pivot_analysis}\n\n"
        f"# Corroboration Assessment\n{corro_text}\n\n"
        f"# Final Assessment\n{final_assessment}\n"
    )


# ==========================================================================
# PUBLIC ENTRY POINTS
# ==========================================================================

def generate_detailed_verdict(digest):
    try:
        return render_report(digest), []
    except Exception as e:
        print(f"[generate_detailed_verdict] {e}")
        return None, [str(e)]


def stream_detailed_verdict(digest, cancel_token=None):
    """Yields deterministic text immediately (no LLM latency, and it's
    already fully correct so there's nothing to gain by faking a typing
    effect on it). Every LLM-backed piece (per-source interpretation,
    executive summary framing, closing recommendation) streams live,
    token-by-token as Ollama generates it — not as one block after a
    blocking wait.

    cancel_token (optional): checked between sections/sources so that once
    the caller aborts (e.g. the client disconnected), remaining LLM calls
    are skipped entirely rather than run to completion and discarded —
    each individual LLM call also stops early on its own via the same
    token, since it's threaded down into every _llm_snippet*/_ollama_collect
    call.

    Fault isolation: each LLM-backed piece is wrapped so that if it breaks
    partway through, the exception is logged and generation moves on to the
    next piece rather than truncating the whole report. A structural error
    (outside any single piece) still yields an explicit error marker."""
    def _cancelled():
        return bool(cancel_token and cancel_token.cancelled.is_set())

    try:
        checklist = _compute_source_checklist(digest)
        verdict = digest.get("verdict") or ""
        score = _fmt_scalar(digest.get("score", ""))
        consensus = digest.get("consensus_ratio", "")
        triggered_by = digest.get("triggered_by") or []
        recommendation_field = digest.get("recommendation", "")

        corro_result = _safe_call(_render_corroboration, digest, cancel_token,
                                   fallback="Corroboration Assessment could not be generated due to an internal error; check server logs.",
                                   label="_render_corroboration")
        corro_text, overlaps = corro_result if isinstance(corro_result, tuple) else (corro_result, {})
        if _cancelled():
            return

        yield "# Executive Summary\n"
        yield (
            f"The indicator `{digest.get('indicator', '')}` carries a verdict of {verdict} with a "
            f"score of {score}. The consensus_ratio is {consensus}, with triggered_by consisting of "
            f"{', '.join(triggered_by) if triggered_by else 'no sources'}. The JSON's own "
            f"recommendation is: {recommendation_field}.\n\n"
        )
        highlights = _safe_call(_render_executive_summary_highlights, digest, overlaps,
                                 fallback="", label="_render_executive_summary_highlights")
        if highlights:
            yield highlights + "\n\n"
        try:
            for chunk in _executive_summary_synthesis_stream(digest, overlaps, cancel_token=cancel_token):
                yield chunk
            yield "\n\n"
        except Exception:
            import traceback
            print(f"[_executive_summary_synthesis_stream] {traceback.format_exc()}")
        if _cancelled():
            return

        yield "# Source Findings\n"
        source_interpretations = {}
        for item in checklist:
            if _cancelled():
                return
            source, label = item["source"], item["findings_label"]
            try:
                key = _resolve_section_key(source, digest)
                data = digest.get(key)
                detail_lines = _render_source_detail_lines(source, digest)

                yield f"## {source}\n**Findings:** {label}.\n"
                if detail_lines:
                    yield "\n".join(f"- {line}" for line in detail_lines) + "\n"
                else:
                    yield f"No further detail is available in {key} beyond the findings label.\n"

                if detail_lines:
                    interpretation_parts = []
                    for chunk in _source_evidence_snippet_stream(source, label, key, data, cancel_token=cancel_token):
                        interpretation_parts.append(chunk)
                        yield chunk
                    interpretation = "".join(interpretation_parts).strip()
                    if interpretation:
                        source_interpretations[source] = interpretation
                    yield "\n"
                yield "\n"
            except Exception:
                import traceback
                print(f"[stream_detailed_verdict:{source}] {traceback.format_exc()}")
                yield f"## {source}\n**Findings:** {label}.\n(Additional detail could not be rendered for this source.)\n\n"

        if _cancelled():
            return

        yield "# Pivot Analysis\n"
        yield _safe_call(_render_pivot_analysis, digest,
                          fallback="Pivot Analysis could not be generated due to an internal error; check server logs.",
                          label="_render_pivot_analysis") + "\n\n"

        yield "# Corroboration Assessment\n"
        yield corro_text + "\n\n"

        if _cancelled():
            return

        yield "# Final Assessment\n"
        deterministic_tier = _classify_verdict(verdict)
        # Note: unlike other streamed pieces, the header itself now depends on
        # the AI's full response (its own tier), so it can't be yielded before
        # the call completes the way a purely deterministic header could be.
        ai_final_tier, conclusion_sentence = _safe_call(
            _build_ai_final_assessment, digest, overlaps, cancel_token, source_interpretations,
            fallback=(deterministic_tier, f"Based on the evidence discussed above, this indicator presents as {deterministic_tier.lower()}."),
            label="_build_ai_final_assessment",
        )
        if _cancelled():
            return
        yield f"**Overall Assessment: {ai_final_tier}**\n\n"
        yield (
            f"{conclusion_sentence} For reference, the JSON's own fields report: verdict "
            f"\"{verdict}\", score {score}, consensus_ratio {consensus}, and triggered_by "
            f"consisting of {', '.join(triggered_by) if triggered_by else 'no sources'}.\n\n"
        )
        try:
            for chunk in _closing_recommendation_stream(digest, overlaps, ai_final_tier, cancel_token=cancel_token):
                yield chunk
        except Exception:
            import traceback
            print(f"[_closing_recommendation_stream] {traceback.format_exc()}")
            yield _closing_recommendation_prompt(digest, overlaps, ai_final_tier)[1]  # fallback text
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[stream_detailed_verdict] {tb}")
        # Surface the failure explicitly instead of letting the stream just
        # stop — a client can check for this marker to know the report is
        # incomplete, rather than treating a truncated stream as finished.
        yield f"\n\n[REPORT_GENERATION_ERROR] {type(e).__name__}: {e}"
        return