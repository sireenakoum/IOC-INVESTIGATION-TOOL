"""Standalone regression tests for the independent Final Assessment prompt
(llm/ioc_llm.py: _independent_assessment_prompt / _get_independent_assessment).

No test framework is configured in this repo (no pytest, no tests/ runner),
so this is a plain script: each test_* function raises AssertionError on
failure, main() runs them all and reports pass/fail. Run with:

    python tests/test_independent_assessment.py

Scope: these tests cover ONLY the independent-assessment prompt/backstop
change (removing per-source findings_label + numeric counts from what the
model sees, while keeping Python-side validation grounded in the real
label/tier data). They do not call Ollama — _get_independent_assessment's
LLM call is monkeypatched with a canned response, since a live model may
not be reachable in this environment.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import llm.ioc_llm as ioc_llm


def _make_digest():
    """Shape matches output.py's build_detailed_report_json/build_llm_report_digest
    output. Numeric values are chosen to be distinctive (unlikely to appear
    incidentally elsewhere in the prompt text) so their absence is a
    meaningful assertion, not a coincidence."""
    return {
        "indicator": "1.2.3.4",
        "verdict": "high",
        "score": 87,
        "consensus_ratio": "3/5",
        "triggered_by": ["VirusTotal", "AbuseIPDB"],
        "recommendation": "Block at perimeter.",
        "active_sources": ["VirusTotal", "OTX", "AbuseIPDB"],
        "inactive_sources": [],
        "per_source_summary": {
            "VirusTotal": {"findings_label": "High Risk Findings", "findings_tier": "high", "verdict": "malicious"},
            "OTX":        {"findings_label": "No Findings", "findings_tier": "none"},
            "AbuseIPDB":  {"findings_label": "Medium Risk Findings", "findings_tier": "medium"},
        },
        "vt_section": {
            "malicious": 15, "suspicious": 3, "harmless": 60, "undetected": 5,
            "malicious_vendors": [
                {"vendor": "Kaspersky", "name": "Trojan.Win32.Foo"},
                {"vendor": "ESET", "name": "Win32/Bar"},
            ],
            "tags": ["trojan", "c2"],
            "registrar": "NameCheap",
            "creation_date": "2020-01-01",
            "resolutions": [{"ip": "1.2.3.4", "hostname": "evil.example.com"}],
            "dns_records": ["A: 1.2.3.4"],
            "comments": [],
        },
        "otx_section": {
            "pulse_count": 41,
            "pulses_detail": [{"description": "Observed in phishing campaign targeting banks"}],
            "reputation_threat_score": 8,
            "reputation_threat_type": "malware",
            "passive_dns": [{"record_type": "A", "address": "1.2.3.4"}],
        },
        "abuse_section": {
            "abuse_score": 97,
            "total_reports": 137,
            "distinct_users": 42,
            "isp": "Bulletproof Hosting LLC",
            "country": "RU",
            "is_tor": False,
            "top_categories": [("SSH", 90)],
            "reports": [{"reported_at": "2024-01-01"}],
        },
    }


def _make_clean_digest():
    """Every source reports nothing, no pivot section, no overlaps — the
    'Clean' baseline used to test the no-evidence-at-all backstop."""
    return {
        "indicator": "9.9.9.9",
        "verdict": "clean",
        "score": 0,
        "consensus_ratio": "0/5",
        "triggered_by": [],
        "recommendation": "No action needed.",
        "active_sources": ["VirusTotal", "OTX"],
        "inactive_sources": [],
        "per_source_summary": {
            "VirusTotal": {"findings_label": "No Findings", "findings_tier": "none"},
            "OTX":        {"findings_label": "No Findings", "findings_tier": "none"},
        },
    }


def test_prompt_excludes_labels_and_counts():
    digest = _make_digest()
    overlaps = {}
    prompt = ioc_llm._independent_assessment_prompt(digest, overlaps)

    # No pre-digested verdict/label text of any kind.
    for leaked in ("High Risk Findings", "Medium Risk Findings", "No Findings", "sources_and_labels", "findings_label"):
        assert leaked not in prompt, f"prompt leaked a findings label/key: {leaked!r}"

    # No numeric counts/scores from any source's data.
    for count in ("15", "137", "97", "42", "90", "41", "8"):
        assert count not in prompt, f"prompt leaked a numeric count: {count!r}"

    # Qualitative/descriptive facts ARE present — this isn't just "delete
    # everything", the model still gets real evidence to reason from.
    for expected in ("Kaspersky", "Trojan.Win32.Foo", "trojan", "NameCheap",
                      "Bulletproof Hosting LLC", "phishing campaign targeting banks", "SSH"):
        assert expected in prompt, f"expected qualitative fact missing from prompt: {expected!r}"

    print("PASS: test_prompt_excludes_labels_and_counts")


def test_qualitative_source_facts_strips_counts_but_keeps_names():
    digest = _make_digest()
    vt_facts = ioc_llm._qualitative_source_facts("VirusTotal", digest)
    blob = " ".join(vt_facts)
    assert "15" not in blob and "vendor(s)" not in blob
    assert "Kaspersky" in blob and "Trojan.Win32.Foo" in blob

    # The count-inclusive renderer (used by Source Findings) is unaffected —
    # this change must not alter what readers see there.
    full_lines = ioc_llm._render_source_detail_lines("VirusTotal", digest)
    full_blob = " ".join(full_lines)
    assert "15 malicious" in full_blob, "Source Findings' own detail rendering regressed (counts should still be there)"

    print("PASS: test_qualitative_source_facts_strips_counts_but_keeps_names")


def test_backstop_still_discards_fabricated_denial_without_label_in_prompt():
    """The model denies VT found anything malicious, even though VT's real
    findings_label is 'High Risk Findings' — the backstop must still catch
    this using internally-known ground truth, even though that label was
    never shown to the model in the prompt."""
    digest = _make_digest()
    overlaps = {}
    canned_response = (
        "TIER: CLEAN\n"
        "REASONING: No sources found malicious activity regarding this indicator; "
        "all evidence appears benign."
    )
    with patch.object(ioc_llm, "_ollama_collect", return_value=canned_response):
        tier, reasoning = ioc_llm._get_independent_assessment(digest, overlaps)
    assert (tier, reasoning) == (None, None), f"expected backstop to discard fabricated denial, got {(tier, reasoning)!r}"
    print("PASS: test_backstop_still_discards_fabricated_denial_without_label_in_prompt")


def test_valid_response_passes_through():
    digest = _make_digest()
    overlaps = {}
    canned_response = (
        "TIER: MALICIOUS\n"
        "REASONING: VirusTotal vendors including Kaspersky flag this indicator as a trojan, "
        "and AbuseIPDB reports it hosted via a bulletproof provider with SSH-related abuse "
        "categories."
    )
    with patch.object(ioc_llm, "_ollama_collect", return_value=canned_response):
        tier, reasoning = ioc_llm._get_independent_assessment(digest, overlaps)
    assert tier == "Malicious", f"expected a valid non-contradicting response to pass through, got tier={tier!r}"
    assert reasoning
    print("PASS: test_valid_response_passes_through")


def test_backstop_discards_fabricated_risk_with_no_evidence():
    digest = _make_clean_digest()
    overlaps = {}
    canned_response = (
        "TIER: SUSPICIOUS\n"
        "REASONING: Some evidence suggests this indicator may be risky."
    )
    with patch.object(ioc_llm, "_ollama_collect", return_value=canned_response):
        tier, reasoning = ioc_llm._get_independent_assessment(digest, overlaps)
    assert (tier, reasoning) == (None, None), f"expected backstop to discard fabricated risk, got {(tier, reasoning)!r}"
    print("PASS: test_backstop_discards_fabricated_risk_with_no_evidence")


def main():
    tests = [
        test_prompt_excludes_labels_and_counts,
        test_qualitative_source_facts_strips_counts_but_keeps_names,
        test_backstop_still_discards_fabricated_denial_without_label_in_prompt,
        test_valid_response_passes_through,
        test_backstop_discards_fabricated_risk_with_no_evidence,
    ]
    failures = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failures += 1
            print(f"FAIL: {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
