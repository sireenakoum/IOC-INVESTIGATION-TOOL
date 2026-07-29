"""
Word (.docx) export for a completed scan report.

Deliberately does NOT re-derive or re-prompt anything: everything rendered
here comes from the `entry` dict already saved to history (deterministic
fields) and from `entry["ai_summary"]` — the exact markdown text already
produced once by llm.ioc_llm.render_report()/stream_detailed_verdict() and
persisted via output.save_ai_summary(). That markdown has a fixed shape:

    # Executive Summary
    <prose>

    # Source Findings
    ## <source>
    **Findings:** <label>.
    - <deterministic bullet>
    - <deterministic bullet>
    <AI interpretive sentence>

    # Pivot Analysis
    <prose>

    # Corroboration Assessment
    <prose>

    # Final Assessment
    **Overall Assessment: <Malicious|Suspicious|Clean|...>**

    <AI conclusion sentence> For reference, the JSON's own fields report: ...

    <AI closing recommendation>

This module parses exactly that shape. If a future prompt change alters the
markdown, the parser degrades gracefully (unrecognized lines are still
rendered as plain paragraphs) rather than dropping content.
"""

import re
import io
from datetime import datetime

from docx import Document
from docx.shared import Pt, Inches, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

from sources.scoring import VERDICT_DISPLAY

# ── Colors — matches the app's existing severity palette (VerdictCard /
# error states use #ffb4ab for danger, #4edea3 for safe/positive; there is
# no distinct amber in use elsewhere in the app, so a standard amber is
# used for the middle tier). Adjust here if VerdictCard.jsx defines
# different exact hex values. ─────────────────────────────────────────────
COLOR_MALICIOUS = RGBColor(0xC6, 0x28, 0x28)
COLOR_MALICIOUS_BG = "FCE4E4"
COLOR_SUSPICIOUS = RGBColor(0xB8, 0x6A, 0x00)
COLOR_SUSPICIOUS_BG = "FCEFD8"
COLOR_CLEAN = RGBColor(0x1B, 0x8A, 0x5A)
COLOR_CLEAN_BG = "E1F5EC"
COLOR_NEUTRAL = RGBColor(0x5B, 0x6B, 0x73)
COLOR_NEUTRAL_BG = "E9EBEC"

COLOR_HEADING = RGBColor(0x1B, 0x1B, 0x1F)
COLOR_MUTED = RGBColor(0x5B, 0x6B, 0x73)
COLOR_RULE = "3C4A42"


def _tier_from_text(text):
    """Case-insensitive tier classification for coloring — mirrors
    llm.ioc_llm._classify_verdict's three tiers. Applied to whatever tier
    word the AI actually wrote in 'Overall Assessment: <tier>', not
    recomputed from the verdict, since the AI's own words are what's being
    displayed here."""
    t = (text or "").strip().lower()
    if "malicious" in t:
        return "malicious"
    if "suspicious" in t:
        return "suspicious"
    if "clean" in t:
        return "clean"
    return "neutral"


def _tier_from_verdict(verdict):
    """Same three-tier classification, applied to the JSON's own raw
    verdict field (high/medium/low/etc.) for the cover badge color —
    mirrors llm.ioc_llm._classify_verdict's mapping table exactly, kept
    local so this module doesn't need to import a private helper from
    another module for a purely cosmetic color choice."""
    v = (verdict or "").strip().lower()
    if v in ("high", "critical", "severe"):
        return "malicious"
    if v in ("medium", "moderate", "elevated", "mid"):
        return "suspicious"
    if v in ("low", "none", "clean", "benign", "negligible", "minimal"):
        return "clean"
    return "neutral"


_TIER_COLORS = {
    "malicious": (COLOR_MALICIOUS, COLOR_MALICIOUS_BG),
    "suspicious": (COLOR_SUSPICIOUS, COLOR_SUSPICIOUS_BG),
    "clean": (COLOR_CLEAN, COLOR_CLEAN_BG),
    "neutral": (COLOR_NEUTRAL, COLOR_NEUTRAL_BG),
}


# ── low-level oxml helpers (python-docx has no high-level API for these) ──

def _set_cell_background(cell, hex_color):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tc_pr.append(shd)


def _set_cell_borders(cell, hex_color=COLOR_RULE, sz=4):
    tc_pr = cell._tc.get_or_add_tcPr()
    borders = OxmlElement("w:tcBorders")
    for edge in ("top", "left", "bottom", "right"):
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), str(sz))
        el.set(qn("w:space"), "0")
        el.set(qn("w:color"), hex_color)
        borders.append(el)
    tc_pr.append(borders)


def _add_page_number_field(paragraph):
    run = paragraph.add_run()
    fld_begin = OxmlElement("w:fldChar")
    fld_begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = "PAGE"
    fld_sep = OxmlElement("w:fldChar")
    fld_sep.set(qn("w:fldCharType"), "separate")
    fld_end = OxmlElement("w:fldChar")
    fld_end.set(qn("w:fldCharType"), "end")
    run._r.append(fld_begin)
    run._r.append(instr)
    run._r.append(fld_sep)
    run._r.append(fld_end)


_INLINE_SPLIT = re.compile(r"(\*\*.+?\*\*|`.+?`)")


def _render_inline(paragraph, text, base_size=10.5, base_color=None):
    """Splits **bold** and `code` spans out of a line of the AI's markdown
    and adds them as separate runs so emphasis actually renders in Word
    instead of showing literal asterisks/backticks."""
    for part in _INLINE_SPLIT.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            run = paragraph.add_run(part[2:-2])
            run.bold = True
        elif part.startswith("`") and part.endswith("`"):
            run = paragraph.add_run(part[1:-1])
            run.font.name = "JetBrains Mono"
            run.font.size = Pt(base_size - 0.5)
        else:
            run = paragraph.add_run(part)
        run.font.size = Pt(base_size)
        if base_color is not None:
            run.font.color.rgb = base_color


def _is_fully_bold(line):
    return bool(re.fullmatch(r"\*\*.+\*\*", line.strip()))


def _add_body_paragraph(doc, line, style=None):
    p = doc.add_paragraph(style=style)
    _render_inline(p, line)
    p.paragraph_format.space_after = Pt(6)
    return p


def _add_overall_assessment_badge(doc, tier_text):
    """Renders '**Overall Assessment: <tier>**' as a shaded, colored box
    rather than a plain bold line, per the spec's request for a
    scannable-at-a-glance verdict."""
    tier_key = _tier_from_text(tier_text)
    color, bg = _TIER_COLORS[tier_key]

    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.LEFT
    table.autofit = False
    cell = table.rows[0].cells[0]
    table.columns[0].width = Inches(6.5)
    cell.width = Inches(6.5)
    _set_cell_background(cell, bg)
    _set_cell_borders(cell, hex_color=bg)
    cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(4)
    run = p.add_run(f"OVERALL ASSESSMENT: {tier_text.strip().upper()}")
    run.bold = True
    run.font.size = Pt(13)
    run.font.color.rgb = color

    spacer = doc.add_paragraph()
    spacer.paragraph_format.space_after = Pt(6)


def _split_top_sections(md_text):
    """Splits the ai_summary text on '# ' (H1) lines into
    [(title, body_text), ...], preserving order. '## ' lines are NOT
    matched here (re.MULTILINE + negative lookahead keeps them out)."""
    pattern = re.compile(r"^# (?!#)(.+)$", re.MULTILINE)
    matches = list(pattern.finditer(md_text))
    sections = []
    for i, m in enumerate(matches):
        title = m.group(1).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(md_text)
        sections.append((title, md_text[start:end].strip("\n")))
    return sections


def _split_sub_sections(body_text):
    """Splits a section body on '## ' (H2) lines — used for Source
    Findings, where each subsection is one source."""
    pattern = re.compile(r"^## (.+)$", re.MULTILINE)
    matches = list(pattern.finditer(body_text))
    if not matches:
        return [(None, body_text)]
    subsections = []
    lead = body_text[: matches[0].start()].strip("\n")
    if lead.strip():
        subsections.append((None, lead))
    for i, m in enumerate(matches):
        title = m.group(1).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body_text)
        subsections.append((title, body_text[start:end].strip("\n")))
    return subsections


def _render_section_body(doc, body_text):
    """Renders a block of markdown-ish lines: '- ' -> bullet list,
    fully-bold lines -> emphasized standalone paragraph, everything else
    -> normal paragraph with inline bold/code support. Blank lines just
    separate paragraphs (already handled by paragraph spacing)."""
    for raw_line in body_text.split("\n"):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("- "):
            p = doc.add_paragraph(style="List Bullet")
            _render_inline(p, line[2:].strip())
            p.paragraph_format.space_after = Pt(3)
        elif _is_fully_bold(line):
            p = doc.add_paragraph()
            _render_inline(p, line)
            p.paragraph_format.space_after = Pt(6)
        else:
            _add_body_paragraph(doc, line)


def _render_source_findings(doc, body_text):
    for source_name, sub_body in _split_sub_sections(body_text):
        if source_name is None:
            _render_section_body(doc, sub_body)
            continue
        doc.add_heading(source_name, level=3)
        _render_section_body(doc, sub_body)


def _render_final_assessment(doc, body_text):
    """Pulls the 'Overall Assessment: <tier>' line out for special badge
    treatment; renders the rest (conclusion sentence, JSON reference
    fields, closing recommendation) as normal paragraphs, in order."""
    lines = body_text.split("\n")
    remainder = []
    badge_rendered = False
    for line in lines:
        stripped = line.strip()
        m = re.fullmatch(r"\*\*Overall Assessment:\s*(.+?)\*\*", stripped)
        if m and not badge_rendered:
            _add_overall_assessment_badge(doc, m.group(1))
            badge_rendered = True
        else:
            remainder.append(line)
    _render_section_body(doc, "\n".join(remainder))


def _add_per_source_summary_table(doc, per_source):
    """Deterministic per-source summary table (findings label + tier) —
    the exact strings the scoring pipeline already produced, not
    paraphrased. Only sources with actual data are listed."""
    rows = [
        (name, s.get("findings_label") or "—", (s.get("findings_tier") or "—"))
        for name, s in (per_source or {}).items()
        if isinstance(s, dict) and s.get("has_data")
    ]
    if not rows:
        return

    doc.add_heading("Per-Source Summary", level=2)
    table = doc.add_table(rows=1 + len(rows), cols=3)
    table.style = "Light Grid Accent 1"
    table.autofit = False
    widths = [Inches(1.6), Inches(3.9), Inches(1.4)]
    headers = ["Source", "Findings", "Tier"]
    for i, cell in enumerate(table.rows[0].cells):
        cell.text = ""
        p = cell.paragraphs[0]
        run = p.add_run(headers[i])
        run.bold = True
        run.font.size = Pt(10)
        table.columns[i].width = widths[i]
        cell.width = widths[i]

    for r, (name, label, tier) in enumerate(rows, start=1):
        values = [name, label, tier]
        for c, val in enumerate(values):
            cell = table.rows[r].cells[c]
            cell.text = ""
            p = cell.paragraphs[0]
            run = p.add_run(str(val))
            run.font.size = Pt(10)
            table.columns[c].width = widths[c]
            cell.width = widths[c]

    doc.add_paragraph().paragraph_format.space_after = Pt(4)


def _add_vt_counts_table(doc, vt):
    if not vt:
        return
    doc.add_heading("VirusTotal Detection Counts", level=2)
    cols = ["Malicious", "Suspicious", "Harmless", "Undetected"]
    values = [vt.get("malicious", 0), vt.get("suspicious", 0), vt.get("harmless", 0), vt.get("undetected", 0)]

    table = doc.add_table(rows=2, cols=4)
    table.style = "Light Grid Accent 1"
    table.autofit = True
    for i, name in enumerate(cols):
        cell = table.rows[0].cells[i]
        run = cell.paragraphs[0].add_run(name)
        run.bold = True
        run.font.size = Pt(10)
    for i, val in enumerate(values):
        cell = table.rows[1].cells[i]
        run = cell.paragraphs[0].add_run(str(val))
        run.font.size = Pt(10)
    doc.add_paragraph().paragraph_format.space_after = Pt(4)


def _add_cover(doc, entry, indicator):
    title = doc.add_paragraph()
    title.paragraph_format.space_after = Pt(2)
    run = title.add_run("Threat Intelligence Report")
    run.bold = True
    run.font.size = Pt(22)
    run.font.color.rgb = COLOR_HEADING

    sub = doc.add_paragraph()
    sub.paragraph_format.space_after = Pt(16)
    srun = sub.add_run(indicator)
    srun.font.size = Pt(13)
    srun.font.name = "JetBrains Mono"
    srun.font.color.rgb = COLOR_MUTED

    verdict_raw = entry.get("verdict")
    verdict_display = VERDICT_DISPLAY.get(verdict_raw, verdict_raw or "Unknown")
    tier_key = _tier_from_verdict(verdict_raw)
    verdict_color, _ = _TIER_COLORS[tier_key]

    score = entry.get("score")
    score_str = f"{score:.1f}" if isinstance(score, (int, float)) else (str(score) if score is not None else "—")

    rows = [
        ("Indicator", indicator),
        ("Verdict", verdict_display),
        ("Score", score_str),
        ("Scan Timestamp", entry.get("timestamp") or "—"),
        ("Consensus Ratio", str(entry.get("consensus_ratio") or "—")),
    ]

    table = doc.add_table(rows=len(rows), cols=2)
    table.autofit = False
    widths = [Inches(1.8), Inches(4.7)]
    for r, (label, value) in enumerate(rows):
        label_cell, value_cell = table.rows[r].cells
        label_cell.width = widths[0]
        value_cell.width = widths[1]
        _set_cell_borders(label_cell)
        _set_cell_borders(value_cell)

        lp = label_cell.paragraphs[0]
        lrun = lp.add_run(label)
        lrun.bold = True
        lrun.font.size = Pt(10)
        lrun.font.color.rgb = COLOR_MUTED

        vp = value_cell.paragraphs[0]
        vrun = vp.add_run(str(value))
        vrun.font.size = Pt(11)
        if label == "Verdict":
            vrun.bold = True
            vrun.font.color.rgb = verdict_color

    doc.add_paragraph().paragraph_format.space_after = Pt(10)


def _add_footer(doc, indicator):
    section = doc.sections[0]
    footer = section.footer
    p = footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    run = p.add_run(f"{indicator}  •  Generated {generated}  •  Page ")
    run.font.size = Pt(8)
    run.font.color.rgb = COLOR_MUTED
    _add_page_number_field(p)
    tail = p.add_run("")
    tail.font.size = Pt(8)


def _configure_page(doc):
    section = doc.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)
    section.top_margin = Inches(0.9)
    section.bottom_margin = Inches(0.9)

    normal = doc.styles["Normal"]
    normal.font.name = "Georgia"
    normal.font.size = Pt(10.5)

    for level, size in ((1, 16), (2, 13), (3, 11.5)):
        try:
            h = doc.styles[f"Heading {level}"]
            h.font.name = "Calibri"
            h.font.size = Pt(size)
            h.font.color.rgb = COLOR_HEADING
            h.font.bold = True
        except KeyError:
            pass


def build_docx_report(entry, indicator):
    """Builds the Word report for an already-completed scan.

    entry: the dict returned by output.get_last_result() (deterministic
           fields + entry["ai_summary"], the already-generated markdown).
    indicator: the indicator string (entry doesn't always carry its own
               'indicator' key depending on the caller).

    Raises ValueError if entry has no ai_summary yet — callers should have
    already gated the export button/endpoint on generation being complete,
    this is a defensive backstop, not the primary check.

    Returns an io.BytesIO positioned at 0, ready to stream as a response.
    """
    ai_summary = entry.get("ai_summary")
    if not ai_summary:
        raise ValueError("No AI summary has been generated for this scan yet.")

    doc = Document()
    _configure_page(doc)
    _add_footer(doc, indicator)
    _add_cover(doc, entry, indicator)

    _add_per_source_summary_table(doc, entry.get("per_source"))
    _add_vt_counts_table(doc, entry.get("vt"))

    for title, body in _split_top_sections(ai_summary):
        doc.add_heading(title, level=1)
        if title.strip().lower() == "source findings":
            _render_source_findings(doc, body)
        elif title.strip().lower() == "final assessment":
            _render_final_assessment(doc, body)
        else:
            _render_section_body(doc, body)

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf