"""Build the project report (DOCX) from the repository's own sources and evidence.

    python make_figures.py && python build_report.py
    soffice --headless --convert-to pdf --outdir .. ../AI_Privacy_Firewall_Midnight_Attestation_Report.docx

Code excerpts are cut from the source files and evidence excerpts are quoted
from docs/evidence/ at build time, so the report cannot drift from the code.
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_COLOR_INDEX
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

from make_figures import OUT as FIG_DIR, tests_per_suite

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
EVIDENCE = REPO / "docs" / "evidence"
OUTPUT = HERE.parent / "AI_Privacy_Firewall_Midnight_Attestation_Report.docx"

SERIF = "Times New Roman"   # rendered with metric-compatible Liberation Serif on Linux
MONO = "Courier New"
FOOTER_TEXT = "AI Privacy Firewall – Midnight Attestation  |  Project Report  |  Page "
BLACK = RGBColor(0, 0, 0)


# --------------------------------------------------------------------------- sources

def excerpt(rel_path: str, start: str, n_lines: int) -> str:
    lines = (REPO / rel_path).read_text().splitlines()
    i = next(k for k, line in enumerate(lines) if start in line)
    return textwrap.dedent("\n".join(lines[i:i + n_lines]))


def evidence_lines(name: str, pattern: str) -> list[str]:
    return [line for line in (EVIDENCE / name).read_text().splitlines() if re.search(pattern, line)]


# --------------------------------------------------------------------------- formatting helpers

def set_font(style_or_run, name: str, size: float | None = None, bold: bool | None = None):
    font = style_or_run.font
    font.name = name
    if size is not None:
        font.size = Pt(size)
    if bold is not None:
        font.bold = bold
    font.color.rgb = BLACK
    rpr = style_or_run.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    for attr in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
        rfonts.set(qn(attr), name)
    for attr in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
        rfonts.attrib.pop(qn(attr), None)


def configure_styles(doc: Document) -> None:
    normal = doc.styles["Normal"]
    set_font(normal, SERIF, 11.5)
    pf = normal.paragraph_format
    pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    pf.space_after = Pt(5)
    pf.line_spacing = 1.1

    h1 = doc.styles["Heading 1"]
    set_font(h1, SERIF, 14, bold=True)
    h1.font.all_caps = True
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(8)
    h1.paragraph_format.keep_with_next = True
    h1.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT

    h2 = doc.styles["Heading 2"]
    set_font(h2, SERIF, 12.5, bold=True)
    h2.paragraph_format.space_before = Pt(10)
    h2.paragraph_format.space_after = Pt(4)
    h2.paragraph_format.keep_with_next = True
    h2.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT

    for name in ("List Bullet", "List Number"):
        st = doc.styles[name]
        set_font(st, SERIF, 11.5)
        st.paragraph_format.space_after = Pt(2)
        st.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT


def add_page_field(paragraph) -> None:
    run = paragraph.add_run()
    for tag, text in (("begin", None), (None, "PAGE"), ("end", None)):
        if tag:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), tag)
        else:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = text
        run._r.append(el)
    set_font(run, SERIF, 10)


def shade(cell, fill: str) -> None:
    tcpr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tcpr.append(shd)


def keep_row_together(row, header: bool = False) -> None:
    trpr = row._tr.get_or_add_trPr()
    trpr.append(OxmlElement("w:cantSplit"))
    if header:
        trpr.append(OxmlElement("w:tblHeader"))


class Report:
    def __init__(self) -> None:
        self.doc = Document()
        configure_styles(self.doc)
        sec = self.doc.sections[0]
        sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
        for side in ("left_margin", "right_margin", "top_margin", "bottom_margin"):
            setattr(sec, side, Cm(2.54))
        sec.footer_distance = Cm(1.25)
        sec.different_first_page_header_footer = True   # cover page: no footer
        footer = sec.footer.paragraphs[0]
        footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = footer.add_run(FOOTER_TEXT)
        set_font(run, SERIF, 10)
        add_page_field(footer)
        self.table_no = 0

    # -- text ---------------------------------------------------------------
    def p(self, text: str = "", *, bold_lead: str | None = None, align=None, size=None,
          italic=False, space_after=None, keep_next=False):
        para = self.doc.add_paragraph()
        if bold_lead:
            r = para.add_run(bold_lead)
            r.bold = True
        self._runs(para, text, italic=italic, size=size)
        if align is not None:
            para.alignment = align
        if space_after is not None:
            para.paragraph_format.space_after = Pt(space_after)
        para.paragraph_format.keep_with_next = keep_next
        return para

    @staticmethod
    def _runs(para, text: str, italic=False, size=None, bold=False) -> None:
        # `code` spans -> monospace; [[placeholder]] -> highlighted
        for part in re.split(r"(`[^`]+`|\[\[[^\]]+\]\])", text):
            if not part:
                continue
            if part.startswith("`"):
                r = para.add_run(part[1:-1])
                set_font(r, MONO, (size or 12) - 1.5)
            elif part.startswith("[["):
                r = para.add_run("[" + part[2:-2] + "]")
                r.bold = True
                r.font.highlight_color = WD_COLOR_INDEX.YELLOW
            else:
                r = para.add_run(part)
            r.italic = italic or None
            if bold:
                r.bold = True
            if size and not part.startswith("`"):
                r.font.size = Pt(size)

    def h1(self, text: str, page_break: bool = False):
        para = self.doc.add_heading(text, level=1)
        para.paragraph_format.page_break_before = page_break
        return para

    def h2(self, text: str):
        return self.doc.add_heading(text, level=2)

    def bullets(self, items: list[str], style: str = "List Bullet") -> None:
        for item in items:
            para = self.doc.add_paragraph(style=style)
            if "::" in item:
                lead, rest = item.split("::", 1)
                self._runs(para, lead + ":", bold=True)
                self._runs(para, rest)
            else:
                self._runs(para, item)

    def steps(self, items: list[str]) -> None:
        for i, item in enumerate(items, 1):
            para = self.doc.add_paragraph()
            para.paragraph_format.left_indent = Cm(0.9)
            para.paragraph_format.first_line_indent = Cm(-0.6)
            para.paragraph_format.space_after = Pt(2)
            para.alignment = WD_ALIGN_PARAGRAPH.LEFT
            para.add_run(f"{i}. ").bold = True
            self._runs(para, item)

    def code(self, text: str, caption: str | None = None) -> None:
        table = self.doc.add_table(rows=1, cols=1)
        table.style = "Table Grid"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = table.rows[0].cells[0]
        shade(cell, "F2F2F2")
        keep_row_together(table.rows[0])
        cell.paragraphs[0].text = ""
        para = cell.paragraphs[0]
        para.alignment = WD_ALIGN_PARAGRAPH.LEFT
        para.paragraph_format.space_after = Pt(0)
        para.paragraph_format.line_spacing = 1.0
        for i, line in enumerate(text.splitlines()):
            r = para.add_run(line)
            set_font(r, MONO, 8.5)
            if i < len(text.splitlines()) - 1:
                r.add_break()
        if caption:
            self.caption(caption, before=4)
        else:
            self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    # -- tables & figures ---------------------------------------------------
    def table(self, header: list[str], rows: list[list[str]], widths_cm: list[float], caption: str,
              align_cols: dict[int, object] | None = None) -> None:
        self.table_no += 1
        cap = self.caption(f"Table {caption}", before=6, after=4)
        cap.paragraph_format.keep_with_next = True
        table = self.doc.add_table(rows=1, cols=len(header))
        table.style = "Table Grid"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        for i, text in enumerate(header):
            cell = table.rows[0].cells[i]
            cell.text = ""
            r = cell.paragraphs[0].add_run(text)
            r.bold = True
            r.font.size = Pt(10.5)
            cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            shade(cell, "D9D9D9")
        keep_row_together(table.rows[0], header=True)
        for row in rows:
            cells = table.add_row().cells
            keep_row_together(table.rows[-1])
            for i, text in enumerate(row):
                cells[i].text = ""
                para = cells[i].paragraphs[0]
                para.alignment = (align_cols or {}).get(i, WD_ALIGN_PARAGRAPH.LEFT)
                para.paragraph_format.space_after = Pt(0)
                self._runs(para, text, size=10.5)
        # LibreOffice lays out from <w:tblGrid>, so set the grid as well as each cell.
        table.autofit = False
        for col, w in zip(table._tbl.tblGrid.findall(qn("w:gridCol")), widths_cm):
            col.set(qn("w:w"), str(int(Cm(w).twips)))
        for row in table.rows:
            for i, w in enumerate(widths_cm):
                row.cells[i].width = Cm(w)
            for cell in row.cells:
                for para in cell.paragraphs:
                    para.paragraph_format.line_spacing = 1.05
                    para.paragraph_format.space_before = Pt(2)
                    para.paragraph_format.space_after = Pt(2)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    def figure(self, path: Path, width_cm: float, caption: str) -> None:
        para = self.doc.add_paragraph()
        para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        para.paragraph_format.keep_with_next = True
        para.paragraph_format.space_before = Pt(6)
        para.add_run().add_picture(str(path), width=Cm(width_cm))
        self.caption(caption, before=2, after=10)

    def caption(self, text: str, before: float = 2, after: float = 8):
        para = self.doc.add_paragraph()
        para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        para.paragraph_format.space_before = Pt(before)
        para.paragraph_format.space_after = Pt(after)
        label, _, rest = text.partition(":")
        r = para.add_run(label + (":" if rest else ""))
        r.bold = True
        r.font.size = Pt(10.5)
        if rest:
            r2 = para.add_run(rest)
            r2.italic = True
            r2.font.size = Pt(10.5)
        return para

    def save(self) -> None:
        self.doc.save(OUTPUT)


# --------------------------------------------------------------------------- content

def cover(rep: Report) -> None:
    c = WD_ALIGN_PARAGRAPH.CENTER
    rep.p("", space_after=70)
    rep.p("AI PRIVACY FIREWALL – MIDNIGHT ATTESTATION", align=c, size=22, space_after=10).runs[0].bold = True
    rep.p("Privacy-Aware Decision Logging and Blockchain-Based Audit Integrity", align=c, size=14,
          italic=True, space_after=60)
    rep.p("PROJECT REPORT", align=c, size=16, space_after=24).runs[0].bold = True
    rep.p("Submitted in partial fulfilment of the requirements for", align=c, size=12, space_after=2)
    rep.p("[[SUBJECT / MINI-PROJECT NAME]]", align=c, size=12, space_after=2)
    rep.p("in the degree of Bachelor of Engineering in Computer Engineering", align=c, size=12, space_after=48)
    rep.p("Submitted by", align=c, size=12, italic=True, space_after=4)
    rep.p("Arya Patel", align=c, size=14, space_after=2).runs[0].bold = True
    rep.p("Roll No.: [[ROLL NUMBER]]", align=c, size=12, space_after=30)
    rep.p("Under the guidance of", align=c, size=12, italic=True, space_after=4)
    rep.p("[[FACULTY GUIDE NAME]]", align=c, size=12, space_after=60)
    rep.p("Department of Computer Engineering", align=c, size=13, space_after=2).runs[0].bold = True
    rep.p("Shree L. R. Tiwari College of Engineering", align=c, size=13, space_after=24).runs[0].bold = True
    rep.p("[[MONTH YEAR OF SUBMISSION]]", align=c, size=12, space_after=0)


def section_problem(rep: Report) -> None:
    rep.h1("1. Problem Statement", page_break=True)
    rep.h2("1.1 Background")
    rep.p("AI agents are increasingly connected to business data. A common safeguard is an instruction in the "
          "model's system prompt asking it not to reveal sensitive values. That is guidance, not a control: an "
          "injected prompt or a misbehaving model can ignore it, and afterwards there is often no reliable record "
          "of what data the agent was allowed to see.")
    rep.h2("1.2 Problem Addressed")
    rep.p("This project addresses two linked problems:")
    rep.bullets([
        "Privacy:: an agent should receive only the fields it needs, in the least revealing form (raw value, "
        "aggregate, or nothing), and its responses should be checked for leaked secrets or personal data before "
        "they reach the user.",
        "Audit integrity:: every access decision should be recorded so that later tampering (editing, reordering "
        "or deleting entries) is detectable, and the decisions should be attestable to a third party without "
        "publishing the underlying data.",
    ])
    rep.h2("1.3 Objectives")
    rep.bullets([
        "Enforce field-level, fail-closed access policies outside the model, from a YAML policy file.",
        "Minimize data: release raw values, `{count, sum, avg}` aggregates with a k-anonymity floor, or nothing.",
        "Inspect model output for canary tokens and unauthorized personal data, blocking violations.",
        "Record every decision in a SHA-256 hash chain whose tampering is detectable.",
        "Reduce each decision to a 32-byte hash suitable for a Midnight Compact contract, keeping private details local.",
        "Compile the Compact contracts with the real toolchain and verify their logic in a local simulation.",
    ])


def section_description(rep: Report) -> None:
    rep.h1("2. Project Description")
    rep.p("The project has three parts, shown in Figure 2.1. Part A is the Python privacy firewall in "
          "`privacy_firewall/`. Part B is a set of standalone audit utilities in `firee/midnight-side/audit/` "
          "that hash-chain and digitally sign an audit log. Part C is two Midnight Compact contracts, compiled with "
          "the Compact toolchain and executed locally by a simulation script.")
    rep.h2("2.1 Workflow")
    rep.steps([
        "An AI agent sends a structured request (agent, resource, operation, fields, query). It never queries "
        "the data store itself.",
        "`PrivacyFirewallMiddleware` asks the `PolicyEngine` for a decision on each field and passes the rows of "
        "`MockEmployeeDB` through the `DataMinimizer`.",
        "The minimized payload goes to the model. In this project the model is `FakeLLM`, a deterministic "
        "stand-in defined in `demo.py`, so behaviour is reproducible and offline.",
        "The `OutputFirewall` scans the model's response for canary tokens and unauthorized personal data and "
        "returns ALLOW or BLOCK.",
        "Every field decision is appended to the `AuditLog` hash chain.",
        "The `MidnightBridge` turns each decision into a `Bytes32` hash and an HMAC-signed batch; "
        "`export_attestation_batch.py` writes that batch to a file.",
        "`simulate_contract.ts` loads the compiled contracts and records the batch's hashes with "
        "`recordAttestation`, then checks them with `isAttested`. It also commits the audit tools' root hash "
        "to `commit.compact`.",
    ])
    rep.figure(FIG_DIR / "fig2_1_architecture.png", 15.0,
               "Figure 2.1: AI Privacy Firewall system architecture and data flow")
    rep.h2("2.2 Local Simulation versus Blockchain Deployment")
    rep.p("All contract results in this report come from executing the compiled contracts locally with the "
          "Compact runtime. No transaction was submitted to any Midnight network. A wallet for the Midnight "
          "Preview test network was created, funded from the official faucet and synchronized, and a DUST "
          "registration transaction was built in a dry run, but DUST registration, contract deployment and the "
          "on-chain audit commitment were not carried out. There is therefore no deployed contract address.")


def section_technology(rep: Report) -> None:
    rep.h1("3. Technology Used")
    rep.table(["TECHNOLOGY", "DESCRIPTION"], [
        ["Python 3", "Language of the firewall, audit chain and bridge. Uses the standard library for hashing "
         "(`hashlib`), HMAC (`hmac`) and random tokens (`secrets`)."],
        ["PyYAML", "Reads the per-agent access policy (`policies/analytics_agent.yaml`)."],
        ["pytest", "Runs the 234 automated tests in `privacy_firewall/tests/`."],
        ["cryptography (Python)", "Provides Ed25519 signing and verification for the standalone audit tools "
         "(`audit/sign.py`, `audit/verify.py`)."],
        ["Midnight Compact", "Smart-contract language for Midnight. The toolchain (version 0.31.1) compiles each "
         "circuit into JavaScript plus zero-knowledge prover and verifier keys."],
        ["Compact runtime and compact-js", "JavaScript libraries (`compact-runtime` 0.16.0, `compact-js` 2.5.1) "
         "that execute compiled contracts; used by the offline simulation."],
        ["TypeScript, Node.js 22, tsx", "Language and runtime of the Midnight-side scripts (simulation, wallet, "
         "deployment pipeline); `tsc` performs the type check."],
        ["Midnight.js 4.1.1 and Wallet SDK", "Midnight's client libraries for wallets, transactions and contract "
         "calls. Used for wallet synchronization and the registration dry run; no transaction was submitted."],
        ["Midnight proof server 8.1.3", "Local service, run in a Podman container, that generates zero-knowledge "
         "proofs for live transactions. It was started and health-checked; it has not proved any submitted "
         "transaction."],
        ["GitHub Actions", "CI workflow (`.github/workflows/ci.yml`) that runs the tests and demo on Python "
         "3.10–3.12. It was not run as part of this report's verification."],
    ], [4.6, 11.3], "3.1: Technologies used in the project")
    rep.h2("3.1 Environment and Limitations")
    rep.p("All verification was performed on a single Fedora Linux 44 machine with Python 3.14.8, Node.js 22.23.4 "
          "and the Compact toolchain 0.31.1, versions chosen to match Midnight's published compatibility matrix. "
          "There is no server, database, web interface or deployed application: the firewall is a Python library "
          "with a command-line demo, its data source is an in-memory mock of five employee records, and the model "
          "is a deterministic stub rather than a real language model.")


def section_methods(rep: Report) -> None:
    rep.h1("4. Algorithm and Technical Methods")
    rep.h2("4.1 Policy Decision (Fail-Closed)")
    rep.p("For every requested field the `PolicyEngine` returns one of three decisions from the agent's YAML "
          "policy:")
    rep.steps([
        "If the agent has no policy, return DENY (\"failing closed\").",
        "If the field is not listed in the agent's policy, return DENY.",
        "Otherwise return the listed decision: ALLOW, AGGREGATE_ONLY or DENY.",
    ])
    rep.h2("4.2 Data Minimization")
    rep.p("ALLOW fields pass through unchanged; DENY fields are dropped. AGGREGATE_ONLY fields are reduced to "
          "aggregates. Minimum and maximum are deliberately not returned because they would reveal one person's "
          "exact value, and groups smaller than k = 3 are suppressed to a count only (`data_minimizer.py`, `_aggregate`).")
    rep.h2("4.3 Output Inspection")
    rep.p("The `OutputFirewall` blocks a response (decision BLOCK, output withheld) if it contains a canary "
          "token, a secret planted in the data that no agent is authorized to see, or an unmasked personal-data "
          "entity outside the agent's allowed fields. Canaries are generated with `secrets.token_hex` and are "
          "detected verbatim, with spaces or newlines inserted, and base64-encoded. The `PIIDetector` finds "
          "emails, phone numbers, US social security numbers, credit-card numbers (13–19 digits with a Luhn "
          "check), person names (a capitalized-name heuristic) and API keys or secrets (labels and high-entropy "
          "tokens).")
    rep.h2("4.4 Firewall Audit Hash Chain")
    rep.p("Each decision becomes an `AuditEntry` whose hash covers seven fields and the previous entry's hash, "
          "starting from a genesis value of 64 zeros. Each field is prefixed with its length, so a delimiter "
          "character inside a field cannot make two different entries produce the same hash input:")
    rep.code(excerpt("privacy_firewall/privacy_firewall/audit.py", "    parts = [entry_id, agent, field_name", 2))
    rep.p("`verify_chain()` recomputes every hash in order; any edited, reordered or deleted entry breaks the chain "
          "and verification returns false. This chain lives in memory and is not digitally signed.")
    rep.h2("4.5 Decision Hash and Attestation Batch")
    rep.p("For the contract, the `MidnightBridge` hashes five fields of each decision (agent, field, decision, "
          "reason, timestamp) with the same length framing, giving a 32-byte SHA-256 value. Agent, field names "
          "and reason stay in the private part of a local witness; only the hash is meant for the chain. The "
          "batch of hashes is signed with HMAC-SHA256 using a development key by default. HMAC proves the batch "
          "was produced by a holder of that key and has not changed; it is not a zero-knowledge proof.")
    rep.h2("4.6 Standalone Audit Signing and Tamper Detection")
    rep.p("The utilities in `firee/midnight-side/audit/` operate on a synthetic JSONL audit log, separate from the "
          "firewall's in-memory chain:")
    rep.steps([
        "`hash_chain.py`: for each record, h = SHA-256(canonical JSON of record + previous h), starting from 64 "
        "zeros; the final h is the root hash.",
        "`sign.py`: sign the root hash bytes with an Ed25519 private key.",
        "`verify.py`: rebuild the chain from the log, compare it with the expected root hash, and check the Ed25519 "
        "signature. Both checks must pass; otherwise the result is FAIL.",
    ])
    rep.h2("4.7 Contract Logic")
    rep.p("`policy_attestation.compact` stores attested decision hashes in a public map; `disclose()` marks only "
          "the hash as public. `commit.compact` stores the latest root hash and a commit counter.")
    rep.code(excerpt("privacy_firewall/midnight/policy_attestation.compact", "export ledger attested", 1) + "\n\n"
             + excerpt("privacy_firewall/midnight/policy_attestation.compact", "export circuit recordAttestation", 8))


def section_implementation(rep: Report) -> None:
    rep.h1("5. Implementation")
    rep.h2("5.1 Python Modules")
    rep.table(["FILE", "ROLE"], [
        ["`policy_engine.py`", "Loads the YAML policy; fail-closed per-field decisions"],
        ["`data_minimizer.py`", "Raw, aggregate (count, sum, avg; k = 3) or dropped values"],
        ["`pii_detector.py`", "Regex, Luhn and entropy-based detection; three masking strategies"],
        ["`canary.py`", "Generates and checks canary tokens"],
        ["`output_firewall.py`", "Canary and personal-data scan of model output; ALLOW or BLOCK"],
        ["`agent.py`", "`MockEmployeeDB`, `AIAgent`, `PrivacyFirewallMiddleware`"],
        ["`audit.py`", "SHA-256 hash-chained audit log and `verify_chain()`"],
        ["`midnight_bridge.py`", "Decision hashes, private witness, HMAC-signed batch, contract interface check"],
        ["`demo.py`", "Five-scenario command-line demonstration with `FakeLLM`"],
        ["`export_attestation_batch.py`", "Runs firewall requests and exports the signed batch"],
    ], [6.8, 9.1], "5.1: Main Python files (privacy_firewall/)")
    rep.h2("5.2 Contracts and Midnight-Side Scripts")
    rep.bullets([
        "`privacy_firewall/midnight/policy_attestation.compact`:: circuits `recordAttestation` and `isAttested`.",
        "`firee/midnight-side/contract/commit.compact`:: circuits `commit` and `get_latest`.",
        "`firee/midnight-side/scripts/simulate_contract.ts`:: executes both compiled contracts locally.",
        "`firee/midnight-side/scripts/`:: also contains the wallet, synchronization, DUST-registration, fee "
        "estimation, deployment and commit scripts prepared for an optional live deployment.",
    ])
    rep.h2("5.3 Integration Points")
    rep.p("The bridge parses `policy_attestation.compact` at start-up and refuses to run if the contract lacks the "
          "`recordAttestation` circuit, so the Python side and the contract interface cannot silently diverge. "
          "The exported batch file connects Part A to Part C, and `root_hash.txt` connects Part B to Part C "
          "(Figure 2.1). Because the batch contains the private witness, it is excluded from version control.")
    rep.h2("5.4 Running the Project")
    rep.code("cd privacy_firewall\n"
             "python -m pytest -q                       # 234 tests\n"
             "python demo.py --no-pause --no-color      # 5 scenarios\n"
             "PYTHONPATH=. python export_attestation_batch.py ../firee/midnight-side/build/attestation_batch.json\n\n"
             "cd ../firee/midnight-side\n"
             "npm run compile && npm run compile:policy # both contracts\n"
             "npm run typecheck\n"
             "npm run simulate                          # 6 checks, no network",
             caption="Listing 5.1: Verification commands (full setup in SUBMISSION.md)")


def section_results(rep: Report) -> None:
    total = sum(tests_per_suite().values())
    rep.h1("6. Results and Discussion")
    rep.p("All results below were obtained locally and offline on 29 October 2026 and re-run that day during "
          "preparation of this report with identical outcomes. Verbatim terminal output is stored in "
          "`docs/evidence/`.")
    rep.table(["CHECK", "RESULT", "SCOPE"], [
        ["Python test suite", f"{total} passed, 0 failed", "Local"],
        ["Command-line demo", "5 of 5 scenarios PASS", "Local"],
        ["Compile `commit.compact`", "Compiled; 2 circuits with prover/verifier keys", "Local"],
        ["Compile `policy_attestation.compact`", "Compiled; 2 circuits with prover/verifier keys", "Local"],
        ["TypeScript type check", "No errors", "Local"],
        ["Contract simulation", "6 of 6 checks pass (4 firewall decision hashes)", "Local, no network"],
        ["Audit verification, original log", "Chain PASS, signature PASS", "Local"],
        ["Audit verification, tampered copy", "Chain FAIL, signature FAIL (expected)", "Local"],
        ["Midnight Preview deployment", "Not performed", "—"],
    ], [6.6, 6.3, 3.0], "6.1: Verified results",
        align_cols={2: WD_ALIGN_PARAGRAPH.CENTER})
    rep.h2("6.1 Discussion")
    rep.bullets([
        f"{total} tests:: the largest suite (65 tests) targets prompt injection, privilege escalation and canary "
        "exfiltration and asserts that no path leaks a canary or raw personal data (Figure 6.1). Passing tests "
        "show the implemented rules behave as specified; they do not prove security against every attack.",
        "5 demo scenarios:: minimized aggregate access, a policy violation, a prompt-injection attempt blocked "
        "inbound and outbound, a canary leak blocked by the output firewall, and an audit export with a "
        "verified hash chain.",
        "Two compiled contracts:: compilation with the real toolchain confirms the contracts are valid Compact "
        "and produces the zero-knowledge keys a deployment would need. During verification the policy contract "
        "was found not to compile and was corrected (Section 7.3).",
        "6/6 simulation checks:: the contract logic stores and returns exactly the values given to it, including "
        "four hashes produced by the real firewall. This verifies the logic and the Python-to-contract data "
        "format, not network behaviour.",
        "Audit verification:: PASS on the original log and FAIL on a copy with one changed field show that the "
        "hash chain and Ed25519 signature detect modification.",
    ])
    rep.figure(FIG_DIR / "fig6_1_tests_per_suite.png", 11.0,
               f"Figure 6.1: Distribution of the {total} passing tests across the eight test suites")


def section_testing(rep: Report) -> None:
    rep.h1("7. Testing and Validation")
    rep.table(["CHECK", "PURPOSE", "COMMAND", "RESULT"], [
        ["Unit and security tests", "Policy, minimizer, detector, firewall, audit, bridge and injection behaviour",
         "`python -m pytest -q`", "234 passed"],
        ["Demo", "End-to-end scenarios", "`python demo.py --no-pause --no-color`", "5/5 PASS"],
        ["Contract compile", "Valid Compact; keys generated", "`npm run compile`, `npm run compile:policy`", "Pass"],
        ["Type check", "TypeScript scripts are type-correct", "`npm run typecheck`", "Pass"],
        ["Batch export", "Real decision hashes for the contract", "`export_attestation_batch.py`", "4 hashes"],
        ["Simulation", "Contract logic with real hashes", "`npm run simulate`", "6/6 pass"],
        ["Audit verify", "Integrity of log and signature", "`verify.py audit_log.jsonl <root> <sig>`", "PASS"],
        ["Tamper test", "Detection of a modified log", "`verify.py <edited copy> <root> <sig>`", "FAIL (expected)"],
    ], [2.9, 4.2, 6.2, 2.6], "7.1: Checks, commands and results",
        align_cols={3: WD_ALIGN_PARAGRAPH.CENTER})
    rep.h2("7.1 Audit Verification and Tamper Test")
    rep.p("The root hash of the synthetic audit log was signed with Ed25519 and verified (exit code 0). One field "
          "of one record was then changed in a copy of the log (policy P-001 to P-999) and verified against the "
          "same root hash and signature. Verification failed with exit code 1, the expected result:", keep_next=True)
    orig = evidence_lines("07_audit_sign_verify.txt", r"^(Chain integrity|Signature check|OVERALL)")
    rep.code("\n".join(["--- original log"] + orig[:3] + ["--- copy with one field changed"] + orig[3:6]),
             caption="Listing 7.1: Excerpt of docs/evidence/07_audit_sign_verify.txt")
    rep.h2("7.2 Firewall Hashes through the Policy-Attestation Contract")
    rep.p("`export_attestation_batch.py` ran two agent requests through the firewall, producing four decision "
          "hashes. The simulation recorded each with `recordAttestation`, confirmed `isAttested` is true for all "
          "four and false for a hash that was never recorded, and checked that the ledger holds exactly four "
          "entries. This was a local execution of the compiled contract, not an on-chain transaction.")
    sim = evidence_lines("06_simulate_contracts.txt", r"(PASS|FAIL|compact$|Simulation:)")
    rep.code("\n".join(sim), caption="Listing 7.2: Excerpt of docs/evidence/06_simulate_contracts.txt")
    rep.h2("7.3 Defects Found During Validation")
    rep.p("Compiling `policy_attestation.compact` with the real toolchain failed: the standard library was not "
          "imported and the key type `Opaque<\"Bytes32\">` is not supported. It was corrected to `Bytes<32>`, the "
          "matching parser in `midnight_bridge.py` was updated, and all 234 tests still pass. The Midnight runtime "
          "dependency was also realigned to Midnight's compatibility matrix (`compact-runtime` 0.16.0).")
    rep.p("Screenshots are not included; the evidence is captured terminal output. If screenshots are required, "
          "they can be taken of the commands in Listing 5.1.", italic=True)


def section_conclusion(rep: Report) -> None:
    rep.h1("8. Conclusion")
    rep.p("The project shows that privacy rules for an AI agent can be enforced outside the model: the agent "
          "receives only what its policy allows, in the least revealing form, and responses that leak canaries "
          "or unauthorized personal data are blocked. Every decision is recorded in a tamper-evident hash chain "
          "and reduced to a 32-byte hash that a Midnight Compact contract can attest without revealing the "
          "underlying data.")
    rep.p("These properties are verified by 234 automated tests, five demonstration scenarios, two contracts "
          "compiled with the real Compact toolchain, a local contract simulation using real firewall hashes, and "
          "an audit verification that accepts an untouched log and rejects a modified one. The guarantees are "
          "those of the implemented checks on a deterministic test setup; they are not a proof of security "
          "against all attacks, and the blockchain step has been demonstrated locally rather than on a live "
          "network.")


def section_limitations(rep: Report) -> None:
    rep.h1("9. Limitations and Future Scope")
    rep.h2("9.1 Limitations")
    rep.bullets([
        "Live Midnight Preview deployment, DUST registration and the on-chain audit commitment have not been "
        "completed; contract behaviour is shown by local simulation only.",
        "The attestation batch is signed with HMAC-SHA256 and a development key by default; it is not a "
        "zero-knowledge proof, and key management is not production-grade.",
        "The firewall's in-memory audit chain is not signed; Ed25519 signing is applied by the separate audit "
        "utilities to a synthetic log.",
        "The model is a deterministic stub and the data source is a five-record in-memory mock.",
        "Personal-data detection is rule-based (regular expressions, Luhn check, entropy) with limited recall.",
    ])
    rep.h2("9.2 Future Scope")
    rep.bullets([
        "Optional testnet deployment: register the funded wallet for DUST, deploy both contracts and call "
        "`recordAttestation` and `commit` from the batch exporter.",
        "Sign the firewall's own audit chain and manage signing keys securely instead of using development keys.",
        "Replace the HMAC batch signature with a zero-knowledge proof.",
        "Broaden security testing, for example against real language models and larger, more varied datasets.",
        "Optional higher-recall personal-data detection and streaming output inspection.",
    ])


def section_references(rep: Report) -> None:
    rep.h1("10. References")
    refs = [
        "Project repository documentation: `README.md`, `SUBMISSION.md`, `firee/midnight-side/README.md`, and "
        "verification output in `docs/evidence/`.",
        "Python Software Foundation, \"hashlib — Secure hashes and message digests,\" "
        "https://docs.python.org/3/library/hashlib.html",
        "Python Software Foundation, \"hmac — Keyed-Hashing for Message Authentication,\" "
        "https://docs.python.org/3/library/hmac.html",
        "Python Software Foundation, \"secrets — Generate secure random numbers,\" "
        "https://docs.python.org/3/library/secrets.html",
        "pytest documentation, https://docs.pytest.org/",
        "PyYAML documentation, https://pyyaml.org/wiki/PyYAMLDocumentation",
        "Python Cryptographic Authority, \"Ed25519 signing,\" "
        "https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/",
        "Midnight Network documentation, https://docs.midnight.network/",
        "Midnight Network, \"Release compatibility matrix,\" https://docs.midnight.network/relnotes/support-matrix",
        "Midnight Network, Compact toolchain releases, https://github.com/midnightntwrk/compact",
        "NIST, FIPS 180-4, \"Secure Hash Standard (SHS),\" https://csrc.nist.gov/pubs/fips/180-4/upd1/final",
        "H. Krawczyk, M. Bellare and R. Canetti, RFC 2104, \"HMAC: Keyed-Hashing for Message Authentication,\" "
        "https://www.rfc-editor.org/rfc/rfc2104",
        "S. Josefsson and I. Liusvaara, RFC 8032, \"Edwards-Curve Digital Signature Algorithm (EdDSA),\" "
        "https://www.rfc-editor.org/rfc/rfc8032",
    ]
    for i, ref in enumerate(refs, 1):
        para = rep.doc.add_paragraph()
        para.alignment = WD_ALIGN_PARAGRAPH.LEFT
        para.paragraph_format.left_indent = Cm(0.9)
        para.paragraph_format.first_line_indent = Cm(-0.9)
        para.paragraph_format.space_after = Pt(2)
        para.paragraph_format.line_spacing = 1.0
        para.add_run(f"[{i}]\t").font.size = Pt(10.5)
        rep._runs(para, ref, size=10.5)


def main() -> None:
    rep = Report()
    cover(rep)
    section_problem(rep)
    section_description(rep)
    section_technology(rep)
    section_methods(rep)
    section_implementation(rep)
    section_results(rep)
    section_testing(rep)
    section_conclusion(rep)
    section_limitations(rep)
    section_references(rep)
    rep.save()
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
