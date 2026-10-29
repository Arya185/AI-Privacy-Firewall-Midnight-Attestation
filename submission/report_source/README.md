# Report source

Regenerates `../AI_Privacy_Firewall_Midnight_Attestation_Report.docx` and `.pdf`.

```bash
cd submission/report_source
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python make_figures.py      # figures/ (test counts parsed from docs/evidence/01_pytest.txt)
.venv/bin/python build_report.py      # ../AI_Privacy_Firewall_Midnight_Attestation_Report.docx
soffice --headless --convert-to pdf --outdir .. ../AI_Privacy_Firewall_Midnight_Attestation_Report.docx
```

- `make_figures.py`: Figure 2.1 (architecture, PNG + SVG) and Figure 6.1 (tests per suite).
- `build_report.py`: the report. Code excerpts are cut from the source files and evidence
  excerpts are quoted from `docs/evidence/` at build time.
- Placeholders (highlighted in the document): subject / mini-project name, roll number,
  faculty guide, month and year of submission.
