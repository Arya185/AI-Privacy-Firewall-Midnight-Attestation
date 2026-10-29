"""Figures for the project report.

Figure 2.1: system architecture and data flow (drawn from the actual code paths).
Figure 6.1: tests per suite, parsed from docs/evidence/01_pytest.txt.

    python make_figures.py        # writes figures/ next to this file
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, Rectangle  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
EVIDENCE = REPO / "docs" / "evidence"
OUT = HERE / "figures"

plt.rcParams.update({"font.family": "serif", "font.serif": ["Liberation Serif", "DejaVu Serif"]})


def tests_per_suite() -> Counter:
    text = (EVIDENCE / "01_pytest.txt").read_text()
    # Parametrized ids may contain spaces, e.g. test_x[+1 415 555 0132].
    counts = Counter(m.group(1) for m in re.finditer(r"^tests/(test_\w+)\.py::.*? PASSED", text, re.M))
    summary = int(re.search(r"=+ (\d+) passed", text).group(1))
    assert sum(counts.values()) == summary, f"parsed {sum(counts.values())} != pytest summary {summary}"
    return counts


# --------------------------------------------------------------------------- Figure 2.1

def _box(ax, x, y, w, h, title, lines=(), fill="white", dashed=False, title_size=11):
    ax.add_patch(Rectangle((x, y), w, h, facecolor=fill, edgecolor="black",
                           linewidth=0.9, linestyle="--" if dashed else "-"))
    ax.text(x + w / 2, y + h - 0.16, title, ha="center", va="top", fontsize=title_size, weight="bold")
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.5 - i * 0.3, line, ha="center", va="top", fontsize=10)


def _arrow(ax, start, end, label=None, dashed=False, label_offset=(0.0, 0.1), rad=0.0):
    ax.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=11, linewidth=0.9,
                                 color="black", linestyle="--" if dashed else "-",
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=1, shrinkB=1))
    if label:
        mx, my = (start[0] + end[0]) / 2 + label_offset[0], (start[1] + end[1]) / 2 + label_offset[1]
        ax.text(mx, my, label, ha="center", va="bottom", fontsize=9, style="italic",
                bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.5})


def _lane(ax, x, y, w, h, label):
    ax.add_patch(Rectangle((x, y), w, h, facecolor="#f4f4f4", edgecolor="#777777", linewidth=0.7))
    ax.text(x + 0.12, y + h - 0.1, label, ha="left", va="top", fontsize=10, weight="bold", color="#333333")


def architecture() -> None:
    fig, ax = plt.subplots(figsize=(10, 9.2))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 9.2)
    ax.axis("off")

    # Lane A: Python privacy firewall
    _lane(ax, 0.1, 4.35, 9.8, 4.75, "A.  Python privacy firewall  (privacy_firewall/)")
    _box(ax, 0.3, 7.25, 1.55, 1.15, "AI agent", ["structured", "request"])
    _box(ax, 2.2, 6.85, 2.6, 1.95, "PrivacyFirewallMiddleware",
         ["PolicyEngine: YAML, per-field,", "fail-closed (ALLOW / DENY /", "AGGREGATE_ONLY)",
          "DataMinimizer: raw | count,", "sum, avg (k = 3) | drop"], fill="#e8e8e8", title_size=10.5)
    _box(ax, 2.55, 5.0, 1.9, 1.05, "MockEmployeeDB", ["in-memory, 5 records", "(canaries in notes)"])
    _box(ax, 5.2, 7.25, 1.45, 1.15, "FakeLLM", ["model stand-in", "(demo.py)"])
    _box(ax, 7.0, 7.05, 1.55, 1.55, "OutputFirewall", ["canary tokens", "(verbatim, spaced,", "base64), PII scan"])
    _box(ax, 8.85, 7.25, 0.95, 1.15, "Caller", ["ALLOW or", "BLOCK"])
    _box(ax, 5.15, 4.5, 2.05, 1.6, "AuditLog", ["SHA-256 hash chain,", "7 length-framed fields,", "verify_chain()"])
    _box(ax, 7.5, 4.5, 2.3, 1.6, "MidnightBridge", ["Bytes32 decision hash", "(5 fields); private witness", "stays local; HMAC-SHA256", "signed batch"])

    _arrow(ax, (1.85, 7.82), (2.2, 7.82))
    _arrow(ax, (3.5, 6.05), (3.5, 6.85), "rows", label_offset=(0.32, -0.05))
    _arrow(ax, (4.8, 7.82), (5.2, 7.82), "minimized", label_offset=(0.0, 0.08))
    _arrow(ax, (6.65, 7.82), (7.0, 7.82))
    _arrow(ax, (8.55, 7.82), (8.85, 7.82))
    _arrow(ax, (4.6, 6.85), (5.6, 6.05), "every field decision", label_offset=(0.05, 0.02))
    _arrow(ax, (7.2, 5.32), (7.5, 5.32))

    # Lane B: standalone audit tools
    _lane(ax, 0.1, 0.1, 4.7, 4.0, "B.  Standalone audit tools  (firee/midnight-side/audit/)")
    _box(ax, 0.3, 2.6, 2.05, 1.0, "fake_audit_generator", ["synthetic JSONL log"], title_size=10.5)
    _box(ax, 2.6, 2.6, 2.0, 1.0, "hash_chain.py", ["SHA-256 chain", "-> root_hash.txt"])
    _box(ax, 0.3, 0.45, 2.05, 1.15, "sign.py", ["Ed25519 signature", "over root hash"])
    _box(ax, 2.6, 0.45, 2.0, 1.15, "verify.py", ["chain + signature:", "PASS; edited copy FAIL"])
    _arrow(ax, (2.35, 3.1), (2.6, 3.1))
    _arrow(ax, (3.1, 2.6), (1.6, 1.6), "root hash", label_offset=(-0.15, 0.0))
    _arrow(ax, (2.35, 1.02), (2.6, 1.02))

    # Lane C: Compact contracts, offline
    _lane(ax, 5.0, 0.1, 4.9, 4.0, "C.  Compact contracts  (compiled, executed locally)")
    _box(ax, 5.2, 2.6, 2.1, 1.0, "commit.compact", ["commit, get_latest"], fill="#e8e8e8")
    _box(ax, 7.6, 2.6, 2.1, 1.0, "policy_attestation", ["recordAttestation,", "isAttested"], fill="#e8e8e8")
    _box(ax, 5.2, 1.35, 4.5, 0.95, "simulate_contract.ts", ["Compact runtime 0.16.0, no network: 6/6 checks"])
    _box(ax, 5.2, 0.25, 4.5, 0.8, "Midnight Preview testnet: NOT deployed",
         ["no DUST registration, deployment or commit submitted"], dashed=True, title_size=10.5)
    _arrow(ax, (6.25, 2.6), (6.25, 2.3))
    _arrow(ax, (8.65, 2.6), (8.65, 2.3))
    _arrow(ax, (7.45, 1.35), (7.45, 1.05), dashed=True)

    # cross-lane data flows
    _arrow(ax, (8.65, 4.5), (8.65, 3.6), "attestation_batch.json (4 hashes)", label_offset=(-1.3, 0.08))
    _arrow(ax, (4.6, 3.1), (5.2, 3.1))
    ax.text(4.9, 3.2, "root_hash.txt", ha="center", va="bottom", fontsize=9, style="italic",
            bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.5})

    fig.tight_layout(pad=0.2)
    OUT.mkdir(exist_ok=True)
    fig.savefig(OUT / "fig2_1_architecture.png", dpi=220)
    fig.savefig(OUT / "fig2_1_architecture.svg")
    plt.close(fig)



# --------------------------------------------------------------------------- Figure 6.1

def test_distribution() -> int:
    counts = tests_per_suite()
    names = sorted(counts, key=lambda k: counts[k])
    fig, ax = plt.subplots(figsize=(6.0, 3.3))
    bars = ax.barh([f"{n}.py" for n in names], [counts[n] for n in names], color="#7a7a7a", edgecolor="black", linewidth=0.6)
    for b in bars:
        ax.text(b.get_width() + 0.8, b.get_y() + b.get_height() / 2, str(int(b.get_width())), va="center", fontsize=9)
    ax.set_xlabel("Passing tests (pytest, 2026-10-29)")
    ax.set_xlim(0, max(counts.values()) * 1.15)
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(axis="y", labelsize=9)
    ax.set_title(f"Total: {sum(counts.values())} tests, all passing", fontsize=10)
    fig.tight_layout()
    OUT.mkdir(exist_ok=True)
    fig.savefig(OUT / "fig6_1_tests_per_suite.png", dpi=220)
    plt.close(fig)
    return sum(counts.values())


def main() -> None:
    architecture()
    total = test_distribution()
    print(f"figures written to {OUT} (tests parsed from evidence: {total})")


if __name__ == "__main__":
    main()
