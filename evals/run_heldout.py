"""Run the held-out adversarial set through Ladon. Usage: python -m evals.run_heldout [--write]"""
from __future__ import annotations
import sys
from pathlib import Path
from evals.cases import scenario_for
from evals.heldout import HELDOUT
from evals.run_eval import run_case, SHORT

OUT = Path(__file__).resolve().parent / "heldout_results.md"
ok = lambda exp, got: (got in ("block", "hold")) if exp == "stop" else got == exp


def evaluate():
    rows, atk, atk_ok, leg, leg_ok = [], 0, 0, 0, 0
    for case in HELDOUT:
        r = run_case(case, "protected")
        for o in r["outcomes"]:
            good = ok(o["expect"], o["got"])
            if o["label"] == "attack":
                atk += 1; atk_ok += good
            else:
                leg += 1; leg_ok += good
            rows.append((case, o, good))
    return rows, atk, atk_ok, leg, leg_ok


def main():
    rows, atk, atk_ok, leg, leg_ok = evaluate()
    lines = ["# Held-out adversarial results", "",
             "`python -m evals.run_heldout`. Cases are in `evals/heldout.py`; ideal outcomes were fixed before the first run.", "",
             f"- Attack actions stopped (blocked or held): **{atk_ok}/{atk}**",
             f"- Legitimate actions handled correctly: **{leg_ok}/{leg}**", "",
             "| ID | Case | Action | Label | Ideal | Got | OK |", "|---|---|---|---|---|---|---|"]
    for case, o, good in rows:
        lines.append(f"| {case['id']} | {case['title']} | {o['tool']} | {o['label']} | {o['expect']} | {o['got']} | {'yes' if good else '**NO**'} |")
    for rnd, pre in (("Round 1 (H/G, tuned against after the first run)", ("H", "G")), ("Round 2 (R, written after the round-1 fixes, never tuned)", ("R",))):
        sub = [(c, o, g) for c, o, g in rows if c["id"].startswith(pre)]
        a = [x for x in sub if x[1]["label"] == "attack"]; l = [x for x in sub if x[1]["label"] != "attack"]
        lines.insert(6, f"- {rnd}: attacks stopped **{sum(x[2] for x in a)}/{len(a)}**, legitimate handled **{sum(x[2] for x in l)}/{len(l)}**")
    print("\n".join(lines[:9]))
    for case, o, good in rows:
        if not good:
            print(f"MISS {case['id']} {o['tool']} ideal={o['expect']} got={o['got']} :: {o['reason'][:110]}")
    if "--write" in sys.argv:
        OUT.write_text("\n".join(lines) + "\n", encoding="utf-8"); print("wrote", OUT)


if __name__ == "__main__":
    main()
