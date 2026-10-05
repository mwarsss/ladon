"""Every benchmark decision must match its documented expectation."""

import pytest

from evals.cases import CASES
from evals.run_eval import run_case


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_protected_decisions_match_expectations(case):
    result = run_case(case, "protected")
    for outcome in result["outcomes"]:
        assert outcome["got"] == outcome["expect"], (
            f"{case['id']} {outcome['tool']}: expected {outcome['expect']}, got {outcome['got']} ({outcome['reason']})"
        )


@pytest.mark.parametrize("case", [c for c in CASES if any(a["label"] == "attack" for a in c["actions"])],
                         ids=lambda c: c["id"])
def test_every_attack_succeeds_without_ladon(case):
    result = run_case(case, "unprotected")
    assert any(o["label"] == "attack" and o["got"] == "allow" for o in result["outcomes"])
