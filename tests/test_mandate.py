"""Signed payment mandates: only the owner's signature makes a supplier payable."""

import copy
import datetime

from ladon.environment import Environment
from ladon.gateway import Gateway
from ladon.mandate import sign_mandate
from ladon.policy import PolicyEngine
from evals.cases import CASES, scenario_for

INVOICE = next(c for c in CASES if c["id"] == "B01")


def pay(env, to="ACC-55210", amount=3200.0):
    gw = Gateway(env, mode="protected")
    gw.execute("read_inbox", {})
    for msg in env.inbox:
        gw.execute("read_email", {"id": msg.id})
    return gw.execute("make_payment", {"to": to, "amount": amount, "reference": "INV-402"})


def test_registered_supplier_is_paid_under_a_valid_mandate():
    env = Environment.from_scenario(scenario_for(INVOICE))
    assert env.mandate.verify()[0]
    decision = pay(env)
    assert decision.decision == "allow" and env.mandate.id in decision.reason


def test_account_added_after_signing_is_blocked():
    data = scenario_for(INVOICE)
    data["registry_tampering"] = [{"name": "Harare Fuel (new bank)", "account": "ACC-31337"}]
    env = Environment.from_scenario(data)
    assert env.get_payee("ACC-31337") is not None  # it IS on the list...
    decision = pay(env, to="ACC-31337")
    assert decision.decision == "block" and "signed payment mandate" in decision.reason  # ...but not signed


def test_edited_mandate_fails_verification_and_stops_all_payments():
    env = Environment.from_scenario(scenario_for(INVOICE))
    env.mandate = copy.deepcopy(env.mandate)
    env.mandate.payees.append({"name": "Scammer", "account": "ACC-31337", "max_auto_amount": None})
    assert not env.mandate.verify()[0]
    assert pay(env).decision == "block"


def test_expired_mandate_is_rejected():
    m = sign_mandate([{"name": "A", "account": "ACC-1"}], valid_days=1)
    later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)
    ok, reason = m.verify(now=later)
    assert not ok and "expired" in reason


def test_rule_is_what_stops_the_tampered_payee():
    """Without the mandate rule, a tampered supplier list would let the payment through."""
    data = scenario_for(INVOICE)
    data["registry_tampering"] = [{"name": "Harare Fuel (new bank)", "account": "ACC-31337"}]
    env = Environment.from_scenario(data)
    engine = PolicyEngine()
    engine.rules = [r for r in engine.rules if r["id"] != "block_payee_outside_signed_mandate"]
    gw = Gateway(env, mode="protected", policy_engine=engine)
    assert gw.execute("make_payment", {"to": "ACC-31337", "amount": 3200.0, "reference": "X"}).decision == "allow"
