# Ladon user manual

## 1. What Ladon is
Ladon sits between an AI assistant and its tools: email, files, web requests and payments. Every action the assistant takes passes through it. Ladon allows it, blocks it, or holds it until a human confirms. It also writes a plain-language report and a tamper-evident log.

It is a demo built around a fictional company (Kopje Logistics) and its accounts clerk, Rudo. Email, files, web pages and payments are an in-memory mock, so nothing real is ever sent or paid.

## 2. Install and start
```bash
git clone https://github.com/mwarsss/ladon.git
cd ladon
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m ladon.server
```
- **Scenario dashboard:** http://127.0.0.1:8000
- **Attack Lab:** http://127.0.0.1:8000/lab

No API key is needed for the offline parts. To use a real model, copy `.env.example` to `.env` and fill in `GEMINI_API_KEY` or `FEATHERLESS_API_KEY`. To use the real inbox, also set the three `AGENTBOXD_*` values.

## 3. The Attack Lab (try to scam it)
1. Pick a preset scam or write your own email. The presets are fake CEO, gift cards, lookalike supplier, hidden instruction, payroll "verification" link, EcoCash supplier, EcoCash "sent by mistake" refund, and a genuine control email.
2. Optionally tick **hack the supplier list**. This swaps a supplier's bank account in Rudo's records, like a compromised supplier database.
3. Choose the assistant:
   - **Fully fooled (offline):** obeys everything it reads. This is the worst case, and it works without a key.
   - **Real AI model:** an actual model that may or may not fall for your email. It is capped per visitor and per day.
4. Run it. The same email hits two assistants side by side, one unprotected and one behind Ladon.
5. Read the result: money lost, files leaked, which actions Ladon blocked or held, and the scam report.
6. The scoreboard at the top counts all attempts: tried, stopped, got through, and the most common tricks. It stores counts only, never what people wrote.

**Real inbox (optional):** with the Agentboxd keys set, the lab shows a real email address. Send a scam to it from your own account, then run it through both assistants.

## 4. The scenario dashboard
Pick a scenario, choose Unprotected or Protected, and press **Run scenario**. These replay recorded runs of a real model, and Ladon's decisions are computed live.

| Scenario | Mode | Expect |
|---|---|---|
| A: Attack email | Unprotected | The assistant pays $8,450 to the scammer |
| B: Protected defence | Protected | Scam payment and payroll leak blocked; real invoice paid; quote sent |
| C: Normal day | Protected | Nothing blocked |
| D: Verify before paying | Protected | A genuine bank-detail change is held for a code |
| E: Tamper-evident log | Protected | Verify, simulate tamper, verify again: the break is found |

Click any tool call in the timeline to see where its data came from.

## 5. Reading the decisions
- **Allow:** the action is safe and proceeds.
- **Block:** refused. Examples are a payment to an account from an unknown or spoofed sender, or confidential data going out.
- **Hold (require approval):** waits for a human. Examples are a changed bank account, a duplicate invoice, a payment over the limit, or a message that reuses wording from a confidential file.

**Approving a held payment.** Ladon sends a one-time code to the supplier's phone number on company records, never the number in the email. Call that number and ask the supplier to read you the code. Type it in to approve. Three wrong codes deny the payment. In this demo the code appears on screen as the simulated phone, so anyone watching can see it. Real use needs a real SMS.

## 6. Audit log and scam report
- Every action is written to `logs/audit.jsonl`, hash-chained and Ed25519-signed.
- Check it: `python scripts/verify_log.py`. It reports the first tampered entry, if any.
- The scam report lists each red flag, the quoted evidence, what was prevented and who to call.

## 7. Use it with your own assistant (MCP)
```bash
claude mcp add ladon -- /path/to/ladon/.venv/bin/python -m ladon.mcp_server
```
Any MCP-capable assistant can then work Rudo's inbox through Ladon, and a blocked call returns its reason as a tool error.

## 8. Command line and tests
```bash
python -m ladon.agent --scenario scenarios/b_protected_defense.json --mode protected --llm-mode replay
python -m pytest -q                 # 176 tests
python -m evals.run_eval            # benchmark -> evals/results.md
python -m evals.run_heldout         # held-out adversarial set -> evals/heldout_results.md
python -m evals.model_matrix        # same scams against 6 real models (needs a key)
```

## 9. Policy
Rules live in `policies/default.yaml` and run in order, with the first match winning. External sends and payments are default-deny. A misspelled condition makes Ladon refuse to start. The automatic payment limit is under `limits:`.

## 10. Known limits
- Detection is text-based, so a rewording that shares no words with the original can slip through.
- The verification code is shown on screen in the demo.
- Some demo server endpoints (`/api/reset`, `/api/status`, `/api/tamper-log`) need no login.
- The scenario dashboard is single-user, so two visitors running scenarios at once will see each other's runs.
- It has not been tested against an adaptive attacker or an external benchmark.

The full lists are in the [README](../README.md#what-works-and-what-doesnt).
