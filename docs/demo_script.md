# AgentWall demo video script (about 3 minutes)

Setup before recording: `python -m agentwall.server`, open http://127.0.0.1:8000 in a 1920×1080 browser window, zoom 100%, close other tabs. Run each scenario once beforehand so nothing is slow on camera. Speak over the screen; keep the cursor on what you're describing.

| Time | On screen | Say |
|---|---|---|
| 0:00–0:20 | Dashboard, Scenario A selected | "Businesses are letting AI assistants run their inbox and pay their invoices. That means a scammer doesn't need to fool a person anymore — just the AI. This is AgentWall: a fraud firewall for AI assistants." |
| 0:20–0:35 | Point at the fake CEO email in the timeline after starting A | "Here's a real-looking email from the CEO. Look closely at the domain: kopje-logistlcs — an L instead of an I. It says the supplier's bank details changed, pay today, and send the payroll for the auditors." |
| 0:35–1:00 | Run A in **Unprotected**; wait for the red banner and attacker panel | "Without protection, the assistant does exactly what it's told: $8,450 goes to the scammer and the payroll file leaves the company." |
| 1:00–1:35 | Switch to **Protected**, run B; point at the two BLOCKED cards and the green banner | "Same inbox, AgentWall on. The payment and the data leak are both blocked — and the real supplier invoice and the customer reply still go through. It stops the scam without stopping the work." |
| 1:35–1:55 | Scroll the scam report; then click the blocked send_email card and show the provenance panel | "Every block comes with a plain-language scam report: the lookalike domain, the spoofed name, the pressure tactics, and who to call to verify. And here's why it blocked: the payroll file is confidential, and this address first appeared inside the scam email." |
| 1:55–2:20 | Run D; approval banner appears; press Approve | "Not every bank change is a scam. When a known supplier changes accounts, AgentWall pauses the payment and asks a human to confirm it by phone — the single step that stops most invoice fraud." |
| 2:20–2:35 | Press Verify log, Simulate tamper, Verify again | "Every decision goes into a signed, hash-chained log. Edit one line, and verification catches it." |
| 2:35–2:50 | Show the evaluation table from the README | "We tested 17 attack scenarios against a fully compromised assistant: all 17 succeed without AgentWall; with it, every stoppable one is stopped, with zero false alarms on normal work — and we publish the three it misses." |
| 2:50–3:00 | Dashboard | "AgentWall: your assistant can read anything — but scammers can't make it pay them." |

Tips: record in one take per section and join them; keep each banner on screen for two seconds; if a voice-over is hard, add captions with the same lines.
