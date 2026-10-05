# AgentWall — Devpost description

**Tagline:** Scammers can email your AI assistant. AgentWall makes sure they can't make it pay them.

**Track:** AI + Cybersecurity

## Inspiration
Meet Rudo. She runs accounts at a 12-truck haulage firm in Harare, and her AI assistant reads the inbox, answers customers and pays approved supplier invoices. One morning an email arrives from "Tendai Moyo, CEO" at `kopje-logistlcs.example` (an *l* for the *i*): the supplier changed banks, pay today, and send the payroll for the auditors. Rudo never sees it. Her assistant does.

Business email compromise cost US victims $3.05 billion across 24,768 complaints in 2025, about $123,000 each, by FBI figures. Small businesses are now handing their inboxes and invoices to AI assistants, so a scammer no longer has to fool a person. Fooling the assistant is enough.

## What it does
AgentWall is a firewall between an AI assistant and its tools (email, files, web, payments). Every action passes through it.
- **Recognises** scams: lookalike domains, display-name spoofing, reply-to tricks, changed bank details, pressure tactics, payments moved to mobile money (EcoCash), fake "sent by mistake" refunds, and hidden instructions in messages.
- **Prevents** fraud: it tracks where every piece of data came from, and blocks payments to accounts introduced by unknown or spoofed senders and confidential data leaving the company, even inside a web address. It only pays accounts covered by the owner's **signed payment mandate**, so a hacked supplier list can't redirect money either.
- **Verifies:** bank-detail changes, duplicate invoices and large payments are held. AgentWall texts a one-time code to the supplier's number **from company records**, never from the email, and releases the payment only when the approver types the code they got by calling that number.
- **Helps people respond:** every attempt produces a plain-language scam report and a tamper-evident, Ed25519-signed audit log.

**Try to scam it yourself.** In the **Attack Lab**, you write the scam email, or send one from your phone to a real inbox. The same email lands in two copies of Rudo's inbox, one assistant unprotected and one behind AgentWall, and both stream their actions side by side. A public scoreboard counts every visitor's attempts and lists any that got through.

**Use it with your own assistant.** AgentWall also runs as an MCP server, so Claude Code, Claude Desktop or any MCP client can work through it. We tested it with a real Claude Code session.

## How we built it
Python and FastAPI, with a hand-built ledger-style interface streamed live over server-sent events. Assistants run on Gemini or on open models through Featherless AI. AgentWall's core is deterministic so every decision is explainable and testable:
- provenance tracking of every value the assistant reads (exact, fragment and paraphrase matching), following Google DeepMind's CaMeL idea of controlling data flow instead of hoping the model resists injection;
- impersonation checks (edit distance plus homoglyph normalisation, mobile-money patterns);
- a YAML zero-trust policy engine with default-deny for payments and external sends;
- an Ed25519-signed payment mandate, the same idea as the signed mandates in Google's AP2 and Mastercard Agent Pay, plus the check those systems lack: where the instruction came from;
- code-confirmed human approval, and an Ed25519-signed, SHA-256 hash-chained audit log;
- an isolated, tool-less AI judge for hidden instructions in live mode;
- an MCP server on the official Python SDK; and Agentboxd for the real inbox.

## Challenges
Being strict without blocking real work. The benchmark caught false positives (payroll sent to a colleague, replies to a trusted supplier, one shared word counted as a leak), and a real-model run caught one the benchmark missed (an emailed quote to a customer). Live models needed Gemini thought signatures handled and free-tier rate limits retried. Reviewing our own dashboard, we found attacker-written email text could run script in it (7 executions in one test), now 0. And a supplier list is only as trustworthy as whoever last edited it, which is why payments now need the owner's signature, not just a list entry.

## Accomplishments
- **Benchmark:** 30 scripted traces from a fully fooled assistant. All 21 attacks succeed without AgentWall. With it, every stoppable attack is blocked or held, with zero false positives on legitimate work and well under a millisecond added per action. We publish the 3 cases it misses.
- **Six real models:** We sent the Attack Lab's 7 scams to Llama 3.1 8B, Qwen3 32B, Llama 3.3 70B, Qwen 2.5 72B, gpt-oss 120B and Kimi K2. Without AgentWall, 5 of the 6 models fell for at least one scam (8 of 42 runs; up to $10,450 lost per model), and which scam worked changed from model to model. Only gpt-oss 120B refused all seven. With AgentWall, 0 of 42 got through, with no false alarms on the genuine email.
- **128 automated tests**, with every scenario and the Attack Lab tested in a headless browser.

## What we learned
Whether a model falls for a scam changes from model to model and scam to scam. Security for AI agents has to come from what they're *allowed to do*: data-flow tracking, signed mandates and verification through a known channel catch attacks that clever prompts can't.

## What works and what doesn't
**Works:** the Attack Lab (fully fooled or real model, plus the real inbox), all five dashboard scenarios offline and live, the scoreboard, signed mandates, code verification, MCP mode, the benchmark and the six-model comparison.

**Partly or not:** paraphrased data ("twelve and a half thousand") isn't recognised as confidential; email, files and payments are simulated; the verification text is shown on screen rather than sent by SMS; the demo keeps the mandate signing key on the server instead of the owner's device; three benchmark attacks are known misses (listed in the README); the scenario dashboard is single-user.

## What's next
Talk to finance teams about whether they would pay for this; connect real inboxes and accounting software; send verification codes by SMS (Africa's Talking or Twilio); and offer AgentWall as an MCP plugin for AI bookkeeping assistants.

**Built with:** Python, FastAPI, Gemini API, Featherless AI, Model Context Protocol, Agentboxd, RapidFuzz, cryptography (Ed25519), HTML/CSS/JavaScript
