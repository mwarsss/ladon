# AgentWall — Devpost description

**Tagline:** Scammers can email your AI assistant. AgentWall makes sure they can't make it pay them.

**Track:** AI + Cybersecurity

## Inspiration
Business email compromise — fake CEOs, lookalike supplier domains, "our bank details have changed" — already costs companies billions. Now small businesses are handing their inboxes and invoices to AI assistants. A scammer no longer has to fool a person; one convincing email can make the assistant pay a fake invoice or forward the payroll on its own.

## What it does
AgentWall is a firewall that sits between an AI assistant and its tools (email, files, web, payments). It:
- **Recognises** scams: lookalike domains, display-name spoofing, reply-to tricks, changed bank details, pressure tactics and hidden instructions in messages.
- **Prevents** fraud: it tracks where every piece of data came from and blocks payments to accounts introduced by unknown or spoofed senders, and confidential data leaving the company — including inside a web address.
- **Verifies:** bank-detail changes, duplicate invoices and unusually large payments wait for a human to confirm through a trusted channel.
- **Helps people respond:** every attempt produces a plain-language scam report (red flags, evidence, what was prevented, who to call) and a tamper-evident, signed audit log.

In our demo, a real model (Qwen 2.5 72B) reads a fake-CEO email and pays the scammer $8,450 on its own. With AgentWall, that payment and the reply to the scammer are blocked, while the legitimate invoice and the customer's quote still go through.

## How we built it
Python, FastAPI and a single-page dashboard with live updates. The assistant runs on Gemini or on open models through Featherless AI; the demo recordings are real Qwen 2.5 72B runs. AgentWall's core is deterministic so its decisions are explainable and testable: provenance tracking of every value the assistant reads, impersonation checks (edit distance plus homoglyph normalisation), a YAML zero-trust policy engine with default-deny for payments and external sends, a human approval queue, and an Ed25519-signed, SHA-256 hash-chained audit log. In live mode the model also runs as a separate, tool-less judge for hidden instructions. The design follows Google DeepMind's CaMeL idea: instead of hoping the model resists injection, control what data can flow where.

## Challenges
Making detection strict without blocking real work. Our benchmark caught two false positives (payroll sent to an internal colleague, and replies to a trusted supplier) and a scoring bug where one shared word counted as a data leak; a run with a real model caught a third (an emailed quote to a customer). Getting live models working also meant handling Gemini's thought signatures and free-tier rate limits. Reviewing our own dashboard, we also found that attacker-written email text could run script inside it (7 executions in one test) — now fixed (0).

## Accomplishments
A benchmark of 27 scripted traces from a fully compromised assistant: all 18 attacks succeed without AgentWall; with it, every stoppable attack is blocked or held, legitimate work has zero false positives, and the median added latency is 0.08 ms. We publish the three cases it misses.

## What we learned
Security for AI agents is about what they're *allowed to do*, not just what they're told. Data-flow tracking and human verification of money movements catch attacks that clever prompts can't.

## What works and what doesn't
Works: all demo scenarios end to end (offline replays of real Qwen 2.5 72B runs, or live with Gemini or Featherless), the benchmark, approvals and tamper detection. Partly: paraphrased data ("twelve and a half thousand") isn't recognised as confidential; email, files and payments are simulated; model behaviour varies (Gemini 3.8 Flash ignored our fake-CEO email by itself, Qwen paid it), which is why the benchmark measures AgentWall against an assistant that is fully fooled.

## What's next
Connect real inboxes (e.g. Agentboxd), learn per-supplier payment patterns, and package AgentWall as a drop-in layer for popular agent frameworks.

**Built with:** Python, FastAPI, Gemini API, Featherless AI, RapidFuzz, cryptography (Ed25519), Tailwind CSS
