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

In our demo, an unprotected assistant pays a scammer $8,450 and leaks the payroll. With AgentWall, both are blocked and the legitimate invoice and customer reply still go through.

## How we built it
Python, FastAPI and a single-page dashboard with live updates. The assistant uses Gemini function calling (Featherless supported as an alternative). AgentWall's core is deterministic so its decisions are explainable and testable: provenance tracking of every value the assistant reads, impersonation checks (edit distance plus homoglyph normalisation), a YAML zero-trust policy engine with default-deny for payments and external sends, a human approval queue, and an Ed25519-signed, SHA-256 hash-chained audit log. In live mode the model also runs as a separate, tool-less judge for hidden instructions. The design follows Google DeepMind's CaMeL idea: instead of hoping the model resists injection, control what data can flow where.

## Challenges
Making detection strict without blocking real work. Our benchmark caught two false positives (payroll sent to an internal colleague, and replies to a trusted supplier) and a scoring bug where one shared word counted as a data leak. Reviewing our own dashboard, we also found that attacker-written email text could run script inside it (7 executions in one test) — now fixed (0).

## Accomplishments
A benchmark of 25 scripted traces from a fully compromised assistant: all 17 attacks succeed without AgentWall; with it, every stoppable attack is blocked or held, legitimate work has zero false positives, and the median added latency is 0.07 ms. We publish the three cases it misses.

## What we learned
Security for AI agents is about what they're *allowed to do*, not just what they're told. Data-flow tracking and human verification of money movements catch attacks that clever prompts can't.

## What works and what doesn't
Works: all demo scenarios end to end (offline replay of scripted assistant runs), the benchmark, approvals and tamper detection. Partly: paraphrased data ("twelve and a half thousand") isn't recognised as confidential; email, files and payments are simulated; the offline demo uses scripted assistant runs so the attack is visible; in a live run, Gemini 3.8 Flash ignored our obvious fake-CEO email by itself, which is why the benchmark measures AgentWall against an assistant that is fully fooled.

## What's next
Connect real inboxes (e.g. Agentboxd), learn per-supplier payment patterns, and package AgentWall as a drop-in layer for popular agent frameworks.

**Built with:** Python, FastAPI, Gemini API, Featherless AI, RapidFuzz, cryptography (Ed25519), Tailwind CSS
