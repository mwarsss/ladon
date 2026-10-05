# Ladon demo video script (about 3 minutes; trim the 1:20–1:35 segment if over)

**Setup:** start the server (`python -m ladon.server`), open `http://127.0.0.1:8000/lab` in a 1920×1080 window at 100% zoom, close other tabs. Have your phone ready with a draft email to the lab's real inbox address. Do one full rehearsal first. Record each section separately and join them; record the whole thing twice.

**Story shape:** problem → before → trigger → aha → impact.

| Time | On screen | Say |
|---|---|---|
| 0:00–0:20 | Attack Lab, the "Meet Rudo" strip | "This is Rudo. She runs accounts at a haulage firm in Harare, and her AI assistant reads the inbox and pays the invoices. Business email compromise cost about three billion dollars last year. Now scammers don't need to fool Rudo — just her AI." |
| 0:20–0:35 | Fake CEO preset filled in; point at the sender address | "Here's the scam: the CEO, urgent, the supplier changed banks, pay today, and send the payroll. Look at the domain — kopje-logistlcs, an L instead of an I." |
| 0:35–1:20 | Choose **Real AI model**, press **Send to both assistants**; let both lanes stream | "The same email goes to two assistants running a real AI model. Left: no protection. Right: Ladon. … On the left, it pays the scammer eight thousand four hundred and fifty dollars. On the right — blocked. It even keeps trying: a 'verification' email, then the payroll. Blocked every time. And the real supplier invoice and the customer's reply still go through." |
| 1:20–1:35 | Hover the signal chips; point at one block reason | "Every block comes with the why: a lookalike domain, a spoofed name, pressure tactics — and the account came from an untrusted email." |
| 1:35–2:10 | Show the phone sending a scam to the real inbox; click **Refresh**; press **Run this email** | "That was a preset. Now a real email, from my phone, to a real inbox, right now. … It's arrived — screened on arrival by Agentboxd — and Ladon stops it on the right." |
| 2:10–2:30 | Lab: tick **hack the supplier list**, send the genuine email | "Some attacks never touch the email. Here someone swapped a supplier's bank account in Rudo's records. Left: the real invoice goes to the scammer. Right: blocked. Rudo signed her supplier list, and that account isn't covered by her signature." |
| 2:30–2:45 | Dashboard, Scenario D; the supplier's phone shows the code; type it; Approve | "Real bank changes are held. Ladon texts a code to the supplier's number on file, never one from the email. Rudo calls them, they read the code, and only then does the money move." |
| 2:45–2:55 | `evals/model_matrix.md` summary table | "We ran these scams against six real AI models. Some fell for them, some didn't, and it changed from scam to scam. With Ladon, the result didn't depend on the model." |
| 2:55–3:10 | Back to the lab; the scoreboard | "Your assistant can read anything. Ladon makes sure scammers can't make it pay them. Try to scam it yourself — the link's below." |

**Tips:** keep each verdict banner on screen for two seconds. If the live model is slow or refuses the scam, cut to the same run with the fully fooled assistant and say so ("this is the worst case: an assistant that obeys everything"). Add captions with the same lines if a voice-over is hard.
