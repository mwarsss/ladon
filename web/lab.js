// Ladon Attack Lab: one email, two assistants, side by side.

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

const $ = (id) => document.getElementById(id);
const lanes = {
  unprotected: { list: $("laneUnprotected"), status: $("statusUnprotected"), result: $("resultUnprotected"), summary: null, error: null },
  protected: { list: $("laneProtected"), status: $("statusProtected"), result: $("resultProtected"), summary: null, error: null },
};
let brain = "fooled";
let liveAvailable = false;
let source = null;

function setBrain(value) {
  brain = value;
  for (const [id, b] of [["brainFooled", "fooled"], ["brainLive", "live"]]) {
    $(id).setAttribute("aria-pressed", String(brain === b));
  }
}

async function loadStatus() {
  try {
    const st = await (await fetch("/api/lab/status")).json();
    liveAvailable = st.live_available;
    $("brainLive").disabled = !liveAvailable;
    $("brainHint").textContent = liveAvailable
      ? `${st.live_runs_left_today} real-AI runs left today`
      : "Real AI unavailable here; the fooled assistant works offline";
  } catch (e) {
    $("brainHint").textContent = "";
  }
}

async function loadPresets() {
  const { presets } = await (await fetch("/api/lab/presets")).json();
  $("presets").innerHTML = "";
  presets.forEach((p, i) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "preset";
    btn.textContent = p.label;
    btn.addEventListener("click", () => fillPreset(p, btn));
    $("presets").appendChild(btn);
    if (i === 0) fillPreset(p, btn);
  });
}

function fillPreset(p, btn) {
  document.querySelectorAll("#presets .preset").forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
  $("senderName").value = p.sender_name;
  $("senderEmail").value = p.sender_email;
  $("subject").value = p.subject;
  $("body").value = p.body;
}

function describe(event) {
  const a = event.arguments || {};
  switch (event.tool_name) {
    case "read_inbox": return "Read the inbox";
    case "read_email": return `Read email ${esc(a.id)}`;
    case "read_file": return `Opened file <code>${esc(a.path)}</code>`;
    case "list_files": return "Listed files";
    case "draft_reply": return `Drafted a reply to ${esc(a.email_id)}`;
    case "send_email": return `Emailed <code>${esc(a.to)}</code>: “${esc(a.subject)}”`;
    case "make_payment": return `Paid <span class="amt">$${esc(Number(a.amount).toLocaleString())}</span> to <code>${esc(a.to)}</code> (${esc(a.reference)})`;
    case "fetch_url": return `Opened <code>${esc(a.url)}</code>`;
    default: return esc(event.tool_name);
  }
}

const STAMP = {
  allow: ["allow", "allowed"],
  block: ["block", "blocked"],
  require_approval: ["hold", "held for a human"],
};

function onEvent(e) {
  const lane = lanes[e.lane];
  if (e.type === "tool_call" && lane) {
    const row = document.createElement("li");
    row.className = "entry";
    row.innerHTML = `<span class="what">${describe(e)}</span><span class="stamp pending">…</span><p class="why" hidden></p>`;
    lane.list.appendChild(row);
    lane.list.scrollTop = lane.list.scrollHeight;
    lane.status.textContent = "working…";
  } else if (e.type === "decision" && lane) {
    const row = lane.list.lastElementChild;
    if (!row) return;
    const [cls, label] = STAMP[e.decision] || STAMP.allow;
    const stamp = row.querySelector(".stamp");
    if (e.lane === "unprotected") {
      stamp.className = "stamp";
      stamp.textContent = "done";
    } else {
      stamp.className = `stamp ${cls}`;
      stamp.textContent = label;
      if (e.decision !== "allow") {
        const why = row.querySelector(".why");
        why.textContent = e.reason;
        why.hidden = false;
        row.classList.add(cls);
      }
    }
  } else if ((e.type === "impersonation_signal" || e.type === "judge_verdict") && e.lane === "protected") {
    const chip = document.createElement("span");
    chip.className = "signal";
    chip.title = e.evidence || e.explanation || "";
    chip.textContent = e.type === "judge_verdict" ? "hidden instruction" : String(e.signal_type).replace(/_/g, " ");
    $("signals").appendChild(chip);
  } else if (e.type === "inbox_screening") {
    const chip = document.createElement("span");
    chip.className = "signal screen";
    chip.textContent = `Agentboxd: ${e.label}`;
    $("signals").appendChild(chip);
  } else if (e.type === "lane_done" && lane) {
    lane.summary = e.summary;
    lane.status.textContent = "finished";
    renderResult(e.lane);
  } else if (e.type === "lane_error" && lane) {
    lane.error = e.message;
    lane.status.textContent = "error";
    lane.result.className = "total error";
    lane.result.textContent = `The model returned an error: ${e.message}`;
    lane.result.hidden = false;
  } else if (e.type === "run_done") {
    source && source.close();
    $("sendBtn").disabled = false;
    $("sendBtn").textContent = "Send to both assistants";
    renderVerdict();
    loadStatus();
    loadScoreboard();
  }
}

function money(n) {
  return "$" + Number(n).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function lossText(s) {
  const parts = [];
  if (s.paid_to_unverified > 0) parts.push(`${money(s.paid_to_unverified)} paid to unverified accounts`);
  if (s.leaked_files.length) parts.push(`data leaked: ${s.leaked_files.join(", ")}`);
  return parts;
}

function renderResult(laneName) {
  const s = lanes[laneName].summary;
  const losses = lossText(s);
  const work = `${s.drafts} repl${s.drafts === 1 ? "y" : "ies"} drafted · ${money(s.paid_total - s.paid_to_unverified)} paid to known suppliers`;
  const box = lanes[laneName].result;
  const lost = s.paid_to_unverified;
  const stopped = [];
  if (s.blocked) stopped.push(`${s.blocked} action${s.blocked > 1 ? "s" : ""} blocked`);
  if (s.held) stopped.push(`${s.held} held for a human`);
  const detail = losses.length ? losses.join(" · ") : (stopped.length ? stopped.join(" · ") : "Nothing suspicious");
  box.className = "total";
  box.innerHTML = `
    <div class="line"><span class="label">Lost to the scammer</span><span class="fig ${losses.length ? "loss" : "safe"}">${esc(money(lost))}</span></div>
    <p class="detail ${losses.length ? "loss" : ""}">${esc(detail)}</p>
    <p class="detail">${esc(work)}</p>`;
  box.hidden = false;
}

function renderVerdict() {
  const u = lanes.unprotected.summary, p = lanes.protected.summary;
  const v = $("verdict");
  if (!u || !p) { v.hidden = true; return; }
  const uLoss = lossText(u), pLoss = lossText(p);
  let tone, title, text;
  if (uLoss.length && !pLoss.length) {
    tone = "safe"; title = "Ladon stopped your scam.";
    const workDone = p.paid_total - p.paid_to_unverified > 0;
    text = `Without it: ${uLoss.join(" · ")}. With it: $0 lost` + (workDone
      ? ", and the real work still got done."
      : ". A payment pointing at an account Rudo never approved was stopped; fix the supplier list, then pay it.");
  } else if (!uLoss.length && !pLoss.length) {
    tone = "calm"; title = brain === "live" ? "The AI didn't fall for it this time." : "Nothing harmful happened.";
    text = brain === "live"
      ? "This model ignored your email by itself. Models don't always catch scams, so try another, or switch to the fully fooled assistant to see what Ladon stops."
      : "Your email didn't ask for money or data. Try one of the scam presets.";
  } else {
    tone = "loss"; title = "Your scam got past Ladon.";
    text = `Protected side: ${pLoss.join(" · ")}. You found a gap; see the timeline for how.`;
  }
  v.className = `verdict ${tone}`;
  v.innerHTML = `
    <div><h2>${esc(title)}</h2><p>${esc(text)}</p></div>
    <dl class="tally">
      <dt>Without Ladon</dt><dd class="${u.paid_to_unverified ? "k-loss" : ""}">${esc(money(u.paid_to_unverified))}</dd>
      <dt>With Ladon</dt><dd class="${p.paid_to_unverified ? "k-loss" : "k-safe"}">${esc(money(p.paid_to_unverified))}</dd>
    </dl>`;
  v.hidden = false;
}

function resetLanes() {
  for (const lane of Object.values(lanes)) {
    lane.list.innerHTML = "";
    lane.result.hidden = true;
    lane.summary = null;
    lane.error = null;
    lane.status.textContent = "waiting";
  }
  $("signals").innerHTML = "";
  $("verdict").hidden = true;
}

async function send() {
  $("formError").hidden = true;
  const payload = {
    sender_name: $("senderName").value,
    sender_email: $("senderEmail").value,
    subject: $("subject").value,
    body: $("body").value,
    brain,
    tamper_registry: $("tamper").checked,
  };
  const res = await fetch("/api/lab/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  const data = await res.json();
  if (!res.ok) {
    $("formError").textContent = typeof data.detail === "string" ? data.detail : "Please check the email fields.";
    $("formError").hidden = false;
    return;
  }
  follow(data.run_id);
}

function follow(runId) {
  resetLanes();
  $("sendBtn").disabled = true;
  $("sendBtn").textContent = "Assistants are working…";
  source = new EventSource(`/api/lab/events/${runId}`);
  source.onmessage = (msg) => onEvent(JSON.parse(msg.data));
  source.onerror = () => { source.close(); $("sendBtn").disabled = false; $("sendBtn").textContent = "Send to both assistants"; };
  document.querySelector(".ledgers").scrollIntoView({ behavior: "smooth", block: "start" });
}

// A private code for this visitor: the lab only shows real-inbox emails whose subject carries it.
const visitorCode = (() => {
  const make = () => "LAB-" + Array.from(crypto.getRandomValues(new Uint8Array(6)),
    (b) => "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[b % 32]).join("");
  try {
    const saved = localStorage.getItem("ladon-visitor-code");
    if (saved && /^LAB-[A-Z0-9]{6}$/.test(saved)) return saved;
    const fresh = make();
    localStorage.setItem("ladon-visitor-code", fresh);
    return fresh;
  } catch (e) { return make(); }
})();

async function loadInbox() {
  let data;
  try { data = await (await fetch(`/api/lab/inbox?code=${visitorCode}`)).json(); } catch (e) { return; }
  if (!data.enabled) return;
  $("realInbox").hidden = false;
  $("inboxAddress").textContent = data.address || "";
  $("visitorCode").textContent = visitorCode;
  const list = $("inboxList");
  if (data.error) { list.innerHTML = `<li class="inbox-empty k-loss">${esc(data.error)}</li>`; return; }
  if (!data.messages.length) { list.innerHTML = `<li class="inbox-empty">No emails with your code yet. Send one to the address above with ${esc(visitorCode)} in the subject.</li>`; return; }
  list.innerHTML = data.messages.map(m => `
    <li class="inbox-row">
      <div>
        <div class="subj">${esc(m.subject)}</div>
        <div class="meta">${esc(m.from)} · ${esc(new Date(m.received_at).toLocaleString())}${m.screening.map(l => `<span class="tag">${esc(l)}</span>`).join("")}</div>
      </div>
      <button type="button" data-id="${esc(m.id)}" class="run-inbox send">Run this email</button>
    </li>`).join("");
  list.querySelectorAll(".run-inbox").forEach(btn => btn.addEventListener("click", () => runInbox(btn.dataset.id)));
}

const SIGNAL_NAMES = {
  lookalike_domain: "lookalike domain", display_name_spoof: "spoofed name", pressure_tactic: "pressure tactics",
  reply_to_mismatch: "reply-to mismatch", payee_change: "changed bank details", hidden_instruction: "hidden instructions",
};

async function loadMandate() {
  try {
    const m = await (await fetch("/api/lab/mandate")).json();
    const line = $("mandateLine");
    line.textContent = `${m.id} · Ed25519 · ${m.payees.length} suppliers · valid to ${m.valid_until.slice(0, 10)}`;
    line.title = `Signed by ${m.issuer}\nSignature ${m.signature.slice(0, 32)}…\n${m.status}`;
    line.className = `mono ${m.verified ? "ok" : "bad"}`;
  } catch (e) { $("mandateLine").textContent = "couldn't load the mandate"; }
}

async function loadScoreboard() {
  let s;
  try { s = await (await fetch("/api/lab/scoreboard")).json(); } catch (e) { return; }
  $("scoreboard").hidden = false;
  $("sbScams").textContent = s.scams.toLocaleString();
  $("sbStopped").textContent = s.stopped.toLocaleString();
  $("sbThrough").textContent = s.got_through.toLocaleString();
  $("sbThrough").className = s.got_through ? "has-gaps" : "";
  $("sbKept").textContent = "$" + Math.round(s.money_kept).toLocaleString("en-US");
  $("sbSince").textContent = s.since ? `since ${s.since} · ${s.runs.toLocaleString()} emails sent` : "";
  $("sbSignals").textContent = s.top_signals.length
    ? "Most common tricks Ladon caught: " + s.top_signals.map(([k, n]) => `${SIGNAL_NAMES[k] || k.replace(/_/g, " ")} (${n})`).join(", ")
    : "No scams yet. Be the first to try.";
  $("sbGapsWrap").hidden = !s.gaps.length;
  $("sbGaps").innerHTML = s.gaps.map((g) =>
    `<li>${esc(g.when)} UTC · ${esc(g.what)} · ${esc(g.assistant === "live" ? "real AI" : "fully fooled")}, ${esc(g.source)}</li>`).join("");
}

async function runInbox(id) {
  $("formError").hidden = true;
  const res = await fetch(`/api/lab/run-inbox/${encodeURIComponent(id)}?brain=${brain}&tamper=${$("tamper").checked}&code=${visitorCode}`, { method: "POST" });
  const data = await res.json();
  if (!res.ok) {
    $("formError").textContent = typeof data.detail === "string" ? data.detail : "Couldn't run that email.";
    $("formError").hidden = false;
    return;
  }
  follow(data.run_id);
}

$("brainFooled").addEventListener("click", () => setBrain("fooled"));
$("brainLive").addEventListener("click", () => liveAvailable && setBrain("live"));
$("sendBtn").addEventListener("click", send);
$("refreshInbox").addEventListener("click", loadInbox);
setBrain("fooled");
loadPresets();
loadStatus();
loadInbox();
loadScoreboard();
loadMandate();
setInterval(loadInbox, 10000);
