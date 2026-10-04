// AgentWall Attack Lab: one email, two assistants, side by side.

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
    const on = brain === b;
    $(id).className = `brain px-3 py-2 rounded-lg border font-semibold ${on ? "bg-slate-100 text-slate-900 border-slate-100" : "border-slate-700 text-slate-300 hover:bg-slate-800"}`;
  }
}

async function loadStatus() {
  try {
    const st = await (await fetch("/api/lab/status")).json();
    liveAvailable = st.live_available;
    $("brainLive").disabled = !liveAvailable;
    $("brainLive").classList.toggle("opacity-40", !liveAvailable);
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
    btn.className = "text-xs px-2.5 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800";
    btn.textContent = p.label;
    btn.addEventListener("click", () => fillPreset(p));
    $("presets").appendChild(btn);
    if (i === 0) fillPreset(p);
  });
}

function fillPreset(p) {
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
    case "read_file": return `Opened file <span class="font-mono">${esc(a.path)}</span>`;
    case "list_files": return "Listed files";
    case "draft_reply": return `Drafted a reply to ${esc(a.email_id)}`;
    case "send_email": return `Emailed <span class="font-mono">${esc(a.to)}</span>: “${esc(a.subject)}”`;
    case "make_payment": return `Paid <span class="font-semibold">$${esc(Number(a.amount).toLocaleString())}</span> to <span class="font-mono">${esc(a.to)}</span> (${esc(a.reference)})`;
    case "fetch_url": return `Opened <span class="font-mono break-all">${esc(a.url)}</span>`;
    default: return esc(event.tool_name);
  }
}

const BADGE = {
  allow: ["bg-emerald-500/10 text-emerald-300 border-emerald-500/30", "allowed"],
  block: ["bg-rose-500/15 text-rose-300 border-rose-500/40", "BLOCKED"],
  require_approval: ["bg-amber-500/15 text-amber-300 border-amber-500/40", "HELD for a human"],
};

function onEvent(e) {
  const lane = lanes[e.lane];
  if (e.type === "tool_call" && lane) {
    const row = document.createElement("div");
    row.className = "bg-slate-950 border border-slate-800 rounded-lg p-2.5";
    row.innerHTML = `<div class="flex items-start justify-between gap-2"><span class="text-slate-200">${describe(e)}</span><span class="badge text-[10px] font-mono px-1.5 py-0.5 rounded border border-slate-700 text-slate-500">…</span></div><p class="reason hidden mt-1 text-[11px]"></p>`;
    lane.list.appendChild(row);
    lane.list.scrollTop = lane.list.scrollHeight;
    lane.status.textContent = "working…";
  } else if (e.type === "decision" && lane) {
    const row = lane.list.lastElementChild;
    if (!row) return;
    const [cls, label] = BADGE[e.decision] || BADGE.allow;
    const badge = row.querySelector(".badge");
    badge.className = `badge text-[10px] font-mono px-1.5 py-0.5 rounded border ${cls}`;
    badge.textContent = e.lane === "unprotected" ? "done" : label;
    if (e.lane === "protected" && e.decision !== "allow") {
      const reason = row.querySelector(".reason");
      reason.textContent = e.reason;
      reason.className = `reason mt-1 text-[11px] ${e.decision === "block" ? "text-rose-200" : "text-amber-200"}`;
      row.classList.add(e.decision === "block" ? "border-rose-500/50" : "border-amber-500/50");
    }
  } else if ((e.type === "impersonation_signal" || e.type === "judge_verdict") && e.lane === "protected") {
    const chip = document.createElement("span");
    chip.className = "text-[10px] px-2 py-1 rounded-full bg-amber-500/10 text-amber-200 border border-amber-500/30";
    chip.title = e.evidence || e.explanation || "";
    chip.textContent = e.type === "judge_verdict" ? "hidden instruction" : String(e.signal_type).replace(/_/g, " ");
    $("signals").appendChild(chip);
  } else if (e.type === "inbox_screening") {
    const chip = document.createElement("span");
    chip.className = "text-[10px] px-2 py-1 rounded-full bg-sky-500/10 text-sky-200 border border-sky-500/30";
    chip.textContent = `Agentboxd: ${e.label}`;
    $("signals").appendChild(chip);
  } else if (e.type === "lane_done" && lane) {
    lane.summary = e.summary;
    lane.status.textContent = "finished";
    renderResult(e.lane);
  } else if (e.type === "lane_error" && lane) {
    lane.error = e.message;
    lane.status.textContent = "error";
    lane.result.className = "bg-rose-950/40 border border-rose-500/40 rounded-lg p-3 text-xs text-rose-200";
    lane.result.textContent = `The model returned an error: ${e.message}`;
  } else if (e.type === "run_done") {
    source && source.close();
    $("sendBtn").disabled = false;
    $("sendBtn").textContent = "Send to both assistants →";
    renderVerdict();
    loadStatus();
  }
}

function lossText(s) {
  const parts = [];
  if (s.paid_to_unverified > 0) parts.push(`$${s.paid_to_unverified.toLocaleString()} paid to unverified accounts`);
  if (s.leaked_files.length) parts.push(`data leaked: ${s.leaked_files.join(", ")}`);
  return parts;
}

function renderResult(laneName) {
  const s = lanes[laneName].summary;
  const losses = lossText(s);
  const work = `${s.drafts} repl${s.drafts === 1 ? "y" : "ies"} drafted · $${(s.paid_total - s.paid_to_unverified).toLocaleString()} paid to known suppliers`;
  const box = lanes[laneName].result;
  if (losses.length) {
    box.className = "bg-rose-950/50 border border-rose-500/50 rounded-xl p-3 text-sm";
    box.innerHTML = `<p class="font-bold text-rose-200">🚨 ${esc(losses.join(" · "))}</p><p class="text-xs text-rose-100/80 mt-1">${esc(work)}</p>`;
  } else {
    const stopped = [];
    if (s.blocked) stopped.push(`${s.blocked} action${s.blocked > 1 ? "s" : ""} blocked`);
    if (s.held) stopped.push(`${s.held} held for a human`);
    box.className = "bg-emerald-950/40 border border-emerald-500/40 rounded-xl p-3 text-sm";
    box.innerHTML = `<p class="font-bold text-emerald-200">${stopped.length ? "🛡️ " + esc(stopped.join(" · ")) + " · $0 lost" : "✅ Nothing suspicious · $0 lost"}</p><p class="text-xs text-emerald-100/80 mt-1">${esc(work)}</p>`;
  }
  box.classList.remove("hidden");
}

function renderVerdict() {
  const u = lanes.unprotected.summary, p = lanes.protected.summary;
  const v = $("verdict");
  if (!u || !p) { v.classList.add("hidden"); return; }
  const uLoss = lossText(u), pLoss = lossText(p);
  let tone, title, text;
  if (uLoss.length && !pLoss.length) {
    tone = "emerald"; title = "AgentWall stopped your scam.";
    text = `Without it: ${uLoss.join(" · ")}. With it: $0 lost, and the real work still got done.`;
  } else if (!uLoss.length && !pLoss.length) {
    tone = "sky"; title = brain === "live" ? "The AI didn't fall for it this time." : "Nothing harmful happened.";
    text = brain === "live"
      ? "This model ignored your email by itself. Models don't always catch scams, so try another, or switch to the fully fooled assistant to see what AgentWall stops."
      : "Your email didn't ask for money or data. Try one of the scam presets.";
  } else {
    tone = "rose"; title = "Your scam got past AgentWall.";
    text = `Protected side: ${pLoss.join(" · ")}. You found a gap; see the timeline for how.`;
  }
  v.className = `rounded-2xl p-5 border-2 border-${tone}-500 bg-${tone}-950/40`;
  v.innerHTML = `<p class="text-lg font-black text-white">${esc(title)}</p><p class="text-sm text-slate-200 mt-1">${esc(text)}</p>`;
}

function resetLanes() {
  for (const lane of Object.values(lanes)) {
    lane.list.innerHTML = "";
    lane.result.classList.add("hidden");
    lane.summary = null;
    lane.error = null;
    lane.status.textContent = "waiting";
  }
  $("signals").innerHTML = "";
  $("verdict").classList.add("hidden");
}

async function send() {
  $("formError").classList.add("hidden");
  const payload = {
    sender_name: $("senderName").value,
    sender_email: $("senderEmail").value,
    subject: $("subject").value,
    body: $("body").value,
    brain,
  };
  const res = await fetch("/api/lab/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  const data = await res.json();
  if (!res.ok) {
    $("formError").textContent = typeof data.detail === "string" ? data.detail : "Please check the email fields.";
    $("formError").classList.remove("hidden");
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
  source.onerror = () => { source.close(); $("sendBtn").disabled = false; $("sendBtn").textContent = "Send to both assistants →"; };
  $("verdict").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function loadInbox() {
  let data;
  try { data = await (await fetch("/api/lab/inbox")).json(); } catch (e) { return; }
  if (!data.enabled) return;
  $("realInbox").classList.remove("hidden");
  $("inboxAddress").textContent = data.address || "";
  const list = $("inboxList");
  if (data.error) { list.innerHTML = `<p class="text-rose-300 text-xs">${esc(data.error)}</p>`; return; }
  if (!data.messages.length) { list.innerHTML = `<p class="text-slate-500 text-xs italic">No emails yet.</p>`; return; }
  list.innerHTML = data.messages.map(m => `
    <div class="flex flex-wrap items-center justify-between gap-2 bg-slate-950 border border-slate-800 rounded-lg p-2.5">
      <div class="min-w-0">
        <p class="text-slate-200 truncate"><span class="font-semibold">${esc(m.subject)}</span></p>
        <p class="text-xs text-slate-400 truncate">${esc(m.from)} · ${esc(new Date(m.received_at).toLocaleString())}
          ${m.screening.map(l => `<span class="ml-1 text-[10px] px-1.5 rounded bg-sky-500/10 text-sky-200 border border-sky-500/30">${esc(l)}</span>`).join("")}</p>
      </div>
      <button data-id="${esc(m.id)}" class="run-inbox text-xs font-bold bg-rose-600 hover:bg-rose-500 text-white rounded-lg px-3 py-1.5">Run this email →</button>
    </div>`).join("");
  list.querySelectorAll(".run-inbox").forEach(btn => btn.addEventListener("click", () => runInbox(btn.dataset.id)));
}

async function runInbox(id) {
  $("formError").classList.add("hidden");
  const res = await fetch(`/api/lab/run-inbox/${encodeURIComponent(id)}?brain=${brain}`, { method: "POST" });
  const data = await res.json();
  if (!res.ok) {
    $("formError").textContent = typeof data.detail === "string" ? data.detail : "Couldn't run that email.";
    $("formError").classList.remove("hidden");
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
setInterval(loadInbox, 10000);
