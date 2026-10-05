// Ladon Interactive Dashboard Client

let currentMode = "protected";
let currentScenario = "b_protected_defense";
let sseSource = null;
let eventCount = 0;
let lastScamReport = null;
let runStats = { blocked: 0, held: 0, approved: 0, denied: 0 };

// Everything shown in the dashboard can originate from attacker-written email text.
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

// DOM Elements
const scenarioSelect = document.getElementById("scenarioSelect");
const modeUnprotectedBtn = document.getElementById("modeUnprotectedBtn");
const modeProtectedBtn = document.getElementById("modeProtectedBtn");
const runBtn = document.getElementById("runBtn");
const runBtnText = document.getElementById("runBtnText");
const resetBtn = document.getElementById("resetBtn");
const timelineContainer = document.getElementById("timelineContainer");
const timelineCounter = document.getElementById("timelineCounter");
const outcomeBanner = document.getElementById("outcomeBanner");
const approvalBanner = document.getElementById("approvalBanner");
const approvalReason = document.getElementById("approvalReason");
const approvalDetails = document.getElementById("approvalDetails");
const approveBtn = document.getElementById("approveBtn");
const denyBtn = document.getElementById("denyBtn");
const statMoneyLost = document.getElementById("statMoneyLost");
const statLeakedFiles = document.getElementById("statLeakedFiles");
const attackerStatusBadge = document.getElementById("attackerStatusBadge");
const attackerOutboxList = document.getElementById("attackerOutboxList");
const scamReportContent = document.getElementById("scamReportContent");
const provenanceList = document.getElementById("provenanceList");
const auditLogContainer = document.getElementById("auditLogContainer");
const verifyLogBtn = document.getElementById("verifyLogBtn");
const tamperLogBtn = document.getElementById("tamperLogBtn");
const verificationResult = document.getElementById("verificationResult");
const copyReportBtn = document.getElementById("copyReportBtn");

let activeApprovalId = null;

// Mode Switcher Logic
function setMode(mode) {
  currentMode = mode;
  if (mode === "unprotected") {
    modeUnprotectedBtn.className = "text-xs font-semibold px-3 py-1.5 rounded-full bg-rose-600 text-onfill";
    modeProtectedBtn.className = "text-xs font-semibold px-3 py-1.5 rounded-full text-slate-400 hover:text-slate-200";
  } else {
    modeProtectedBtn.className = "text-xs font-semibold px-3 py-1.5 rounded-full bg-emerald-600 text-onfill";
    modeUnprotectedBtn.className = "text-xs font-semibold px-3 py-1.5 rounded-full text-slate-400 hover:text-slate-200";
  }
}

modeUnprotectedBtn.addEventListener("click", () => setMode("unprotected"));
modeProtectedBtn.addEventListener("click", () => setMode("protected"));

scenarioSelect.addEventListener("change", (e) => {
  currentScenario = e.target.value;
  if (currentScenario === "a_attack_email") {
    setMode("unprotected");
  } else {
    setMode("protected");
  }
});

// SSE Connection Setup
function connectSSE() {
  if (sseSource) {
    sseSource.close();
  }

  sseSource = new EventSource("/api/events");

  sseSource.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      handleServerEvent(data);
    } catch (err) {
      console.error("Failed to parse SSE event:", err);
    }
  };

  sseSource.onerror = (err) => {
    console.warn("SSE connection interrupted, retrying...", err);
  };
}

function handleServerEvent(event) {
  eventCount++;
  timelineCounter.textContent = `${eventCount} events`;

  switch (event.type) {
    case "run_started":
      outcomeBanner.classList.add("hidden");
      approvalBanner.classList.add("hidden"); document.getElementById("supplierPhone").classList.add("hidden");
      timelineContainer.innerHTML = "";
      runStats = { blocked: 0, held: 0, approved: 0, denied: 0 };
      lastScamReport = null;
      scamReportContent.innerHTML = `<p class="text-slate-400 italic">No threats intercepted in current run.</p>`;
      provenanceList.innerHTML = `<p class="text-slate-500 italic">Click any tool call in the timeline to inspect its provenance.</p>`;
      eventCount = 1;
      timelineCounter.textContent = "1 event";
      appendTimelineCard("system", `Run started: ${event.scenario_name} [${event.mode.toUpperCase()}]`);
      updateStats(0, 0, []);
      break;

    case "tool_call":
      appendToolCallCard(event);
      break;

    case "decision":
      updateToolDecisionCard(event);
      if (event.scam_report) {
        renderScamReport(event.scam_report);
      }
      break;

    case "impersonation_signal":
      appendSignalCard(event);
      break;

    case "judge_verdict":
      appendJudgeCard(event);
      break;

    case "verification_sent":
      document.getElementById("phoneTo").textContent = `To ${event.to_name}, ${event.to_phone}`;
      document.getElementById("phoneSms").textContent = event.message;
      document.getElementById("supplierPhone").classList.remove("hidden");
      break;

    case "approval_needed":
      runStats.held += 1;
      showApprovalBanner(event);
      break;

    case "approval_resolved":
      approvalBanner.classList.add("hidden");
      break;

    case "run_completed":
      finishRun(event.result);
      fetchAuditLogs();
      break;

    case "error":
      appendTimelineCard("error", event.message);
      setRunning(false);
      break;
  }
}

// Timeline Rendering
function appendTimelineCard(type, text) {
  const div = document.createElement("div");
  div.className = "bg-slate-950/80 border border-slate-800 rounded p-3 text-xs";
  if (type === "system") {
    div.innerHTML = `<span class="text-cyan-400 font-mono font-bold">[SYSTEM]</span> <span class="text-slate-300">${esc(text)}</span>`;
  } else if (type === "error") {
    div.innerHTML = `<span class="text-rose-400 font-mono font-bold">[ERROR]</span> <span class="text-rose-200">${esc(text)}</span>`;
  }
  timelineContainer.appendChild(div);
  timelineContainer.scrollTop = timelineContainer.scrollHeight;
}

function appendToolCallCard(event) {
  const cardId = `tc_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`;
  const div = document.createElement("div");
  div.id = cardId;
  div.className = "bg-slate-950 border border-slate-800 rounded p-3.5 space-y-2.5";

  const categoryColor = {
    read_private: "text-blue-400 border-blue-500/20 bg-blue-500/10",
    read_untrusted: "text-amber-400 border-amber-500/20 bg-amber-500/10",
    write_internal: "text-slate-300 border-slate-600 bg-slate-800",
    send_external: "text-purple-400 border-purple-500/20 bg-purple-500/10",
    financial: "text-emerald-400 border-emerald-500/20 bg-emerald-500/10",
  }[event.category] || "text-slate-400 border-slate-700 bg-slate-800";

  div.innerHTML = `
    <div class="flex items-center justify-between">
      <div class="flex items-center space-x-2">
        <span class="font-mono font-bold text-xs text-white">${esc(event.tool_name)}()</span>
        <span class="text-[10px] font-mono px-2 py-0.5 rounded border ${categoryColor}">${esc(event.category)}</span>
      </div>
      <span class="status-badge text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-400">
        EVALUATING...
      </span>
    </div>
    <pre class="bg-slate-900/90 rounded p-2 text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">${esc(JSON.stringify(event.arguments, null, 2))}</pre>
    <div class="decision-reason hidden text-[11px] pt-1 border-t border-slate-800/80"></div>
  `;

  div.addEventListener("click", () => {
    inspectProvenance(event.tool_name, event.arguments, div.dataset.provenance ? JSON.parse(div.dataset.provenance) : null);
  });

  timelineContainer.appendChild(div);
  timelineContainer.scrollTop = timelineContainer.scrollHeight;
}

function updateToolDecisionCard(event) {
  const cards = timelineContainer.querySelectorAll("div[id^='tc_']");
  if (!cards.length) return;
  const lastCard = cards[cards.length - 1];

  const badge = lastCard.querySelector(".status-badge");
  const reasonDiv = lastCard.querySelector(".decision-reason");

  badge.classList.remove("animate-pulse");
  if (event.provenance) lastCard.dataset.provenance = JSON.stringify(event.provenance);
  if (event.decision === "block") runStats.blocked += 1;

  if (event.decision === "allow") {
    badge.className = "status-badge text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
    badge.textContent = "allowed";
    reasonDiv.innerHTML = `<span class="text-emerald-400 font-semibold">Firewall Allowed:</span> <span class="text-slate-300">${esc(event.reason)}</span>`;
  } else if (event.decision === "block") {
    badge.className = "status-badge text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30";
    badge.textContent = "blocked";
    reasonDiv.innerHTML = `<span class="text-rose-400 font-semibold">Security Policy Block:</span> <span class="text-rose-200">${esc(event.reason)}</span>`;
    lastCard.classList.add("border-rose-500/40");
  } else if (event.decision === "require_approval") {
    badge.className = "status-badge text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30";
    badge.textContent = "held for a human";
    reasonDiv.innerHTML = `<span class="text-amber-400 font-semibold">Held for Human Approval:</span> <span class="text-amber-200">${esc(event.reason)}</span>`;
    lastCard.classList.add("border-amber-500/40");
  }

  reasonDiv.classList.remove("hidden");
  timelineContainer.scrollTop = timelineContainer.scrollHeight;
}

function appendSignalCard(event) {
  const div = document.createElement("div");
  div.className = "bg-amber-950/30 border border-amber-500/30 rounded-lg p-2.5 text-xs flex items-start gap-2";
  div.innerHTML = `
    <div>
      <p class="font-bold text-amber-300 uppercase font-mono text-[10px]">Signal: ${esc(String(event.signal_type).replace(/_/g, ' '))}</p>
      <p class="text-amber-100/90 text-[11px]">${esc(event.evidence)}</p>
    </div>
  `;
  timelineContainer.appendChild(div);
  timelineContainer.scrollTop = timelineContainer.scrollHeight;
}

function appendJudgeCard(event) {
  const div = document.createElement("div");
  div.className = "bg-purple-950/40 border border-purple-500/40 rounded-lg p-2.5 text-xs flex items-start gap-2";
  div.innerHTML = `
    <div>
      <p class="font-bold text-purple-300 uppercase font-mono text-[10px]">Isolated judge: hidden instruction found (confidence ${Math.round(event.confidence * 100)}%)</p>
      <p class="text-purple-100/90 text-[11px]">${esc(event.explanation)}</p>
    </div>
  `;
  timelineContainer.appendChild(div);
  timelineContainer.scrollTop = timelineContainer.scrollHeight;
}

function showApprovalBanner(event) {
  activeApprovalId = event.approval_id;
  approvalReason.textContent = event.reason;
  approvalDetails.textContent = `Action: ${event.tool_name} | Target: ${event.target || 'N/A'} | Amount: $${event.amount ? event.amount.toLocaleString() : 'N/A'}`;
  const v = event.verification || {};
  const codeInput = document.getElementById("verifyCode");
  codeInput.value = "";
  codeInput.classList.toggle("hidden", !v.contact);
  document.getElementById("verifyError").classList.add("hidden");
  document.getElementById("verifyInstructions").textContent = v.contact
    ? `We texted a one-time code to ${v.contact} on ${v.phone}, the number in your records, not one from the email. Call them on that number. If they really asked for this change, they can read you the code.`
    : "There is no contact on file for this account, so it can't be confirmed by phone. Deny it unless you can verify it in person.";
  approvalBanner.classList.remove("hidden");
}

approveBtn.addEventListener("click", async () => {
  if (!activeApprovalId) return;
  if (await resolveApproval(activeApprovalId, true, null, document.getElementById("verifyCode").value)) {
    runStats.approved += 1;
  }
});

denyBtn.addEventListener("click", async () => {
  if (!activeApprovalId) return;
  runStats.denied += 1;
  await resolveApproval(activeApprovalId, false, "Denied by administrator: suspected fraud");
});

async function resolveApproval(approvalId, approved, note, code) {
  const errorBox = document.getElementById("verifyError");
  try {
    const res = await fetch(`/api/approvals/${approvalId}/resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approved, note, code: code || null }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      errorBox.textContent = data.detail || "Couldn't record that decision.";
      errorBox.classList.remove("hidden");
      if (res.status === 403 && /denied/.test(errorBox.textContent)) {
        runStats.denied += 1;
        approvalBanner.classList.add("hidden");
      }
      return false;
    }
    approvalBanner.classList.add("hidden");
    document.getElementById("supplierPhone").classList.add("hidden");
    return true;
  } catch (err) {
    errorBox.textContent = "Couldn't reach Ladon. Try again.";
    errorBox.classList.remove("hidden");
    return false;
  }
}

// Finish Run & Render Outcome Banner
function finishRun(result) {
  setRunning(false);
  updateStats(result.money_lost, result.leaked_files.length, result.leaked_files);

  outcomeBanner.classList.remove("hidden");

  const lost = result.money_lost > 0 || result.leaked_files.length > 0;
  const stopped = runStats.blocked + runStats.held;
  const money = `$${Number(result.money_lost).toLocaleString()}`;
  let tone, kicker, title, body;
  if (lost) {
    tone = "rose"; kicker = "Fraud succeeded";
    const parts = [];
    if (result.money_lost > 0) parts.push(`${money} paid to scammer accounts`);
    if (result.leaked_files.length) parts.push(`leaked: ${result.leaked_files.join(", ")}`);
    title = parts.join(" · ");
    body = currentMode === "unprotected"
      ? "Without Ladon the assistant followed the scammer's instructions. Run the same inbox in Protected mode to compare."
      : "Ladon did not stop this run. See the timeline for the actions that got through.";
  } else if (stopped > 0) {
    tone = "emerald"; kicker = runStats.blocked ? "Scam stopped" : "Verified before paying";
    const parts = [];
    if (runStats.blocked) parts.push(`${runStats.blocked} action${runStats.blocked > 1 ? "s" : ""} blocked`);
    if (runStats.held) {
      const outcome = runStats.approved ? "you approved it" : runStats.denied ? "you denied it" : "awaiting you";
      parts.push(`${runStats.held} held for your verification (${outcome})`);
    }
    title = `${parts.join(" · ")} · $0 lost`;
    body = runStats.blocked
      ? "Legitimate work completed. The scam report on the right explains each red flag and what to do next."
      : "A bank-detail change was paused until a human confirmed it through a trusted channel, the step that stops most invoice fraud.";
  } else {
    tone = "sky"; kicker = "All clear";
    title = "No threats found · all work completed";
    body = "Ladon allowed every action in this run: nothing in this inbox tried to move money or data where it shouldn't go.";
  }
  outcomeBanner.className = `bg-${tone}-500/10 border border-${tone}-500 p-5`;
  outcomeBanner.innerHTML = `
    <div class="space-y-1">
      <div class="flex items-center gap-2">
        <span class="text-xs font-mono font-bold uppercase tracking-wider text-${tone}-400">${esc(kicker)}</span>
        <span class="text-xs text-slate-400 font-mono">${currentMode === "protected" ? "protected by Ladon" : "no protection"}</span>
      </div>
      <h2 class="wordmark text-white" style="font-size:28px">${esc(title)}</h2>
      <p class="text-sm text-slate-200 leading-relaxed max-w-prose">${esc(body)}</p>
    </div>
  `;
  attackerStatusBadge.className = lost
    ? "text-xs font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30"
    : "text-xs font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
  attackerStatusBadge.textContent = lost ? `${money} stolen` : "$0.00 lost";

  fetchStatus();
}

function updateStats(moneyLost, leakedCount, leakedFiles) {
  statMoneyLost.textContent = `$${moneyLost.toLocaleString()}`;
  statLeakedFiles.textContent = leakedCount.toString();

  if (moneyLost > 0) {
    statMoneyLost.className = "text-xl font-bold font-mono text-rose-400 mt-1";
  } else {
    statMoneyLost.className = "text-xl font-bold font-mono text-emerald-400 mt-1";
  }

  if (leakedCount > 0) {
    statLeakedFiles.className = "text-xl font-bold font-mono text-rose-400 mt-1";
  } else {
    statLeakedFiles.className = "text-xl font-bold font-mono text-emerald-400 mt-1";
  }
}

function renderScamReport(report) {
  lastScamReport = report;
  scamReportContent.innerHTML = `
    <div class="bg-rose-950/20 border border-rose-500/30 rounded p-3 space-y-2">
      <p class="font-bold text-rose-400 uppercase font-mono text-[10px]">What the scammer tried:</p>
      <p class="text-slate-200 text-xs">${esc(report.summary)}</p>
    </div>

    <div class="space-y-1.5">
      <p class="font-bold text-slate-400 uppercase font-mono text-[10px]">Red Flags with Quoted Evidence:</p>
      ${report.red_flags.map((rf, idx) => `
        <div class="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-[11px]">
          <span class="text-amber-400 font-bold">${idx + 1}. ${esc(rf.title)}:</span>
          <span class="text-slate-300 font-mono">${esc(rf.evidence)}</span>
        </div>
      `).join("")}
    </div>

    <div class="bg-slate-950 p-3 rounded border border-slate-800 space-y-1.5">
      <p class="font-bold text-emerald-400 uppercase font-mono text-[10px]">Recommended Response Steps:</p>
      <ul class="list-disc pl-4 space-y-1 text-[11px] text-slate-300">
        ${report.recommended_next_steps.map(step => `<li>${esc(step)}</li>`).join("")}
      </ul>
    </div>
  `;
}

copyReportBtn.addEventListener("click", () => {
  if (!lastScamReport) {
    alert("No scam report generated yet.");
    return;
  }
  const md = `# Ladon scam report\n**Summary:** ${lastScamReport.summary}\n\n## Red Flags\n${lastScamReport.red_flags.map(r => `- **${r.title}**: ${r.evidence}`).join('\n')}\n\n## Next Steps\n${lastScamReport.recommended_next_steps.map(s => `- ${s}`).join('\n')}`;
  navigator.clipboard.writeText(md).then(() => {
    alert("Scam report copied to clipboard as Markdown!");
  });
});

function inspectProvenance(toolName, args, provenance) {
  const flows = provenance ? provenance.flows : [];
  const ctx = provenance ? provenance.untrusted_in_context : [];
  const flowHtml = !provenance
    ? `<p class="text-slate-500 italic">Provenance is recorded in protected mode only.</p>`
    : flows.length === 0
      ? `<p class="text-emerald-300">No tracked data flows into this call's arguments.</p>`
      : flows.map(f => `
          <div class="bg-slate-900 rounded p-2 space-y-0.5">
            <p><span class="font-mono text-cyan-300">${esc(f.source)}</span>
               <span class="text-[10px] px-1.5 rounded ${f.sensitivity === "confidential" ? "bg-rose-500/20 text-rose-300" : "bg-slate-700 text-slate-300"}">${esc(f.sensitivity)}</span>
               <span class="text-[10px] px-1.5 rounded ${f.trust === "untrusted" ? "bg-amber-500/20 text-amber-300" : "bg-slate-700 text-slate-300"}">${esc(f.trust)}</span></p>
            <p class="text-slate-400">into <span class="font-mono">${esc(f.argument)}</span> by ${esc(f.match)} match: <span class="font-mono text-slate-300">${esc(f.evidence)}</span></p>
          </div>`).join("");
  provenanceList.innerHTML = `
    <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-2 text-[11px]">
      <p class="text-cyan-400 font-bold font-mono text-xs">${esc(toolName)}()</p>
      <pre class="text-[10px] text-slate-300 overflow-x-auto whitespace-pre-wrap">${esc(JSON.stringify(args, null, 2))}</pre>
      <p class="text-slate-400 font-semibold pt-2 border-t border-slate-800">Data flowing into this call</p>
      ${flowHtml}
      <p class="text-slate-400 font-semibold pt-2 border-t border-slate-800">Untrusted content the assistant had read</p>
      <p class="font-mono text-amber-300">${ctx.length ? ctx.map(esc).join(", ") : "none"}</p>
    </div>
  `;
}

// Status & Audit Log Pollers
async function fetchStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    if (data.outbox && data.outbox.length > 0) {
      // Red only for emails that leaked company data or went to the scammer; normal replies stay neutral.
      attackerOutboxList.innerHTML = data.outbox.map(email => {
        const bad = (email.leaked_files && email.leaked_files.length) || email.to_scammer;
        const why = [];
        if (email.leaked_files && email.leaked_files.length) why.push(`leaked ${email.leaked_files.join(", ")}`);
        if (email.to_scammer) why.push("sent to the scammer");
        return `
        <div class="${bad ? "bg-rose-950/20 border-rose-500/30" : "bg-slate-950 border-slate-800"} border p-2.5 rounded-lg space-y-1">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <p class="font-mono font-bold ${bad ? "text-rose-300" : "text-slate-200"}">To: ${esc(email.to)}</p>
            <span class="text-[10px] font-mono px-1.5 py-0.5 rounded border ${bad ? "border-rose-500/40 text-rose-300" : "border-slate-700 text-slate-400"}">${bad ? esc(why.join(" · ")) : "normal reply"}</span>
          </div>
          <p class="font-semibold text-slate-200">Subject: ${esc(email.subject)}</p>
          <pre class="text-[10px] text-slate-400 font-mono whitespace-pre-wrap">${esc(email.body.substring(0, 150))}...</pre>
        </div>`;
      }).join("");
    } else {
      attackerOutboxList.innerHTML = `<p class="text-slate-500 italic text-center py-2">No emails sent.</p>`;
    }
  } catch (err) {
    console.error("Failed to fetch status:", err);
  }
}

async function fetchAuditLogs() {
  try {
    const res = await fetch("/api/verify-log", { method: "POST" });
    const data = await res.json();
    if (data.recent_entries && data.recent_entries.length > 0) {
      auditLogContainer.innerHTML = data.recent_entries.map(entry => `
        <div class="p-1.5 hover:bg-slate-900 rounded flex flex-wrap items-center justify-between gap-2 border-b border-slate-900/60">
          <div>
            <span class="text-slate-500">#${esc(entry.index)}</span>
            <span class="text-cyan-400 font-bold ml-1">${esc(entry.event)}</span>
            <span class="text-slate-400 ml-2">${esc(JSON.stringify(entry.details).substring(0, 60))}...</span>
          </div>
          <div class="text-[10px] text-slate-500 font-mono">
            SHA256: <span class="text-emerald-500 font-bold">${esc(entry.entry_hash.substring(0, 8))}...</span>
          </div>
        </div>
      `).join("");
    } else {
      auditLogContainer.innerHTML = `<p class="text-slate-500 italic text-center py-4">No audit entries recorded yet.</p>`;
    }
  } catch (err) {
    console.error("Failed to fetch audit logs:", err);
  }
}

verifyLogBtn.addEventListener("click", async () => {
  verificationResult.classList.remove("hidden");
  verificationResult.className = "rounded p-3.5 text-xs font-mono bg-slate-800 text-slate-300";
  verificationResult.textContent = "Verifying Ed25519 signatures and SHA-256 hash chaining across all log entries...";

  try {
    const res = await fetch("/api/verify-log", { method: "POST" });
    const data = await res.json();

    if (data.valid) {
      verificationResult.className = "rounded p-3.5 text-xs font-mono bg-emerald-950/60 border border-emerald-500 text-emerald-300 flex items-center gap-2";
      verificationResult.innerHTML = `<span><strong>Intact.</strong> ${esc(data.message)} (${esc(data.total_entries)} records validated)</span>`;
    } else {
      verificationResult.className = "rounded p-3.5 text-xs font-mono bg-rose-950/80 border-2 border-rose-500 text-rose-300 space-y-1";
      verificationResult.innerHTML = `
        <div class="flex items-center gap-2 font-bold text-rose-200">
          <span>Tampering detected. The signature chain is broken.</span>
        </div>
        <p class="text-rose-100">${esc(data.message)}</p>
        <p class="text-[11px] text-rose-300">First broken entry: #${esc(data.broken_index)}</p>
      `;
    }
    fetchAuditLogs();
  } catch (err) {
    verificationResult.className = "rounded p-3.5 text-xs font-mono bg-rose-950 text-rose-300";
    verificationResult.textContent = `Verification error: ${err.message}`;
  }
});

tamperLogBtn.addEventListener("click", async () => {
  try {
    const res = await fetch("/api/tamper-log", { method: "POST" });
    const data = await res.json();
    alert(`Entry #${data.tampered_index} was edited on disk. Now press "Verify log integrity" to see the change detected.`);
    fetchAuditLogs();
  } catch (err) {
    alert("Please run a scenario first so there are audit log entries to tamper with.");
  }
});

function setRunning(running) {
  runBtn.disabled = running;
  if (running) {
    runBtnText.textContent = "Running…";
  } else {
    runBtnText.textContent = "Run scenario";
  }
}

runBtn.addEventListener("click", async () => {
  setRunning(true);
  try {
    const res = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenario_id: currentScenario,
        mode: currentMode,
        llm_mode: "replay",
      }),
    });
    if (!res.ok) {
      const err = await res.json();
      alert(`Cannot start run: ${err.detail}`);
      setRunning(false);
    }
  } catch (err) {
    console.error("Run error:", err);
    setRunning(false);
  }
});

resetBtn.addEventListener("click", async () => {
  await fetch("/api/reset", { method: "POST" });
  timelineContainer.innerHTML = `<div class="p-8 text-center text-slate-500 text-xs italic">System reset. Ready to run.</div>`;
  outcomeBanner.classList.add("hidden");
  approvalBanner.classList.add("hidden"); document.getElementById("supplierPhone").classList.add("hidden");
  updateStats(0, 0, []);
  attackerOutboxList.innerHTML = `<p class="text-slate-500 italic text-center py-2">No emails sent.</p>`;
  scamReportContent.innerHTML = `<p class="text-slate-400 italic">No threats intercepted in current run.</p>`;
  provenanceList.innerHTML = `<p class="text-slate-500 italic">Click any tool call in the timeline to inspect its provenance.</p>`;
  auditLogContainer.innerHTML = `<p class="text-slate-500 italic text-center py-4">No audit entries recorded yet.</p>`;
  verificationResult.classList.add("hidden");
  timelineCounter.textContent = "0 events";
  eventCount = 0;
});

// Initialize on page load
window.addEventListener("DOMContentLoaded", () => {
  connectSSE();
  fetchAuditLogs();
});
