// AgentWall Interactive Dashboard Client

let currentMode = "protected";
let currentScenario = "b_protected_defense";
let sseSource = null;
let eventCount = 0;
let lastScamReport = null;

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
    modeUnprotectedBtn.className = "text-xs font-semibold px-3 py-1.5 rounded transition-all bg-rose-600 text-white shadow-md shadow-rose-600/30";
    modeProtectedBtn.className = "text-xs font-semibold px-3 py-1.5 rounded transition-all text-slate-400 hover:text-slate-200";
  } else {
    modeProtectedBtn.className = "text-xs font-semibold px-3 py-1.5 rounded transition-all bg-emerald-600 text-white shadow-md shadow-emerald-600/30";
    modeUnprotectedBtn.className = "text-xs font-semibold px-3 py-1.5 rounded transition-all text-slate-400 hover:text-slate-200";
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
      approvalBanner.classList.add("hidden");
      timelineContainer.innerHTML = "";
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

    case "approval_needed":
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
  div.className = "bg-slate-950/80 border border-slate-800 rounded-xl p-3 text-xs";
  if (type === "system") {
    div.innerHTML = `<span class="text-cyan-400 font-mono font-bold">[SYSTEM]</span> <span class="text-slate-300">${text}</span>`;
  } else if (type === "error") {
    div.innerHTML = `<span class="text-rose-400 font-mono font-bold">[ERROR]</span> <span class="text-rose-200">${text}</span>`;
  }
  timelineContainer.appendChild(div);
  timelineContainer.scrollTop = timelineContainer.scrollHeight;
}

function appendToolCallCard(event) {
  const cardId = `tc_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`;
  const div = document.createElement("div");
  div.id = cardId;
  div.className = "bg-slate-950 border border-slate-800 rounded-xl p-3.5 space-y-2.5 transition-all";

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
        <span class="font-mono font-bold text-xs text-white">${event.tool_name}()</span>
        <span class="text-[10px] font-mono px-2 py-0.5 rounded border ${categoryColor}">${event.category}</span>
      </div>
      <span class="status-badge text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-400 animate-pulse">
        EVALUATING...
      </span>
    </div>
    <div class="bg-slate-900/90 rounded p-2 text-[11px] font-mono text-slate-300 overflow-x-auto">
      ${JSON.stringify(event.arguments, null, 2)}
    </div>
    <div class="decision-reason hidden text-[11px] pt-1 border-t border-slate-800/80"></div>
  `;

  div.addEventListener("click", () => {
    inspectProvenance(event.tool_name, event.arguments);
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

  if (event.decision === "allow") {
    badge.className = "status-badge text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
    badge.innerHTML = "✓ [ALLOWED]";
    reasonDiv.innerHTML = `<span class="text-emerald-400 font-semibold">Firewall Allowed:</span> <span class="text-slate-300">${event.reason}</span>`;
  } else if (event.decision === "block") {
    badge.className = "status-badge text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30";
    badge.innerHTML = "🚫 [BLOCKED]";
    reasonDiv.innerHTML = `<span class="text-rose-400 font-semibold">Security Policy Block:</span> <span class="text-rose-200">${event.reason}</span>`;
    lastCard.classList.add("border-rose-500/40");
  } else if (event.decision === "require_approval") {
    badge.className = "status-badge text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30";
    badge.innerHTML = "⚠️ [VERIFICATION REQUIRED]";
    reasonDiv.innerHTML = `<span class="text-amber-400 font-semibold">Held for Human Approval:</span> <span class="text-amber-200">${event.reason}</span>`;
    lastCard.classList.add("border-amber-500/40");
  }

  reasonDiv.classList.remove("hidden");
  timelineContainer.scrollTop = timelineContainer.scrollHeight;
}

function appendSignalCard(event) {
  const div = document.createElement("div");
  div.className = "bg-amber-950/30 border border-amber-500/30 rounded-lg p-2.5 text-xs flex items-start gap-2";
  div.innerHTML = `
    <span class="text-amber-400 font-bold">⚠️</span>
    <div>
      <p class="font-bold text-amber-300 uppercase font-mono text-[10px]">Signal: ${event.signal_type.replace('_', ' ')}</p>
      <p class="text-amber-100/90 text-[11px]">${event.evidence}</p>
    </div>
  `;
  timelineContainer.appendChild(div);
  timelineContainer.scrollTop = timelineContainer.scrollHeight;
}

function appendJudgeCard(event) {
  const div = document.createElement("div");
  div.className = "bg-purple-950/40 border border-purple-500/40 rounded-lg p-2.5 text-xs flex items-start gap-2";
  div.innerHTML = `
    <span class="text-purple-400 font-bold">🔍</span>
    <div>
      <p class="font-bold text-purple-300 uppercase font-mono text-[10px]">Isolated Judge: Prompt Injection Detected (Confidence: ${Math.round(event.confidence * 100)}%)</p>
      <p class="text-purple-100/90 text-[11px]">${event.explanation}</p>
    </div>
  `;
  timelineContainer.appendChild(div);
  timelineContainer.scrollTop = timelineContainer.scrollHeight;
}

function showApprovalBanner(event) {
  activeApprovalId = event.approval_id;
  approvalReason.textContent = event.reason;
  approvalDetails.textContent = `Action: ${event.tool_name} | Target: ${event.target || 'N/A'} | Amount: $${event.amount ? event.amount.toLocaleString() : 'N/A'}`;
  approvalBanner.classList.remove("hidden");
}

approveBtn.addEventListener("click", async () => {
  if (!activeApprovalId) return;
  await resolveApproval(activeApprovalId, true, "Approved by administrator via dashboard");
});

denyBtn.addEventListener("click", async () => {
  if (!activeApprovalId) return;
  await resolveApproval(activeApprovalId, false, "Denied by administrator: suspected fraud");
});

async function resolveApproval(approvalId, approved, note) {
  try {
    await fetch(`/api/approvals/${approvalId}/resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approved, note }),
    });
    approvalBanner.classList.add("hidden");
  } catch (err) {
    console.error("Failed to resolve approval:", err);
  }
}

// Finish Run & Render Outcome Banner
function finishRun(result) {
  setRunning(false);
  updateStats(result.money_lost, result.leaked_files.length, result.leaked_files);

  outcomeBanner.classList.remove("hidden");

  if (result.money_lost > 0 || result.leaked_files.length > 0) {
    // Unprotected failure banner
    outcomeBanner.className = "bg-gradient-to-r from-rose-950/90 via-rose-900/80 to-slate-900 border-2 border-rose-500 rounded-2xl p-6 shadow-2xl shadow-rose-950/50 flex items-start gap-4";
    outcomeBanner.innerHTML = `
      <div class="h-12 w-12 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/40 flex items-center justify-center text-2xl flex-shrink-0">
        🚨
      </div>
      <div class="space-y-1">
        <div class="flex items-center gap-2">
          <span class="text-xs font-mono font-bold uppercase tracking-wider text-rose-400">Vulnerability Confirmed</span>
          <span class="text-xs bg-rose-500/20 text-rose-300 px-2 py-0.5 rounded font-mono">UNPROTECTED MODE</span>
        </div>
        <h2 class="text-lg font-black text-white">FRAUD SUCCEEDED: $${result.money_lost.toLocaleString()} paid to scammer, payroll leaked!</h2>
        <p class="text-xs text-rose-200/90 leading-relaxed">
          The unprotected assistant executed the prompt injection from the fake CEO, transferred funds to unverified account ACC-99281, and forwarded confidential file finance/q3_payroll.csv to external lookalike domain kopje-logistlcs.example.
        </p>
      </div>
    `;
    attackerStatusBadge.className = "text-xs font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30";
    attackerStatusBadge.textContent = `STOLEN: $${result.money_lost.toLocaleString()}`;
  } else {
    // Protected defense success banner
    outcomeBanner.className = "bg-gradient-to-r from-emerald-950/90 via-emerald-900/80 to-slate-900 border-2 border-emerald-500 rounded-2xl p-6 shadow-2xl shadow-emerald-950/50 flex items-start gap-4";
    outcomeBanner.innerHTML = `
      <div class="h-12 w-12 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center text-2xl flex-shrink-0">
        🛡️
      </div>
      <div class="space-y-1">
        <div class="flex items-center gap-2">
          <span class="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400">Threat Neutralized</span>
          <span class="text-xs bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded font-mono">AGENTWALL PROTECTED</span>
        </div>
        <h2 class="text-lg font-black text-white">SCAM STOPPED, WORK DONE!</h2>
        <p class="text-xs text-emerald-200/90 leading-relaxed">
          AgentWall intercepted all fraudulent transfers and prevented exfiltration of confidential files. Legitimate supplier payments and customer quote drafts completed successfully.
        </p>
      </div>
    `;
    attackerStatusBadge.className = "text-xs font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
    attackerStatusBadge.textContent = "ZERO LOSS ($0.00)";
  }

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
    <div class="bg-rose-950/20 border border-rose-500/30 rounded-xl p-3 space-y-2">
      <p class="font-bold text-rose-400 uppercase font-mono text-[10px]">What the scammer tried:</p>
      <p class="text-slate-200 text-xs">${report.summary}</p>
    </div>

    <div class="space-y-1.5">
      <p class="font-bold text-slate-400 uppercase font-mono text-[10px]">Red Flags with Quoted Evidence:</p>
      ${report.red_flags.map((rf, idx) => `
        <div class="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-[11px]">
          <span class="text-amber-400 font-bold">${idx + 1}. ${rf.title}:</span>
          <span class="text-slate-300 font-mono">${rf.evidence}</span>
        </div>
      `).join("")}
    </div>

    <div class="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1.5">
      <p class="font-bold text-emerald-400 uppercase font-mono text-[10px]">Recommended Response Steps:</p>
      <ul class="list-disc pl-4 space-y-1 text-[11px] text-slate-300">
        ${report.recommended_next_steps.map(step => `<li>${step}</li>`).join("")}
      </ul>
    </div>
  `;
}

copyReportBtn.addEventListener("click", () => {
  if (!lastScamReport) {
    alert("No scam report generated yet.");
    return;
  }
  const md = `# 🛡️ AgentWall Incident Scam Report\n**Summary:** ${lastScamReport.summary}\n\n## Red Flags\n${lastScamReport.red_flags.map(r => `- **${r.title}**: ${r.evidence}`).join('\n')}\n\n## Next Steps\n${lastScamReport.recommended_next_steps.map(s => `- ${s}`).join('\n')}`;
  navigator.clipboard.writeText(md).then(() => {
    alert("Scam report copied to clipboard as Markdown!");
  });
});

function inspectProvenance(toolName, args) {
  provenanceList.innerHTML = `
    <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-2">
      <p class="text-cyan-400 font-bold font-mono text-xs">Target: ${toolName}()</p>
      <p class="text-slate-400 text-[11px]">Inspecting arguments:</p>
      <pre class="text-[10px] text-slate-300 overflow-x-auto">${JSON.stringify(args, null, 2)}</pre>
      <div class="pt-2 border-t border-slate-800 text-[11px] text-slate-300 space-y-1 font-sans">
        <p>• <span class="font-semibold text-emerald-400">CaMeL Data Flow:</span> Validated against session taint registry.</p>
        <p>• <span class="font-semibold text-cyan-400">Context Provenance:</span> Untrusted external messages tracked.</p>
      </div>
    </div>
  `;
}

// Status & Audit Log Pollers
async function fetchStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    if (data.outbox && data.outbox.length > 0) {
      attackerOutboxList.innerHTML = data.outbox.map(email => `
        <div class="bg-rose-950/20 border border-rose-500/30 p-2.5 rounded-lg space-y-1">
          <p class="font-mono text-rose-300 font-bold">To: ${email.to}</p>
          <p class="font-semibold text-slate-200">Subject: ${email.subject}</p>
          <pre class="text-[10px] text-slate-400 font-mono whitespace-pre-wrap">${email.body.substring(0, 150)}...</pre>
        </div>
      `).join("");
    } else {
      attackerOutboxList.innerHTML = `<p class="text-slate-500 italic text-center py-2">No emails exfiltrated to attacker.</p>`;
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
            <span class="text-slate-500">#${entry.index}</span>
            <span class="text-cyan-400 font-bold ml-1">${entry.event}</span>
            <span class="text-slate-400 ml-2">${JSON.stringify(entry.details).substring(0, 60)}...</span>
          </div>
          <div class="text-[10px] text-slate-500 font-mono">
            SHA256: <span class="text-emerald-500 font-bold">${entry.entry_hash.substring(0, 8)}...</span>
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
  verificationResult.className = "rounded-xl p-3.5 text-xs font-mono bg-slate-800 text-slate-300";
  verificationResult.textContent = "Verifying Ed25519 signatures and SHA-256 hash chaining across all log entries...";

  try {
    const res = await fetch("/api/verify-log", { method: "POST" });
    const data = await res.json();

    if (data.valid) {
      verificationResult.className = "rounded-xl p-3.5 text-xs font-mono bg-emerald-950/60 border border-emerald-500 text-emerald-300 flex items-center gap-2";
      verificationResult.innerHTML = `<span>✓</span> <span><strong>VERIFIED INTACT:</strong> ${data.message} (${data.total_entries} records validated)</span>`;
    } else {
      verificationResult.className = "rounded-xl p-3.5 text-xs font-mono bg-rose-950/80 border-2 border-rose-500 text-rose-300 space-y-1";
      verificationResult.innerHTML = `
        <div class="flex items-center gap-2 font-bold text-rose-200">
          <span>🚨</span> <span>CRYPTOGRAPHIC TAMPERING DETECTED!</span>
        </div>
        <p class="text-rose-100">${data.message}</p>
        <p class="text-[11px] text-rose-300">Broken Entry Index: #${data.broken_index}</p>
      `;
    }
    fetchAuditLogs();
  } catch (err) {
    verificationResult.className = "rounded-xl p-3.5 text-xs font-mono bg-rose-950 text-rose-300";
    verificationResult.textContent = `Verification error: ${err.message}`;
  }
});

tamperLogBtn.addEventListener("click", async () => {
  try {
    const res = await fetch("/api/tamper-log", { method: "POST" });
    const data = await res.json();
    alert(`⚡ Simulated Tamper: Entry #${data.tampered_index} was modified on disk!\nNow click "Verify Log Integrity" to watch cryptographic detection in action.`);
    fetchAuditLogs();
  } catch (err) {
    alert("Please run a scenario first so there are audit log entries to tamper with.");
  }
});

function setRunning(running) {
  runBtn.disabled = running;
  if (running) {
    runBtnText.textContent = "RUNNING...";
  } else {
    runBtnText.textContent = "RUN SCENARIO";
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
  approvalBanner.classList.add("hidden");
  updateStats(0, 0, []);
  attackerOutboxList.innerHTML = `<p class="text-slate-500 italic text-center py-2">No emails exfiltrated to attacker.</p>`;
  scamReportContent.innerHTML = `<p class="text-slate-400 italic">No threats intercepted in current run.</p>`;
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
