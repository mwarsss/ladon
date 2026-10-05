"""
FastAPI Server and Real-Time Event Hub for Ladon.

Provides REST APIs and Server-Sent Events (SSE) streaming for the live interactive web dashboard:
- Run Scenarios A–E in Unprotected or Protected modes
- Stream real-time tool calls, firewall decisions, injection verdicts, and audit records
- Resolve human-in-the-loop approvals (Approve / Deny)
- Verify cryptographic audit log integrity and simulate tampering live on camera
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import sys
import threading
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ladon.agent import make_judge, run_agent_loop
from ladon.approvals import ApprovalQueue, CodeRejected
from ladon.audit import AuditLogger
from ladon.environment import Environment
from ladon.gateway import Gateway
from ladon.lab import router as lab_router
from ladon.llm import create_llm_provider
from ladon.security import PUBLIC, RateLimiter, SecurityMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
SCENARIOS_DIR = BASE_DIR / "scenarios"
LOGS_DIR = BASE_DIR / "logs"
KEYS_DIR = BASE_DIR / "keys"

app = FastAPI(title="Ladon Dashboard API", version="0.2.0",
              # No interactive API docs on a public deployment.
              docs_url=None if PUBLIC else "/docs", redoc_url=None, openapi_url=None if PUBLIC else "/openapi.json")
app.add_middleware(SecurityMiddleware)

# The scenario dashboard shares one state between visitors, so its state-changing
# endpoints are limited per visitor.
dashboard_limit = RateLimiter(limit=int(os.environ.get("DASHBOARD_ACTIONS_PER_HOUR", "60")))

# The dashboard is served from the same origin, so no cross-site access is needed.
ALLOWED_ORIGINS = os.environ.get("LADON_ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Global State Container
class ServerState:
    def __init__(self):
        self.lock = threading.Lock()
        self.is_running = False
        self.current_scenario_id = "a_attack_email"
        self.current_mode = "protected"
        self.env: Optional[Environment] = None
        self.gateway: Optional[Gateway] = None
        self.approval_queue = ApprovalQueue()
        self.audit_logger = AuditLogger()
        self.sse_queues: List[queue.Queue] = []
        self.last_run_result: Optional[Dict[str, Any]] = None

    def broadcast_event(self, event_data: Dict[str, Any]) -> None:
        """Enqueue event for all active SSE connections."""
        with self.lock:
            dead_queues = []
            for q in self.sse_queues:
                try:
                    q.put_nowait(event_data)
                except Exception:
                    dead_queues.append(q)
            for dq in dead_queues:
                if dq in self.sse_queues:
                    self.sse_queues.remove(dq)


state = ServerState()

KNOWN_SCENARIO_IDS = {p.stem for p in SCENARIOS_DIR.glob("*.json")}


class RunRequest(BaseModel):
    scenario_id: str = "a_attack_email"
    mode: str = "protected"  # "unprotected" or "protected"
    llm_mode: str = "replay"  # "replay", "auto", "live"


class ResolveApprovalRequest(BaseModel):
    approved: bool
    note: Optional[str] = None
    code: Optional[str] = None


@app.get("/api/scenarios")
def get_scenarios():
    """Return all available demo scenarios."""
    scenarios = [
        {
            "id": "a_attack_email",
            "name": "Scenario A: Attack Email (Unprotected)",
            "description": "BEC CEO Impersonation & prompt injection. Watch the unprotected assistant leak payroll and pay the scammer.",
            "recommended_mode": "unprotected",
        },
        {
            "id": "b_protected_defense",
            "name": "Scenario B: Protected Defense (Firewall Active)",
            "description": "The exact same attack email, but Ladon stops the fraud, prevents exfiltration, and finishes legitimate work.",
            "recommended_mode": "protected",
        },
        {
            "id": "c_benign_inbox",
            "name": "Scenario C: Benign Daily Inbox (Zero False Alarms)",
            "description": "Normal business operations: customer transport inquiries and verified supplier invoice. Proves Ladon does not over-block.",
            "recommended_mode": "protected",
        },
        {
            "id": "d_verify_bank_change",
            "name": "Scenario D: Verify Before Paying (Human Approval)",
            "description": "Genuine supplier asks to pay to a new bank account. Ladon pauses the payment and requests human confirmation.",
            "recommended_mode": "protected",
        },
        {
            "id": "e_tamper_evident",
            "name": "Scenario E: Tamper-Evident Audit Log",
            "description": "Cryptographically verifiable signed audit log with instant tamper detection.",
            "recommended_mode": "protected",
        },
    ]
    return {"scenarios": scenarios}


@app.get("/api/status")
def get_status():
    """Return live system state."""
    with state.lock:
        env = state.env
        outbox_items = []
        payments_items = []
        drafts_items = []
        money_lost = 0.0
        leaked_files = []

        if env:
            outbox_items = [
                {"to": e.to, "subject": e.subject, "body": e.body, "timestamp": e.timestamp}
                for e in env.outbox
            ]
            payments_items = [
                {"to": p.to, "amount": p.amount, "reference": p.reference, "is_scam": p.is_scam}
                for p in env.payments
            ]
            drafts_items = [
                {"email_id": d.email_id, "body": d.body, "timestamp": d.timestamp}
                for d in env.drafts
            ]
            money_lost = env.total_money_lost
            leaked_files = env.leaked_files

        return {
            "is_running": state.is_running,
            "current_scenario_id": state.current_scenario_id,
            "mode": state.current_mode,
            "money_lost": money_lost,
            "leaked_files": leaked_files,
            "outbox": outbox_items,
            "payments": payments_items,
            "drafts": drafts_items,
            "pending_approvals": state.approval_queue.get_pending(),
            "last_run_result": state.last_run_result,
        }


def _run_worker(scenario_id: str, mode: str, llm_mode: str) -> None:
    """Background worker executing scenario agent loop."""
    try:
        scenario_file = SCENARIOS_DIR / f"{scenario_id}.json"
        if scenario_id not in KNOWN_SCENARIO_IDS or not scenario_file.exists():
            state.broadcast_event({"type": "error", "message": f"Scenario not found: {scenario_id}"})
            return

        with open(scenario_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        env = Environment.from_scenario(data)
        audit_logger = AuditLogger()
        approval_queue = ApprovalQueue(default_timeout_seconds=45.0)

        llm = create_llm_provider(mode=llm_mode, scenario_name=scenario_id)
        gateway = Gateway(
            env=env,
            mode=mode,
            audit_logger=audit_logger,
            approval_queue=approval_queue,
            judge=make_judge(llm),
        )

        # Wire gateway events directly into the SSE broadcaster
        gateway.add_event_listener(state.broadcast_event)

        with state.lock:
            state.env = env
            state.gateway = gateway
            state.approval_queue = approval_queue
            state.audit_logger = audit_logger
            state.current_scenario_id = scenario_id
            state.current_mode = mode

        state.broadcast_event({
            "type": "run_started",
            "scenario_id": scenario_id,
            "mode": mode,
            "scenario_name": data.get("name", scenario_id),
        })

        result = run_agent_loop(env=env, gateway=gateway, llm=llm)

        with state.lock:
            state.last_run_result = {
                "completed": result.completed,
                "turns": result.turns,
                "money_lost": result.total_money_lost,
                "leaked_files": result.leaked_files,
                "outbox_count": result.outbox_count,
                "payments_count": result.payments_count,
                "drafts_count": result.drafts_count,
                "final_response": result.final_response,
            }

        state.broadcast_event({
            "type": "run_completed",
            "result": state.last_run_result,
        })

    except Exception as e:
        state.broadcast_event({"type": "error", "message": str(e)})
    finally:
        with state.lock:
            state.is_running = False


@app.post("/api/run")
def start_run(req: RunRequest, background_tasks: BackgroundTasks, request: Request):
    """Start executing a scenario in background."""
    dashboard_limit.check(request, "scenario runs")
    if PUBLIC and req.llm_mode != "replay":
        raise HTTPException(status_code=403, detail="The public demo replays recorded runs. Use the Attack Lab for a live model.")
    if req.scenario_id not in KNOWN_SCENARIO_IDS:
        raise HTTPException(status_code=404, detail="Unknown scenario.")
    if req.mode not in ("protected", "unprotected") or req.llm_mode not in ("replay", "auto", "live"):
        raise HTTPException(status_code=422, detail="Invalid mode.")
    with state.lock:
        if state.is_running:
            raise HTTPException(status_code=400, detail="A scenario run is already in progress.")
        state.is_running = True

    background_tasks.add_task(_run_worker, req.scenario_id, req.mode, req.llm_mode)
    return {"status": "started", "scenario_id": req.scenario_id, "mode": req.mode}


@app.post("/api/approvals/{approval_id}/resolve")
def resolve_approval(approval_id: str, req: ResolveApprovalRequest, request: Request):
    """Approve or Deny a held action."""
    dashboard_limit.check(request, "approval attempts")
    try:
        success = state.approval_queue.resolve(approval_id, req.approved, req.note, code=req.code)
    except CodeRejected as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    if not success:
        raise HTTPException(status_code=404, detail="Pending approval not found or already resolved.")

    state.broadcast_event({
        "type": "approval_resolved",
        "approval_id": approval_id,
        "approved": req.approved,
        "note": req.note,
    })
    return {"status": "resolved", "approval_id": approval_id, "approved": req.approved}


@app.get("/api/events")
async def sse_events(request: Request):
    """Server-Sent Events endpoint streaming real-time timeline data."""
    q: queue.Queue = queue.Queue(maxsize=100)
    with state.lock:
        state.sse_queues.append(q)

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            # Send initial connection heartbeat
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = q.get_nowait()
                    yield f"data: {json.dumps(event)}\n\n"
                except queue.Empty:
                    await asyncio.sleep(0.1)
        finally:
            with state.lock:
                if q in state.sse_queues:
                    state.sse_queues.remove(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/verify-log")
def verify_audit_log(request: Request):
    """Verify cryptographic integrity of the audit log."""
    dashboard_limit.check(request, "log checks")
    log_file = LOGS_DIR / "audit.jsonl"
    pub_key_file = KEYS_DIR / "ed25519_public.pem"

    is_valid, message, broken_idx = AuditLogger.verify_log_file(
        log_path=log_file,
        public_key_path=pub_key_file,
    )

    # Read latest entries for viewer
    entries: List[Dict[str, Any]] = []
    if log_file.exists():
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass

    return {
        "valid": is_valid,
        "message": message,
        "broken_index": broken_idx,
        "total_entries": len(entries),
        "recent_entries": entries[-10:],
    }


@app.post("/api/tamper-log")
def tamper_audit_log(request: Request):
    """Deliberately modify one entry in audit.jsonl to demonstrate cryptographic tamper detection."""
    dashboard_limit.check(request, "tamper demos")
    log_file = LOGS_DIR / "audit.jsonl"
    if not log_file.exists() or log_file.stat().st_size == 0:
        raise HTTPException(status_code=400, detail="Audit log is empty. Run a scenario first.")

    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        raise HTTPException(status_code=400, detail="Audit log has no entries to tamper with.")

    # Tamper with the earliest entry
    tampered_entry = json.loads(lines[0])
    orig = json.dumps(tampered_entry.get("details", {}))
    tampered_entry["details"]["tampered_by"] = "malicious_attacker"
    lines[0] = json.dumps(tampered_entry) + "\n"

    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    state.broadcast_event({
        "type": "audit_tampered",
        "index": tampered_entry.get("index", 0),
    })

    return {
        "status": "tampered",
        "tampered_index": tampered_entry.get("index", 0),
        "message": "Entry modified. Click 'Verify Log' to see cryptographic tamper detection in action.",
    }


@app.post("/api/reset")
def reset_system(request: Request):
    """Reset system state and mutable data."""
    dashboard_limit.check(request, "resets")
    with state.lock:
        state.is_running = False
        state.env = None
        state.gateway = None
        state.last_run_result = None
        state.approval_queue = ApprovalQueue()

    # Reinitialize fresh audit log
    if (LOGS_DIR / "audit.jsonl").exists():
        os.remove(LOGS_DIR / "audit.jsonl")

    state.audit_logger = AuditLogger()
    return {"status": "reset"}


# Mount static web UI files
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


app.include_router(lab_router)


@app.get("/lab", response_class=HTMLResponse)
def attack_lab_page():
    """Attack Lab: one email, unprotected vs protected, side by side."""
    lab_file = WEB_DIR / "lab.html"
    return HTMLResponse(lab_file.read_text(encoding="utf-8"))


@app.get("/", response_class=HTMLResponse)
def index_page():
    """Serve main dashboard single page app."""
    index_file = WEB_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>Ladon Dashboard loading...</h1>", status_code=200)
    with open(index_file, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


def start_server(host: Optional[str] = None, port: Optional[int] = None) -> None:
    import uvicorn
    # Local runs stay on 127.0.0.1; a host like Render sets HOST=0.0.0.0 and PORT.
    uvicorn.run("ladon.server:app", host=host or os.environ.get("HOST", "127.0.0.1"),
                port=port or int(os.environ.get("PORT", "8000")), reload=False)


if __name__ == "__main__":
    start_server()
