"""
VinBank AI Security & Guardrails Console — FastAPI backend.

Chạy từ gốc repo:
    python ui/app.py
hoặc:
    uvicorn ui.app:app --host 127.0.0.1 --port 8000 --reload
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from agents.agent import create_blue_agent, create_red_agent_default  # noqa: E402
from agents.guards_agent import create_red_agent_advance  # noqa: E402
from assignment.audit_log import AuditLogPlugin  # noqa: E402
from assignment.monitoring import MonitoringAlert  # noqa: E402
from assignment.pipeline import (  # noqa: E402
    build_production_plugins,
    is_egress_allowed,
)
from assignment.rate_limiter import RateLimitPlugin  # noqa: E402
from attacks.attacks import (  # noqa: E402
    adversarial_prompts,
    classify_attack_outcome,
)
from core.config import (  # noqa: E402
    blue_provider_label,
    get_liquid_decisions_model,
    get_liquid_decisions_url,
    red_provider_label,
)
from core.liquid_decisions import demo_triage  # noqa: E402
from core.utils import chat_with_agent  # noqa: E402
from google.genai import types  # noqa: E402
from guardrails.input_guardrails import (  # noqa: E402
    InputGuardrailPlugin,
    detect_injection,
    topic_filter,
)
from guardrails.output_guardrails import (  # noqa: E402
    OutputGuardrailPlugin,
    content_filter,
)

app = FastAPI(title="VinBank AI Security & Guardrails Console", version="1.0.0")


class _RuntimeState:
    """In-memory live runtime state for interactive testing."""

    def __init__(self) -> None:
        self.reset_blue()
        self.red_default_pair = None
        self.red_advance_pair = None
        self._red_lock = asyncio.Lock()

    def reset_blue(self, max_requests: int = 10, window_seconds: int = 60) -> None:
        self.plugins = build_production_plugins(
            max_requests=max_requests,
            window_seconds=window_seconds,
            use_llm_judge=False,
        )
        self.rate_limiter: RateLimitPlugin = self.plugins[0]
        self.input_guard: InputGuardrailPlugin = self.plugins[1]
        self.output_guard: OutputGuardrailPlugin = self.plugins[2]
        # Attach only Input + Output plugins to the LLM runner so we can enforce
        # per-user_id RateLimitPlugin explicitly before invoking the runner.
        self.blue_agent, self.blue_runner = create_blue_agent(
            [self.input_guard, self.output_guard]
        )
        self.audit = AuditLogPlugin()
        self.monitor = MonitoringAlert()
        self.req_seq = 0

    async def get_red_default(self):
        async with self._red_lock:
            if self.red_default_pair is None:
                self.red_default_pair = create_red_agent_default()
            return self.red_default_pair

    async def get_red_advance(self):
        async with self._red_lock:
            if self.red_advance_pair is None:
                self.red_advance_pair = create_red_agent_advance()
            return self.red_advance_pair


state = _RuntimeState()


# --- Request Models ---

class BlueChatRequest(BaseModel):
    message: str = Field(default="")
    user_id: str = Field(default="demo_user")


class BurstRequest(BaseModel):
    user_id: str = Field(default="burst_user")
    count: int = Field(default=12, ge=1, le=50)


class RedAttackRequest(BaseModel):
    prompt: str = Field(..., min_length=1)
    target: str = Field(default="both")  # "both" | "red" | "red_advance"


class GuardrailsTestRequest(BaseModel):
    input_text: str = Field(default="")
    output_text: str = Field(default="")
    egress_url: str = Field(default="https://api.vinbank.example/v1/transfers")
    egress_payload: str = Field(default="approved transfer amount 500000")


class LiquidDecisionsRequest(BaseModel):
    state: str = Field(..., min_length=1)


# --- Routes ---

@app.get("/", response_class=HTMLResponse)
async def serve_index() -> str:
    html_path = Path(__file__).resolve().parent / "index.html"
    return html_path.read_text(encoding="utf-8")


@app.get("/api/status")
async def api_status() -> dict[str, Any]:
    state.monitor.check_metrics()
    return {
        "blue_provider": blue_provider_label(),
        "red_provider": red_provider_label(),
        "decisions_model": get_liquid_decisions_model(),
        "decisions_url": get_liquid_decisions_url(),
        "rate_limit_config": {
            "max_requests": state.rate_limiter.max_requests,
            "window_seconds": state.rate_limiter.window_seconds,
        },
        "metrics": state.monitor.snapshot(),
        "plugin_stats": {
            "rate_limiter_blocked": state.rate_limiter.blocked_count,
            "input_guard_blocked": state.input_guard.blocked_count,
            "output_guard_redacted": state.output_guard.redacted_count,
            "output_guard_blocked": state.output_guard.blocked_count,
        },
        "recent_logs": list(reversed(state.audit.logs[-30:])),
        "cp4_prompts": adversarial_prompts,
    }


@app.post("/api/blue/reset")
async def api_blue_reset() -> dict[str, Any]:
    state.reset_blue()
    return {"ok": True, "metrics": state.monitor.snapshot()}


@app.post("/api/blue/chat")
async def api_blue_chat(req: BlueChatRequest) -> dict[str, Any]:
    state.req_seq += 1
    req_id = f"ui-{state.req_seq}"
    user_id = (req.user_id or "demo_user").strip() or "demo_user"
    message = req.message or ""

    t0 = time.perf_counter()
    state.audit.record_input(user_id=user_id, text=message, request_id=req_id)

    trace = [
        {"step": "Rate Limiter", "status": "pending", "detail": ""},
        {"step": "Input Guardrail", "status": "pending", "detail": ""},
        {"step": "Blue LLM", "status": "pending", "detail": blue_provider_label()},
        {"step": "Output Guardrail", "status": "pending", "detail": ""},
    ]

    # Step 1: Per-user Rate Limiter
    ctx = SimpleNamespace(user_id=user_id)
    content = types.Content(role="user", parts=[types.Part.from_text(text=message)])
    rl_resp = await state.rate_limiter.on_user_message_callback(
        invocation_context=ctx, user_message=content
    )
    if rl_resp is not None:
        reply = rl_resp.parts[0].text if rl_resp.parts else "Rate limit exceeded."
        trace[0] = {"step": "Rate Limiter", "status": "blocked", "detail": reply}
        trace[1]["status"] = "skipped"
        trace[2]["status"] = "skipped"
        trace[3]["status"] = "skipped"
        state.monitor.total_requests += 1
        state.monitor.blocked_requests += 1
        state.monitor.rate_limit_hits += 1
        state.monitor.check_metrics()
        entry = state.audit.record_output(
            user_id=user_id, text=reply, blocked=True, layer="rate_limiter", request_id=req_id
        )
        return {
            "request_id": req_id,
            "reply": reply,
            "blocked": True,
            "layer": "rate_limiter",
            "latency_ms": entry["latency_ms"],
            "trace": trace,
            "metrics": state.monitor.snapshot(),
            "recent_logs": list(reversed(state.audit.logs[-30:])),
        }

    trace[0] = {
        "step": "Rate Limiter",
        "status": "passed",
        "detail": f"{len(state.rate_limiter.user_windows[user_id])}/{state.rate_limiter.max_requests} in {state.rate_limiter.window_seconds}s",
    }

    # Step 2–4: Input Guardrail -> Blue LLM -> Output Guardrail
    prev_ig = state.input_guard.blocked_count
    prev_og_red = state.output_guard.redacted_count
    prev_og_blk = state.output_guard.blocked_count

    try:
        reply, _ = await chat_with_agent(state.blue_agent, state.blue_runner, message)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Blue agent error: {exc}") from exc

    blocked = False
    layer = None

    if state.input_guard.blocked_count > prev_ig:
        blocked = True
        layer = "input_guardrail"
        inj = detect_injection(message)
        top = topic_filter(message)
        reason = "Empty input" if not message.strip() else (
            "Prompt injection detected" if inj == "BLOCK" else f"Topic filter blocked (topic={top})"
        )
        trace[1] = {"step": "Input Guardrail", "status": "blocked", "detail": reason}
        trace[2]["status"] = "skipped"
        trace[3]["status"] = "skipped"
    else:
        trace[1] = {"step": "Input Guardrail", "status": "passed", "detail": "Injection=ALLOW, Topic=ALLOW"}
        trace[2] = {"step": "Blue LLM", "status": "passed", "detail": blue_provider_label()}
        if state.output_guard.blocked_count > prev_og_blk:
            blocked = True
            layer = "output_guardrail"
            trace[3] = {"step": "Output Guardrail", "status": "blocked", "detail": "Blocked by safety check"}
        elif state.output_guard.redacted_count > prev_og_red:
            layer = "output_guardrail_redacted"
            trace[3] = {"step": "Output Guardrail", "status": "redacted", "detail": "PII / secret replaced with [REDACTED]"}
        else:
            trace[3] = {"step": "Output Guardrail", "status": "passed", "detail": "Clean output (no PII/secret)"}

    state.monitor.total_requests += 1
    if blocked:
        state.monitor.blocked_requests += 1
    state.monitor.check_metrics()

    entry = state.audit.record_output(
        user_id=user_id,
        text=reply,
        blocked=blocked,
        layer=layer,
        request_id=req_id,
    )
    return {
        "request_id": req_id,
        "reply": reply,
        "blocked": blocked,
        "layer": layer,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
        "trace": trace,
        "metrics": state.monitor.snapshot(),
        "recent_logs": list(reversed(state.audit.logs[-30:])),
    }


@app.post("/api/blue/burst")
async def api_blue_burst(req: BurstRequest) -> dict[str, Any]:
    """Run a fast sliding-window burst test against the live RateLimitPlugin."""
    user_id = (req.user_id or "burst_user").strip() or "burst_user"
    ctx = SimpleNamespace(user_id=user_id)
    msg = "What is my savings account balance?"
    content = types.Content(role="user", parts=[types.Part.from_text(text=msg)])
    passed = 0
    blocked = 0
    for _ in range(req.count):
        state.req_seq += 1
        req_id = f"burst-{state.req_seq}"
        state.audit.record_input(user_id=user_id, text=msg, request_id=req_id)
        resp = await state.rate_limiter.on_user_message_callback(
            invocation_context=ctx, user_message=content
        )
        state.monitor.total_requests += 1
        if resp is not None:
            blocked += 1
            state.monitor.blocked_requests += 1
            state.monitor.rate_limit_hits += 1
            state.audit.record_output(
                user_id=user_id,
                text=resp.parts[0].text if resp.parts else "Rate limit exceeded.",
                blocked=True,
                layer="rate_limiter",
                request_id=req_id,
            )
        else:
            passed += 1
            state.audit.record_output(
                user_id=user_id,
                text="Passed rate limiter",
                blocked=False,
                layer=None,
                request_id=req_id,
            )
    state.monitor.check_metrics()
    return {
        "user_id": user_id,
        "sent": req.count,
        "passed": passed,
        "blocked": blocked,
        "metrics": state.monitor.snapshot(),
        "recent_logs": list(reversed(state.audit.logs[-30:])),
    }


@app.post("/api/red/attack")
async def api_red_attack(req: RedAttackRequest) -> dict[str, Any]:
    results: dict[str, Any] = {"prompt": req.prompt, "provider": red_provider_label()}

    async def _run_target(kind: str):
        t0 = time.perf_counter()
        if kind == "red":
            agent, runner = await state.get_red_default()
            target_name = "red_default"
        else:
            agent, runner = await state.get_red_advance()
            target_name = "red_advance"
        try:
            reply, _ = await chat_with_agent(agent, runner, req.prompt)
            outcome = classify_attack_outcome(req.prompt, reply, target_name=target_name)
            return {
                "target": target_name,
                "response": reply,
                "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                **outcome,
            }
        except Exception as exc:
            return {
                "target": target_name,
                "response": f"Error: {exc}",
                "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                "leaked": False,
                "blocked_input": False,
                "blocked": False,
                "layer": "error",
                "blocked_at": f"ERROR — {type(exc).__name__}",
            }

    if req.target == "red":
        results["red"] = await _run_target("red")
    elif req.target == "red_advance":
        results["red_advance"] = await _run_target("red_advance")
    else:
        red_res, adv_res = await asyncio.gather(
            _run_target("red"), _run_target("red_advance")
        )
        results["red"] = red_res
        results["red_advance"] = adv_res

    return results


@app.post("/api/tools/guardrails")
async def api_tools_guardrails(req: GuardrailsTestRequest) -> dict[str, Any]:
    inj = detect_injection(req.input_text)
    top = topic_filter(req.input_text)
    out_res = content_filter(req.output_text)
    egress_ok = is_egress_allowed(req.egress_url, req.egress_payload)
    return {
        "input_check": {
            "injection": inj,
            "topic": top,
            "final": "BLOCK" if (inj == "BLOCK" or top == "BLOCK") else "ALLOW",
        },
        "output_check": out_res,
        "egress_check": {
            "destination": req.egress_url,
            "payload": req.egress_payload,
            "allowed": egress_ok,
        },
    }


@app.post("/api/liquid/decisions")
async def api_liquid_decisions(req: LiquidDecisionsRequest) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        data = await asyncio.to_thread(demo_triage, req.state)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Liquid Decisions error: {exc}") from exc
    return {
        "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
        "endpoint": get_liquid_decisions_url(),
        "data": data,
    }


@app.get("/api/artifacts")
async def api_artifacts() -> dict[str, Any]:
    out_dir = REPO_ROOT / "outputs"
    files = [
        "grade_report.json",
        "results.json",
        "attack_results.json",
        "metrics.json",
        "audit_log.json",
        "unsafe_attack_result.json",
        "guards_attack_result.json",
        "lab_report.md",
    ]
    payload: dict[str, Any] = {}
    for name in files:
        p = out_dir / name
        if not p.exists():
            payload[name] = None
            continue
        text = p.read_text(encoding="utf-8")
        if name.endswith(".json"):
            try:
                payload[name] = json.loads(text)
            except Exception:
                payload[name] = text
        else:
            payload[name] = text
    return payload


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
