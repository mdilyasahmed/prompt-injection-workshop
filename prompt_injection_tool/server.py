from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from promptguard import PromptGuard
from ctf import CHALLENGES, judge

app = FastAPI(title="PromptGuard Demo API", version="1.0.0")
guard = PromptGuard()


class ChatRequest(BaseModel):
    user_id: str = Field(..., examples=["alice"])
    role: str = Field(..., examples=["analyst"])
    message: str


class ToolCallRequest(BaseModel):
    user_id: str
    role: str
    tool_name: str
    args: dict


class CtfRequest(BaseModel):
    challenge: str = Field(..., examples=["c1_extract"])
    message: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


def mock_llm_response(prompt: str) -> str:
    # Controlled mock response for demo.
    return f"Model response (sanitized flow): {prompt[:220]}"


@app.post("/chat")
def chat(req: ChatRequest) -> dict:
    decision = guard.inspect_message(req.message)
    if not decision.allowed:
        return {
            "allowed": False,
            "risk_score": decision.risk_score,
            "reasons": decision.reasons,
            "message": "Blocked by PromptGuard policy.",
        }

    safe_message = decision.rewritten_message or req.message
    response = mock_llm_response(safe_message)
    return {
        "allowed": True,
        "risk_score": decision.risk_score,
        "reasons": decision.reasons,
        "rewritten": bool(decision.rewritten_message),
        "response": response,
    }


@app.post("/tool-call")
def tool_call(req: ToolCallRequest) -> dict:
    decision = guard.validate_tool_call(req.role, req.tool_name, req.args)
    if not decision.allowed:
        return {
            "allowed": False,
            "risk_score": decision.risk_score,
            "reasons": decision.reasons,
            "message": "Tool call blocked by policy.",
        }

    return {
        "allowed": True,
        "risk_score": decision.risk_score,
        "reasons": decision.reasons,
        "tool_execution": {
            "tool_name": req.tool_name,
            "args": req.args,
            "status": "simulated_success",
        },
    }


@app.get("/ctf/challenges")
def ctf_challenges() -> dict:
    return {
        "challenges": [
            {
                "id": c.id,
                "title": c.title,
                "difficulty": c.difficulty,
                "objective": c.objective,
            }
            for c in CHALLENGES
        ]
    }


@app.post("/ctf/submit")
def ctf_submit(req: CtfRequest) -> dict:
    decision = guard.inspect_message(req.message)
    return judge(req.challenge, req.message, decision.allowed, decision.risk_score)

