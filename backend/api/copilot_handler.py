"""
copilot_handler.py — CopilotKit runtime endpoint.

Proxies CopilotKit chat messages through the Fathom 3-phase orchestrator.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any, Optional

copilot_router = APIRouter()


class CopilotMessage(BaseModel):
    role: str  # "user" | "assistant" | "system"
    content: str


class CopilotRequest(BaseModel):
    messages: list[CopilotMessage]
    actions: Optional[list[dict[str, Any]]] = None


class CopilotResponse(BaseModel):
    message: CopilotMessage
    sources: list[str] = []


@copilot_router.post("/copilot")
async def copilot_endpoint(req: CopilotRequest):
    """
    CopilotKit runtime endpoint.

    Receives chat messages from the Next.js CopilotSidebar,
    runs them through the Fathom orchestrator, and returns the response.
    """
    user_message = ""
    history: list[dict] = []

    for msg in req.messages:
        if msg.role == "user":
            user_message = msg.content
        elif msg.role == "assistant" and history:
            history[-1]["bot"] = msg.content
        if msg.role == "user":
            history.append({"user": msg.content, "bot": ""})

    if not user_message:
        return CopilotResponse(
            message=CopilotMessage(role="assistant", content="Please provide a message."),
        )

    try:
        from agent.orchestrator import run_investigation
        response_text = run_investigation(
            query=user_message,
            cape_context="",
            history=history[:-1],  # exclude current turn
        )
    except Exception:
        from llm.inference import generate
        result = generate(query=user_message)
        response_text = result.text

    return CopilotResponse(
        message=CopilotMessage(role="assistant", content=response_text),
    )
