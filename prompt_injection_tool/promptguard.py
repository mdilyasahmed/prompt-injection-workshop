from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class GuardDecision:
    allowed: bool
    risk_score: int
    reasons: list[str]
    rewritten_message: str | None = None


class PromptGuard:
    """
    Lightweight guard for demo purposes:
    - Canonicalizes input
    - Scores prompt-injection patterns
    - Applies simple policy actions (allow/block/rewrite)
    """

    BLOCK_PATTERNS = [
        r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
        r"reveal\s+(the\s+)?system\s+prompt",
        r"print\s+(the\s+)?hidden\s+rules",
        r"(exfiltrate|leak|dump)\s+(data|secrets|credentials)",
        r"developer\s+mode",
        r"bypass\s+(safety|policy|guardrail)",
    ]

    SUSPICIOUS_PATTERNS = [
        r"base64",
        r"roleplay",
        r"act\s+as",
        r"override",
        r"do\s+anything\s+now",
    ]

    def __init__(self, block_threshold: int = 70, rewrite_threshold: int = 40) -> None:
        self.block_threshold = block_threshold
        self.rewrite_threshold = rewrite_threshold

    def normalize(self, text: str) -> str:
        compact = text.strip().lower()
        compact = re.sub(r"\s+", " ", compact)
        return compact

    def inspect_message(self, message: str) -> GuardDecision:
        msg = self.normalize(message)
        reasons: list[str] = []
        risk = 0

        for pattern in self.BLOCK_PATTERNS:
            if re.search(pattern, msg, re.IGNORECASE):
                risk += 35
                reasons.append(f"matched_block_pattern:{pattern}")

        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, msg, re.IGNORECASE):
                risk += 10
                reasons.append(f"matched_suspicious_pattern:{pattern}")

        if risk >= self.block_threshold:
            return GuardDecision(allowed=False, risk_score=min(risk, 100), reasons=reasons)

        if risk >= self.rewrite_threshold:
            rewritten = self.rewrite_prompt(message)
            return GuardDecision(
                allowed=True,
                risk_score=min(risk, 100),
                reasons=reasons + ["action:rewrite"],
                rewritten_message=rewritten,
            )

        return GuardDecision(allowed=True, risk_score=min(risk, 100), reasons=reasons or ["no_match"])

    def rewrite_prompt(self, message: str) -> str:
        # Minimal defensive rewrite: strip common override phrases.
        cleaned = re.sub(
            r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions[.,;:!\s-]*",
            "",
            message,
        )
        cleaned = re.sub(r"(?i)reveal\s+(the\s+)?system\s+prompt[.,;:!\s-]*", "", cleaned)
        cleaned = cleaned.strip()
        if not cleaned:
            cleaned = "Please help with a safe, policy-compliant answer to my request."
        return cleaned

    def validate_tool_call(self, role: str, tool_name: str, args: dict[str, Any]) -> GuardDecision:
        """Simple RBAC + argument checks for demo."""
        role = role.lower()
        sensitive_tools = {"email_send", "db_write", "admin_exec"}

        reasons: list[str] = []
        risk = 0

        if tool_name in sensitive_tools and role not in {"admin", "security"}:
            risk += 80
            reasons.append("rbac_denied:sensitive_tool")

        if tool_name == "email_send" and "to" in args and str(args.get("to", "")).endswith("@external.com"):
            risk += 30
            reasons.append("exfil_risk:external_recipient")

        if risk >= self.block_threshold:
            return GuardDecision(allowed=False, risk_score=min(risk, 100), reasons=reasons)

        return GuardDecision(allowed=True, risk_score=min(risk, 100), reasons=reasons or ["tool_call_allowed"])

