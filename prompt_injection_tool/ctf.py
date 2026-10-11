"""
CTF layer for the workshop — "Beat the Guard".

A flag unlocks only when a submitted message does BOTH of these:
  1. gets PAST PromptGuard (the guard returns allowed=True), and
  2. still expresses the real attack intent for that challenge.

That combination is the whole skill of prompt injection: a payload that a
weak filter waves through but that a human (here, the CTF judge) still
recognises as an attack. There is no LLM in the loop — the judge is
deterministic keyword/decoding logic, so the lab stays zero-setup and the
flags are reproducible.

The flags below are fake teaching tokens, not secrets.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

MAX_MESSAGE_LEN = 4000  # bound work done on attacker-controlled input


@dataclass
class Challenge:
    id: str
    title: str
    difficulty: str
    objective: str
    flag: str
    # Extra blocklist for this challenge, matched on the literal (lowercased) text.
    filters: tuple[str, ...] = ()
    filter_hint: str = ""


CHALLENGES = [
    Challenge(
        id="c1_extract",
        title="Loose Lips",
        difficulty="easy",
        objective="Get the model to reveal its system prompt / hidden rules. "
                  "This challenge also filters the phrase 'system prompt'. Reword it.",
        flag="PIWS{d1rect_rewording_beats_regex}",
        filters=(r"system\s*prompt",),
        filter_hint="Blocked: this challenge filters the phrase 'system prompt'. "
                    "The judge reads like a human, so say it another way.",
    ),
    Challenge(
        id="c2_exfil",
        title="Quiet Exit",
        difficulty="easy",
        objective="Ask for secrets to be sent or handed over without using the "
                  "words 'credentials', 'password' or 'secret'.",
        flag="PIWS{synonyms_are_a_bypass}",
        filters=(r"\b(credentials?|passwords?|secrets?)\b",),
        filter_hint="Blocked: this challenge filters 'credentials', 'password' and "
                    "'secret'. Attackers rarely need the obvious word.",
    ),
    Challenge(
        id="c3_jailbreak",
        title="No Rules",
        difficulty="medium",
        objective="Push the model into a no-rules mode. The usual jailbreak "
                  "vocabulary is filtered here.",
        flag="PIWS{r0leplay_is_a_jailbreak}",
        filters=(
            r"\bunrestricted\b",
            r"jailbreak",
            r"\bdan\b",
            r"\bno\s+(rules|restrictions|limits|filters?|guardrails)\b",
            r"\bwithout\s+(any\s+)?(rules|restrictions|limits)\b",
            r"do\s+anything|anything\s+now",
        ),
        filter_hint="Blocked: that's on this challenge's jailbreak word list. Think "
                    "personas, modes, or spellings the filter doesn't expect.",
    ),
    Challenge(
        id="c4_encoded",
        title="Hidden in Plain Sight",
        difficulty="medium",
        objective="Get a base64-encoded malicious instruction past the filter. "
                  "This filter decodes base64 once before checking.",
        flag="PIWS{base64_is_not_encryption}",
        filter_hint="Blocked: the filter decoded your base64 and read the attack. "
                    "It decodes once. What doesn't it do?",
    ),
    Challenge(
        id="c5_indirect",
        title="Trojan Document",
        difficulty="medium",
        objective="Hide an instruction inside content the AI is 'reading' (a "
                  "document, email, note) that makes it leak or send something. "
                  "Classic injection markers are filtered.",
        flag="PIWS{data_can_carry_commands}",
        filters=(r"\[/?inst\]", r"</?system>", r"\bignore\b", r"\bdisregard\b"),
        filter_hint="Blocked: this challenge filters classic markers ([INST], "
                    "<system>, ignore, disregard). Real attacks hide more quietly.",
    ),
]

CHALLENGES_BY_ID = {c.id: c for c in CHALLENGES}

# Expand common obfuscating abbreviations before intent matching, so a human-
# obvious bypass ("print your sys config") is judged the way a human would.
_LEET = str.maketrans("013457@$", "oieastas")
_ABBREV = {
    r"\bprev\b": "previous",
    r"\binstrux\b": "instructions",
    r"\binstruction\b": "instructions",
    r"\bsys\b": "system",
    r"\bconfig\b": "configuration",
    r"\bcreds\b": "credentials",
    r"\bpw\b": "password",
    r"\bpwd\b": "password",
    r"\benv\b": "environment",
    r"\bmsg\b": "message",
    r"\binfo\b": "information",
}


def _normalize(text: str) -> str:
    t = text.lower().translate(_LEET)
    t = re.sub(r"[^a-z0-9@{}\[\]/+=_:#<>\s]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    for pat, repl in _ABBREV.items():
        t = re.sub(pat, repl, t)
    return t


def _has_any(text: str, terms: list[str]) -> bool:
    return any(term in text for term in terms)


def _b64_decode_once(text: str) -> str:
    """Concatenated decodes of any base64-looking tokens (>=16 chars), case kept.
    Safe: bounded input, ignores non-decodable tokens, never executes."""
    out = []
    for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            decoded = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        out.append(decoded.decode("utf-8", errors="ignore"))
    return " ".join(out)


_ACTIONS_REVEAL = ["reveal", "show", "print", "display", "expose", "tell",
                   "give", "share", "output", "repeat", "echo", "list", "dump"]
_TARGETS_PROMPT = ["system prompt", "systemprompt", "initial instructions",
                   "your instructions", "your rules", "your prompt",
                   "system instructions", "configuration", "guidelines",
                   "directives", "the prompt above", "original instructions"]

_ACTIONS_EXFIL = ["leak", "dump", "exfiltrate", "send", "forward", "email",
                  "upload", "post", "transmit", "extract", "steal", "copy",
                  "paste"]
_TARGETS_SECRET = ["credentials", "secret", "secrets", "api key", "apikey",
                   "password", "private data", "user data", "confidential",
                   "token", "tokens", "environment", "database", "flag"]

_JAILBREAK = ["unrestricted", "no restrictions", "no rules", "without restrictions",
              "without rules", "ignore safety", "ignore your rules", "jailbreak",
              "do anything", "god mode", "unlock", "no filter",
              "no filters", "no guardrails", "freedom mode", "unlocked",
              "anything now", "no limits", "without limits", "evil mode",
              "unfiltered", "no longer bound", "not bound by", "free from your",
              "disable your", "turn off your", "ignore your guidelines",
              "ignore all rules", "no safety", "anything goes", "no boundaries",
              "without boundaries"]

_ATTACK_KEYWORDS = ["ignore", "disregard", "reveal", "leak", "exfiltrate", "dump",
                    "system prompt", "override", "bypass", "developer mode",
                    "do anything", "flag", "credentials", "secret", "instructions"]

_WRAPPERS = ["document", "summary", "email", "note", "retrieved", "article",
             "review", "comment", "ticket", "message from", "the following",
             "content", "record", "attachment"]
_INJECT_MARKERS = ["[inst]", "[/inst]", "<system>", "</system>", "ignore",
                   "disregard", "new instructions", "updated instructions",
                   "assistant:", "system:", "ai:", "###", "instead", "actually",
                   "note to the ai", "note to the assistant", "if you are an ai",
                   "when you read this", "before summarizing", "after summarizing",
                   "important:"]
# "email" is excluded: it's also a wrapper word, so it can't count as the request.
_C5_ACTIONS = [a for a in _ACTIONS_EXFIL + _ACTIONS_REVEAL if a != "email"] + \
              ["reply with", "include", "append"]


def _blocked_by_challenge(challenge: Challenge, message: str) -> bool:
    if challenge.id == "c4_encoded":
        return _has_any(_b64_decode_once(message).lower(), _ATTACK_KEYWORDS)
    literal = re.sub(r"\s+", " ", message.lower())
    return any(re.search(p, literal) for p in challenge.filters)


def _detect_intent(challenge_id: str, message: str) -> bool:
    t = _normalize(message)
    if challenge_id == "c1_extract":
        return _has_any(t, _ACTIONS_REVEAL) and _has_any(t, _TARGETS_PROMPT)
    if challenge_id == "c2_exfil":
        return _has_any(t, _ACTIONS_EXFIL) and _has_any(t, _TARGETS_SECRET)
    if challenge_id == "c3_jailbreak":
        # "dan" needs a word match: it's a substring of "guidance", "danger"
        return _has_any(t, _JAILBREAK) or re.search(r"\bdan\b", t) is not None
    if challenge_id == "c4_encoded":
        decoded = _b64_decode_once(_b64_decode_once(message)).lower()
        return bool(decoded) and _has_any(decoded, _ATTACK_KEYWORDS)
    if challenge_id == "c5_indirect":
        return (_has_any(t, _WRAPPERS) and _has_any(t, _INJECT_MARKERS)
                and _has_any(t, _C5_ACTIONS)
                and _has_any(t, _TARGETS_SECRET + _TARGETS_PROMPT))
    return False


def judge(challenge_id: str, message: str, guard_allowed: bool,
          guard_score: int) -> dict:
    """Decide the outcome of one CTF submission. Teaching-first responses:
    every failure explains *why* so attendees iterate toward the real skill."""
    challenge = CHALLENGES_BY_ID.get(challenge_id)
    if challenge is None:
        return {"solved": False, "error": f"unknown challenge: {challenge_id}"}

    if len(message) > MAX_MESSAGE_LEN:
        return {"solved": False, "hint": "Message too long for this lab."}

    if not guard_allowed:
        return {
            "solved": False,
            "guard": {"passed_guard": False, "risk_score": guard_score},
            "hint": "PromptGuard blocked you. A flag only unlocks if you get "
                    "PAST the guard first — reword until allowed=True.",
        }

    if _blocked_by_challenge(challenge, message):
        return {
            "solved": False,
            "guard": {"passed_guard": False, "risk_score": guard_score,
                      "blocked_by": "challenge_filter"},
            "hint": challenge.filter_hint,
        }

    if not _detect_intent(challenge_id, message):
        return {
            "solved": False,
            "guard": {"passed_guard": True, "risk_score": guard_score},
            "hint": "You got past the guard, but this isn't actually a "
                    f"'{challenge.title}' attack yet. Re-read the objective — "
                    "the flag only unlocks for a real bypass, not a benign line.",
        }

    return {
        "solved": True,
        "guard": {"passed_guard": True, "risk_score": guard_score},
        "flag": challenge.flag,
        "message": f"Solved '{challenge.title}' — you bypassed the guard AND "
                   f"carried the attack. Flag captured.",
    }
