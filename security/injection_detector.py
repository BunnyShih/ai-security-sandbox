"""
Prompt Injection & Jailbreak Detector
======================================
Detects attempts to override system instructions, extract secrets,
or manipulate AI behaviour through malicious user input.

This is the first line of defense before any input reaches the LLM.
"""

import re
from dataclasses import dataclass
from enum import Enum

class ThreatLevel(Enum):
    SAFE    = "SAFE"
    LOW     = "LOW"
    MEDIUM  = "MEDIUM"
    HIGH    = "HIGH"
    BLOCKED = "BLOCKED"

@dataclass
class ScanResult:
    level:       ThreatLevel
    triggered:   list[str]
    sanitized:   str
    blocked:     bool

# ── Injection pattern library ─────────────────────────────────────────────────
PATTERNS = {
    "system_override": (ThreatLevel.BLOCKED, [
        r"ignore (all |previous |prior |above |system )?instructions?",
        r"disregard (your |the )?(system |previous |prior )?prompt",
        r"forget (everything|all|your instructions)",
        r"you are now",
        r"act as (if you are|a|an)",
        r"pretend (you are|to be)",
        r"new (persona|role|identity|mode)",
        r"developer mode",
        r"jailbreak",
        r"DAN mode",
    ]),
    "secret_extraction": (ThreatLevel.HIGH, [
        r"(show|print|reveal|display|output|return|tell me|what is|repeat).{0,30}(system prompt|instructions|api key|secret|password|token|config)",
        r"what (were you|are you) told",
        r"repeat (your|the) (instructions|prompt|system)",
    ]),
    "role_manipulation": (ThreatLevel.MEDIUM, [
        r"you (must|should|have to|need to) (always|never|only)",
        r"from now on",
        r"your (new|real|true|actual) (purpose|goal|task|mission)",
        r"override",
        r"bypass",
        r"(ignore|skip) (safety|security|filter|restriction|guideline)",
    ]),
    "encoding_evasion": (ThreatLevel.MEDIUM, [
        r"base64",
        r"rot13",
        r"hex decode",
        r"\\u[0-9a-fA-F]{4}",   # unicode escapes
        r"&#x?[0-9a-fA-F]+;",   # HTML entities
    ]),
    "data_exfiltration": (ThreatLevel.HIGH, [
        r"(send|post|fetch|curl|http|upload).{0,40}(data|result|output|response)",
        r"(email|webhook|endpoint|url).{0,20}(send|post|forward)",
    ]),
}

def _compile(patterns: list[str]):
    return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]

COMPILED = {
    category: (level, _compile(patterns))
    for category, (level, patterns) in PATTERNS.items()
}

_SEVERITY = {
    ThreatLevel.SAFE: 0,
    ThreatLevel.LOW: 1,
    ThreatLevel.MEDIUM: 2,
    ThreatLevel.HIGH: 3,
    ThreatLevel.BLOCKED: 4,
}

def scan(text: str) -> ScanResult:
    """
    Scan user input for injection attempts.
    Returns ScanResult with threat level and triggered categories.
    """
    triggered = []
    max_level = ThreatLevel.SAFE

    for category, (level, compiled) in COMPILED.items():
        for pattern in compiled:
            if pattern.search(text):
                triggered.append(category)
                if _SEVERITY[level] > _SEVERITY[max_level]:
                    max_level = level
                break  # one hit per category is enough

    blocked = max_level == ThreatLevel.BLOCKED
    sanitized = "[INPUT BLOCKED]" if blocked else _strip_known(text)

    return ScanResult(
        level=max_level,
        triggered=triggered,
        sanitized=sanitized,
        blocked=blocked,
    )

def _strip_known(text: str) -> str:
    """Light sanitisation for non-blocked inputs."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.sub(r"<script.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
    return text.strip()
