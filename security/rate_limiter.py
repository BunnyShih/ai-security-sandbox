"""
Rate Limiter & Request Validator
==================================
Token-bucket rate limiting per user/session.
Input size, type, and structure validation.
"""

import time
import hashlib
from dataclasses import dataclass, field
from collections import defaultdict

# ── Config ────────────────────────────────────────────────────────────────────
MAX_INPUT_CHARS   = 4_000     # max characters per request
MAX_TOKENS_PER_MIN = 10       # requests per minute per user
MAX_SESSIONS      = 1_000     # max concurrent tracked sessions

@dataclass
class RateBucket:
    tokens:     float = field(default_factory=lambda: float(MAX_TOKENS_PER_MIN))
    last_refill: float = field(default_factory=time.time)

_buckets: dict[str, RateBucket] = defaultdict(RateBucket)

def _session_key(user_id: str) -> str:
    return hashlib.sha256(user_id.encode()).hexdigest()[:16]

def check_rate_limit(user_id: str) -> tuple[bool, str]:
    """
    Token-bucket rate limiter.
    Returns (allowed: bool, reason: str).
    """
    key = _session_key(user_id)
    now = time.time()
    bucket = _buckets[key]

    # Refill tokens (1 token per 6 seconds → 10/min)
    elapsed = now - bucket.last_refill
    bucket.tokens = min(MAX_TOKENS_PER_MIN, bucket.tokens + elapsed / 6.0)
    bucket.last_refill = now

    if bucket.tokens >= 1.0:
        bucket.tokens -= 1.0
        return True, "ok"
    else:
        wait = round(6.0 - elapsed, 1)
        return False, f"Rate limit exceeded. Retry in {wait}s."

@dataclass
class ValidationResult:
    valid:   bool
    reason:  str

def validate_request(payload: dict) -> ValidationResult:
    """
    Validate incoming request structure and content size.
    """
    if not isinstance(payload, dict):
        return ValidationResult(False, "Payload must be a JSON object.")

    message = payload.get("message", "")
    if not isinstance(message, str):
        return ValidationResult(False, "Field 'message' must be a string.")

    if len(message) == 0:
        return ValidationResult(False, "Message cannot be empty.")

    if len(message) > MAX_INPUT_CHARS:
        return ValidationResult(
            False,
            f"Message too long: {len(message)} chars (max {MAX_INPUT_CHARS})."
        )

    # Disallow binary / non-printable characters
    non_printable = sum(1 for c in message if ord(c) < 32 and c not in "\n\r\t")
    if non_printable > 5:
        return ValidationResult(False, "Message contains disallowed control characters.")

    return ValidationResult(True, "ok")
