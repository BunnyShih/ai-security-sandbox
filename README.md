# AI Security Sandbox

> A production-grade security layer for enterprise AI deployments — defending against prompt injection, jailbreaks, DoS attacks, and data exfiltration in one pipeline.

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![Security](https://img.shields.io/badge/Security-Enterprise-red) ![Claude API](https://img.shields.io/badge/Claude-API-orange)

---

## The Problem

Deploying AI in an enterprise means exposing a powerful language model to untrusted user input. Without a proper security layer, attackers can:

- **Prompt inject** — override system instructions to change AI behaviour
- **Jailbreak** — manipulate the AI into ignoring its safety rules
- **Extract secrets** — trick the AI into revealing API keys or configs
- **DoS** — flood the API with oversized requests to exhaust token budgets

This project implements a multi-layer defense sandbox that sits between your users and the LLM.

---

## Architecture

```
User Input
    │
    ▼
┌─────────────────────────────────────────┐
│  Layer 1 — Request Validation           │
│  • Size limit (max 4,000 chars)         │
│  • Structure check (valid JSON/string)  │
│  • Control character detection          │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│  Layer 2 — Rate Limiter                 │
│  • Token-bucket (10 req/min per user)   │
│  • Per-session tracking (hashed IDs)    │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│  Layer 3 — Injection Scanner            │
│  • System override detection            │
│  • Jailbreak pattern matching           │
│  • Secret extraction attempts           │
│  • Encoding evasion (base64, unicode)   │
│  • Data exfiltration patterns           │
│  → BLOCKED / HIGH / MEDIUM / LOW / SAFE │
└────────────────┬────────────────────────┘
                 │ (safe input only)
                 ▼
┌─────────────────────────────────────────┐
│  Layer 4 — Hardened AI Execution        │
│  • Server-side system prompt injection  │
│  • System prompt never exposed to users │
│  • Max output token budget enforced     │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│  Layer 5 — Output Filter                │
│  • API key pattern redaction            │
│  • Bearer token redaction               │
│  • ID / credit card number redaction    │
└────────────────┬────────────────────────┘
                 │
                 ▼
           Safe Response
           + Audit Log Entry
```

---

## Threat Coverage

| Attack Type | Detection Method | Action |
|---|---|---|
| Prompt injection | Regex pattern library | BLOCKED |
| Jailbreak (DAN, etc.) | Role/persona override patterns | BLOCKED |
| System prompt extraction | Secret extraction patterns | FLAGGED/BLOCKED |
| DoS via oversized input | Size validation | BLOCKED |
| Rate flooding | Token-bucket limiter | BLOCKED |
| Encoding evasion | Base64 / unicode pattern scan | FLAGGED |
| Data exfiltration | HTTP/webhook patterns | FLAGGED |
| Credential leak in output | Output redaction layer | REDACTED |

---

## Quick Start

```bash
git clone https://github.com/BunnyShih/ai-security-sandbox
cd ai-security-sandbox

python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

pip install -r requirements.txt

# Demo mode (no API key needed)
python main.py

# Live mode with Claude
export ANTHROPIC_API_KEY=sk-ant-...
python main.py
```

---

## Sample Output

```
[1/7] ✅ SAFE — Normal business query
  Status:  OK  |  Threat: SAFE

[2/7] 🔴 ATTACK — Jailbreak (DAN mode)
  Status:  BLOCKED
  Blocked by: injection
  Detail:  Threat detected: ['system_override']

[7/7] 🔴 ATTACK — Input too long (DoS)
  Status:  BLOCKED
  Blocked by: validation
  Detail:  Message too long: 5001 chars (max 4000)

📊 Sandbox Audit Summary
  Total: 7  |  Allowed: 5  |  Blocked: 2
```

---

## Project Structure

```
ai-security-sandbox/
├── security/
│   ├── injection_detector.py  # Pattern library, threat classification
│   └── rate_limiter.py        # Token-bucket rate limiting, input validation
├── sandbox/
│   └── executor.py            # Orchestrates all layers, calls Claude API
├── main.py                    # Demo runner with 7 attack simulations
└── README.md
```

---

## Skills Demonstrated

| Skill | Implementation |
|---|---|
| **Strict AI Security** | 5-layer defense pipeline, threat classification |
| **Sandbox Control** | Isolated execution, hardened system prompt, output filtering |
| **Enterprise Thinking** | Audit logging, rate limiting, per-user session tracking |

---

## Extending This Project

- **Add patterns**: extend `PATTERNS` dict in `injection_detector.py`
- **Adjust limits**: tune `MAX_INPUT_CHARS` / `MAX_TOKENS_PER_MIN` in `rate_limiter.py`
- **Persist audit log**: pipe `get_sandbox_log()` to a database or SIEM
- **Add IP blocking**: extend rate limiter with IP-based blacklist

---

## License

MIT
