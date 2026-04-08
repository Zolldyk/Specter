# Specter

AI-augmented exploit completion for Ethereum smart contract security research.

Specter wraps SKANF — a state-of-the-art EVM bytecode vulnerability scanner — with an AI agent layer that activates precisely when SKANF stalls on symbolic constraints. When SKANF identifies a vulnerability but cannot generate a working exploit (multi-step CALL chains with chained parameter relationships that symbolic execution cannot resolve), Specter reasons through the constraints, proposes concrete calldata, and validates the result in a local EVM environment.

**Target users:** Smart contract security researchers (Sherlock, Code4rena) and in-house security engineers at DeFi protocols running pre-deployment reviews.

---

## How It Works

Specter runs a 4-stage pipeline:

```
[1/4] SKANF Docker analysis    →  detect vulnerability + attempt exploit
[2/4] Parse SKANF output       →  extract call_pc, type, selector, context  
[3/4] AI exploit generation    →  Claude / GPT-4o / Gemini proposes calldata
[4/4] EVM validation           →  re-run SKANF with agent calldata          
```

Stages 2–4 only activate when SKANF state is `STALLED` (symbolic constraints unresolved). If SKANF generates an exploit directly, Specter reports it immediately without calling the AI.

---

## Installation

Requires Python 3.10+, [uv](https://github.com/astral-sh/uv), and Docker.

```bash
git clone https://github.com/your-org/specter
cd specter
uv sync
```

---

## Quick Start

```bash
# Scan by contract address
specter scan 0xYourContractAddress

# Scan raw bytecode
specter scan 0x6080604052...

# JSON output (for CI/scripting)
specter scan 0xYourContractAddress --json

# Include full agent reasoning trace
specter scan 0xYourContractAddress --verbose

# Write report to file
specter scan 0xYourContractAddress --output report.md

# Verify environment before scanning
specter check

# Show version and pinned dependency info
specter version
```

---

## Environment Variables

All credentials are configured via environment variables — no config files.

### AI Provider (at least one required)

Specter checks in priority order: Anthropic → OpenAI → Gemini.

| Variable | Provider | Model |
|---|---|---|
| `ANTHROPIC_API_KEY` | Anthropic (primary) | `claude-sonnet-4-6` |
| `OPENAI_API_KEY` | OpenAI (fallback) | `gpt-4o` |
| `GEMINI_API_KEY` | Google Gemini (fallback) | `gemini-2.5-flash` |

### RPC & Metadata (optional, needed for address-based scans)

| Variable | Purpose |
|---|---|
| `ALCHEMY_RPC_URL` | Fetches bytecode via `eth_getCode`; checks live balance post-exploit |
| `ETHERSCAN_API_KEY` | Contract metadata enrichment (logged warning if absent) |

Run `specter check` to verify your environment before scanning.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean — no vulnerability detected, or SKANF detected but could not exploit |
| `1` | Validated exploit — confirmed vulnerability with working calldata |
| `2` | Agent-proposed, unvalidated — potential vulnerability, calldata not confirmed |
| `3` | Tool error — missing env var, Docker down, SKANF crash, parse failure, etc. |

This makes Specter composable in CI pipelines:

```bash
specter scan $CONTRACT --json > report.json
if [ $? -eq 1 ]; then
  echo "CRITICAL: validated exploit found"
  exit 1
fi
```

---

## Output

### Markdown (default)

```
# Specter Scan Report

| Field          | Value                          |
|----------------|-------------------------------|
| Contract       | 0x1234...abcd                 |
| Scan Timestamp | 2026-03-22T10:15:30Z          |
| SKANF Digest   | sha256:5ef029...              |
| Model Version  | claude-sonnet-4-6             |
| Runtime        | 42.3s                         |

## Finding: CONFIRMED VULNERABILITY

### Vulnerability Summary
...

### Exploit Calldata
{ "calldata": "0x...", "target_address": "0x...", "value": 0, ... }

### Validation Result
FULL_SUCCESS — Transfer event confirmed
```

Color output is auto-detected (TTY only): red for confirmed, amber for unconfirmed, green for clean.

### JSON (`--json`)

Stable schema across patch versions — safe to parse in scripts.

```json
{
  "contract_address": "0x...",
  "scan_timestamp": "2026-03-22T10:15:30.123456+00:00",
  "skanf_version_digest": "sha256:5ef029...",
  "model_version": "claude-sonnet-4-6",
  "validation_status": "validated_exploit",
  "finding": {
    "exploit_calldata": {
      "calldata": "0x...",
      "target_address": "0x...",
      "value": 0,
      "caller": "0x...",
      "origin": "0x..."
    },
    "validation_result": {
      "tier": "full_success",
      "live_balance": true,
      "validation_status": "validated_exploit"
    }
  },
  "runtime_seconds": 42.3,
  "error": null
}
```

`validation_status` values: `validated_exploit` | `agent_proposed_unvalidated` | `skanf_detected_unexploited` | `clean`

---

## Requirements

- Python 3.10+
- Docker (daemon running, SKANF image pulled)
- At least one AI provider API key
- `ALCHEMY_RPC_URL` for address-based scans (bytecode input works without it)

---

## Development

```bash
uv sync --dev

# Run tests
uv run pytest

# Lint + format
uv run ruff check .
uv run ruff format .

# Type checking
uv run mypy src/
```

---

## License

See [LICENSE](LICENSE).