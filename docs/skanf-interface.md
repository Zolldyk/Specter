# SKANF Container Interface Documentation

**Image:** `dockerofsyang/skanf@sha256:5ef0297fd41b8e7e94f8e4fdc0c0a0d135078db675e2017a81735c27c447c817`
**Base OS:** Ubuntu 20.04 (linux/amd64)
**WorkingDir:** `/opt/greed`
**Entrypoint:** none (default Cmd: `/bin/bash -l`)
**Conda env:** `greed` (Python 3.12, active by default)

---

## 1. Exact Docker Invocation Command

SKANF requires a **two-phase** pipeline. Both phases must run in the **same working directory** where the contract bytecode (`contract.hex`) is placed.

### Phase 1 — Gigahorse decompilation (static analysis)

```bash
docker run --rm \
  -v /host/workdir:/workdir \
  -w /workdir \
  dockerofsyang/skanf@sha256:5ef0297fd41b8e7e94f8e4fdc0c0a0d135078db675e2017a81735c27c447c817 \
  bash -c "analyze_hex.sh --file contract.hex --timeout 120"
```

**Input:** `contract.hex` — raw hex string of the contract runtime bytecode (no `0x` prefix).

**Output files written to workdir:**
- `vulnerability.json` — machine-readable vulnerability report (empty `[]` if clean)
- `vulnerability.csv` — TSV format of same data
- `proto_vulnerability.csv` — proto-vulnerabilities (detected CALL patterns before solver)
- `ArbitraryCall.csv` — detected arbitrary-call statements
- `TAC_Op.csv`, `TAC_Block.csv`, `TAC_Def.csv`, `TAC_Use.csv`, etc. — full TAC IR

**stdout:** `Running gigahorse.py\nYes` (on success)
**stderr:** empty (on success); error details on failure

**Timeout:** `--timeout N` sets the Datalog analysis timeout in seconds (default: 120).

### Phase 2 — greed symbolic execution

```bash
docker run --rm \
  -v /host/workdir:/workdir \
  dockerofsyang/skanf@sha256:5ef0297fd41b8e7e94f8e4fdc0c0a0d135078db675e2017a81735c27c447c817 \
  bash -c "greed /workdir [--find <callPC>] [--address <contract_address>]"
```

**CLI flags:**
- `target` (positional) — path to the Gigahorse output directory (same as workdir)
- `--find <statement_id>` — directed search: find path to the specific TAC statement (the vulnerable CALL). The statement_id is the `key_statement` value from `vulnerability.json` (e.g., `0x76`).
- `--address <0xADDR>` — pass the contract address as `ADDRESS` context (used for storage reads)
- `--partial-concrete-storage` — use on-chain storage values (requires `WEB3_PROVIDER` option)
- `-d / --debug` — enable DEBUG logging

**stdout:** empty (all logging goes to stderr)
**stderr:** Python logging output from greed (INFO/DEBUG/ERROR/FATAL level)

**Key log lines:**
- Clean / no-path: no output
- Stall (symbolic target): `INFO | greed.TAC.flow_ops | Calling contract <SYMBOLIC> (<block>_<ctx>)`
- Success (path found): `INFO | greed | Found State <N> at <callPC>`
- Success (calldata): `INFO | greed | CALLDATA: <hex_calldata_no_0x_prefix>`
- No path to target: `FATAL | greed | No paths found`

**Two stall modes that emit the same log line — distinguish via `vulnerability.json`:**
- **Free-exploration stall**: greed run *without* `--find`, `vulnerability.json` is `[]`. Greed
  reaches any symbolic CALL during unconstrained path exploration. This is captured in
  `tests/fixtures/skanf_stalled.txt`.
- **Validation-mode stall**: greed run *with* `--find <key_statement>`, `vulnerability.json`
  is non-empty. Greed is directed at the known vulnerable CALL but cannot concretize the
  target address (attacker-controlled symbolic). Story 2.4 parser uses `vulnerability.json`
  non-emptiness to set `SkfnState.STALLED` vs. `SkfnState.CLEAN`.

---

## 2. Bytecode Resolution Ownership — **SKANF does NOT fetch bytecode**

SKANF requires a pre-fetched bytecode hex file (`contract.hex`). It does **not** resolve
contract addresses from the chain itself.

**Evidence:**
- `analyze_hex.sh` accepts `--file contract.hex` (file input, not address)
- `resources/download_contract.py` is a *separate utility* for fetching bytecode via Web3:
  ```bash
  python3 download_contract.py --address 0xABC... --w3 ws://127.0.0.1:8545 --out contract.hex
  ```
- `greed`'s `--address` flag only sets the symbolic `ADDRESS` context variable for the EVM state — it does **not** fetch bytecode.

**Specter's responsibility:**
`runner.py` MUST fetch runtime bytecode from Alchemy via `eth_getCode(address, "latest")`
before invoking SKANF. The bytecode hex (stripped of `0x` prefix) is written to `contract.hex`
in the working directory.

---

## 3. Validation Mode Interface

"Validation mode" = running Phase 2 (greed) with the `--find <callPC>` flag targeting the
vulnerable CALL instruction identified by Phase 1.

**Two-pass validation flow:**

1. **Phase 1 (scan):** `analyze_hex.sh` detects proto-vulnerabilities statically.
   `vulnerability.json` contains entries like:
   ```json
   [
     {
       "vulnerability_type": "ArbitraryCall",
       "confidence": "HIGH",
       "visibility": "PUBLIC",
       "key_statement": "0x76",
       "key_selector": "0x1cff79cd",
       "debug_template": "...",
       "debug_arg0": "...", "debug_arg1": "...", "debug_arg2": "...", "debug_arg3": "..."
     }
   ]
   ```
   - `key_statement` = TAC statement ID of the vulnerable CALL opcode (this is the **callPC**)
   - `key_selector` = 4-byte function selector of the public entry point (e.g., `0x1cff79cd`)

2. **Phase 2 (validate):** `greed <workdir> --find <key_statement>` performs directed
   symbolic execution toward the CALL. Outcome:
   - **Success:** greed logs `CALLDATA: <hex>` — concrete exploit calldata found
   - **Stall:** greed logs `Calling contract <SYMBOLIC> (...)` — target remains symbolic
   - **No path:** greed logs `No paths found` (FATAL) — CALL unreachable

**Note:** Phase 2 can also run without `--find` (free exploration). In that mode, greed
explores all execution paths. The stall log (`Calling contract <SYMBOLIC>`) appears
whenever any CALL with a symbolic target is reached.

---

## 4. Container Lifecycle Decision — SINGLE CONTAINER INVOCATION (TWO-PHASE PIPELINE)

**Decision:** Each contract scan uses **one container invocation** that runs both phases
sequentially via a single `bash -c "..."` command, sharing an in-container working
directory mounted from the host.

**Rationale:**
- Phase 1 and Phase 2 are separate tools with different CLI interfaces
- Phase 1 writes CSV/JSON files that Phase 2 reads — the shared working directory is the
  communication channel between phases
- Running both in one container invocation is possible (via `bash -c "...phase1... && ...phase2..."`)
  but separating them allows independent timeout control per phase

**Lifecycle options:**

Option A (two invocations, one volume):
```bash
# Run 1: Gigahorse analysis
docker run --rm -v /workdir:/workdir ... bash -c "cd /workdir && analyze_hex.sh --file contract.hex"
# Run 2: greed symbolic execution (reads Phase 1 CSV outputs)
docker run --rm -v /workdir:/workdir ... bash -c "greed /workdir --find <callPC>"
```

Option B (single invocation, sequential phases):
```bash
docker run --rm -v /workdir:/workdir ... bash -c "
  cd /workdir
  analyze_hex.sh --file contract.hex --timeout 120
  greed /workdir --find \$(jq -r '.[0].key_statement' vulnerability.json) --address <addr>
"
```

**Specter's `runner.py` will use Option B** (single container invocation) to minimize
container startup overhead and simplify state management.

---

## Actual vs. Paper Output Format (Figure 3 Mapping)

The SKANF paper's Figure 3 shows a structured vulnerability report. The **actual greed
output does not produce a literal Figure 3 section.** Mapping:

| Paper Field              | Actual greed/SKANF output location              |
|--------------------------|--------------------------------------------------|
| callPC                   | `key_statement` in `vulnerability.json` (e.g., `0x76`) |
| symbolic calldata        | `<SYMBOLIC>` in greed log (stall), or concrete hex in `CALLDATA:` line (success) |
| tainted bytes            | NOT in output — internal to solver state         |
| controllability flags    | NOT in output — internal to solver state         |
| block height             | NOT in output unless `WEB3_PROVIDER` is set      |
| token balance            | NOT in output — symbolic `BALANCE_<xid>`         |
| contract address         | Passed via `--address` flag                      |

**Implication for SkfnContext:** The model fields must reflect what is *actually* parseable
from the real output, not the paper's idealized representation. See `src/specter/models.py`.

---

## Edge Cases and Quirks

1. **ARM64 hosts:** The image is `linux/amd64` only. On Apple Silicon (ARM64), Docker
   uses Rosetta 2 emulation. Certain instructions in the greed Python code trigger
   `AttributeError: 'dict' object has no attribute 'register'` for some contracts. Use
   `--platform linux/amd64` flag to ensure correct emulation.

2. **Statement IDs in greed vs. TAC_Op.csv:** `TAC_Op.csv` uses decimal-ish hex IDs
   (e.g., `0x76`). greed's `--find` flag uses the same IDs. The stall log shows
   `(block_decimal_context)` format (e.g., `134_1` = block 0x86, context 1), NOT the
   statement ID directly.

3. **vulnerability.json format:** The JSON output is a Souffle JSON array. Each entry
   contains a flat object with string values for all 12 fields. The `original_statement_list`
   and `function_list` fields are Souffle list-encoded strings (not JSON arrays).

4. **No network access needed:** Phase 1 (Gigahorse) and Phase 2 (greed without
   `--partial-concrete-storage`) run fully offline. Web3 is only needed for
   `--partial-concrete-storage` mode (uses `options.WEB3_PROVIDER`).

5. **Working directory pollution:** `analyze_hex.sh` writes ~100 CSV files to the working
   directory. Use a fresh temporary directory per contract scan.
