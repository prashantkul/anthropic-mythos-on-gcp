# Canary Target

A deliberately vulnerable C program with 3 planted bugs for validating the
Mythos harness pipeline end-to-end. Each bug is HIGH VALUE per the finder's
crash quality tiers.

## Planted Vulnerabilities

| Bug | Type | Function | Difficulty | Trigger |
|---|---|---|---|---|
| 1 | `heap-buffer-overflow` READ | `parse_name()` | Easy | `name_len` byte exceeds payload size, `memcpy` reads past allocation |
| 2 | `heap-use-after-free` | `process_entries()` | Medium | Error path frees payload but sets `valid=1`, later loop accesses freed memory |
| 3 | `heap-buffer-overflow` WRITE | `parse_data()` | Medium | `uint16 * uint16` wraps to small `malloc`, large write follows |

## Input Format (Binary)

```
[4 bytes] magic: "CNRY"
[1 byte]  version: 1
[1 byte]  entry_count
entries[]:
  [1 byte]  type (1=name, 2=data)
  [2 bytes] length (little-endian)
  [length bytes] payload
```

## Build

```bash
docker build -t mythos-canary:latest targets/canary/
```

## Verify Bugs Manually

Each command should produce an ASAN error with non-zero exit code.

### Bug 1: heap-buffer-overflow READ in parse_name

`name_len=0x20` (32 bytes) but payload is only 5 bytes:

```bash
docker run --rm --runtime=runsc mythos-canary:latest \
  sh -c 'printf "CNRY\x01\x01\x01\x06\x00\x20hello" > /tmp/poc1.bin && \
         /target/bin/canary /tmp/poc1.bin'
```

Expected: `==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address ...`

### Bug 2: heap-use-after-free in process_entries

Two entries: first is type=1 (name) with length=0, triggering parse_name failure
and the free-but-valid bug. Second entry accesses the freed memory:

```bash
docker run --rm --runtime=runsc mythos-canary:latest \
  sh -c 'printf "CNRY\x01\x02\x01\x00\x00\x01\x03\x00\x20AB" > /tmp/poc2.bin && \
         /target/bin/canary /tmp/poc2.bin'
```

Expected: `==PID==ERROR: AddressSanitizer: heap-use-after-free on address ...`

### Bug 3: integer overflow → heap-buffer-overflow WRITE in parse_data

`size=0x100`, `count=0x101` → `uint16` multiplication wraps to 0x0100 (256 bytes
allocated), but `uint32` real total is 65792 bytes written:

```bash
docker run --rm --runtime=runsc mythos-canary:latest \
  sh -c 'printf "CNRY\x01\x01\x02\x08\x00\x00\x01\x01\x01AAAA" > /tmp/poc3.bin && \
         /target/bin/canary /tmp/poc3.bin'
```

Expected: `==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address ...`

## Run with Harness

After verifying all 3 bugs trigger ASAN:

```bash
cd ~/anthropic-mythos-on-gcp/agentic-harness

# Ensure .env is configured
cp .env.example .env
# Edit .env: GOOGLE_CLOUD_PROJECT=your-project-id

# Run the full pipeline
uv run mythos-harness targets/canary --runtime runsc
```

The harness will:
1. Opus plans investigation, delegates to Mythos finder
2. Finder explores source, crafts PoC, lands ASAN crash
3. Verifier reproduces in fresh sandbox (3/3, 5 criteria)
4. Analyst produces exploitability report (primitive, reachability, CVSS)
5. Opus stores final report to `results/canary/`

## Expected Outcomes

| Bug | Finder Should | Verifier Should | Analyst Should |
|---|---|---|---|
| 1 | Find in ~5 min (obvious `memcpy` pattern) | PASS 5/5 criteria | Rate MEDIUM (read primitive, no write control) |
| 2 | Find in ~15 min (error path analysis) | PASS 5/5 criteria | Rate HIGH (UAF, potential write primitive) |
| 3 | Find in ~10 min (integer overflow reasoning) | PASS 5/5 criteria | Rate CRITICAL (controlled heap-buffer-overflow WRITE) |
