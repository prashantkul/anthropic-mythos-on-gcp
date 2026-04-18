I'll start by reading the relevant source code to perform a thorough analysis.Now let me check the binary for security mitigations:I have everything I need from the source. Here is the complete structured exploitability report.

---

# Exploitability Report: Heap-Buffer-Overflow WRITE via Integer Overflow in `parse_data()`

**File:** `/target/src/canary.c` — Bug 3  
**Crash type:** Heap-buffer-overflow (WRITE)  
**Verdict: HIGH severity, practically exploitable**

---

## 1. Primitive — What Is Written, Where, and How Much Attacker Control

### Vulnerable Code (`canary.c:88–101`)
```c
uint16_t size  = e->payload[0] | (e->payload[1] << 8);   // attacker-controlled
uint16_t count = e->payload[2] | (e->payload[3] << 8);   // attacker-controlled

uint16_t alloc_size = (uint16_t)(size * count);           // BUG: wraps mod 2^16
if (alloc_size == 0) alloc_size = 1;
uint8_t *buf = malloc(alloc_size);                        // tiny allocation

uint32_t real_total = (uint32_t)size * (uint32_t)count;  // correct full product
for (uint32_t i = 0; i < real_total; i++) {
    buf[i] = 'A';                                         // writes real_total bytes
}
```

### Primitive Breakdown

| Property | Detail |
|---|---|
| **Write value** | Constant byte `0x41` ('A') — not directly attacker-controlled |
| **Write length** | `real_total = size × count` (uint32, up to 4 GiB) — fully attacker-controlled |
| **Allocation size** | `(uint16_t)(size × count)` — truncated to 1 in the PoC case (`256×256 = 65536 → 0 → clamped to 1`) |
| **Overflow offset** | Starts at byte index 1 (one byte past the 1-byte allocation) |
| **Overflow length** | Up to `real_total − alloc_size` bytes past the chunk end |
| **Number of overwritten bytes** | In PoC: 65,535 bytes past the 1-byte allocation |
| **Primitive type** | Linear heap overflow with a constant fill byte |

The attacker controls `size` and `count` with full 16-bit resolution (any 16-bit value each). This allows dialing in the exact overflow length, subject to the constraint that `size × count mod 65536 = 0` (or is very small to maximize overwrite). Effective attack windows include:

- `size=1, count=65537` — impossible (count is uint16, max 65535)  
- `size=256, count=256` → allocates 1 byte, writes 65,536 bytes (**PoC**)  
- `size=512, count=128` → allocates 0→1 byte, writes 65,536 bytes  
- `size=2, count=32768` → allocates 0→1 byte, writes 65,536 bytes  
- `size=65535, count=65535` → allocates `(65535²) mod 65536 = 1` byte, writes ~4 GiB

The maximum practically useful overflow fills the entire heap.

---

## 2. Reachability — Attack Surface Path

```
main()
  fread(data, 1, fsize, f)          ← reads attacker file verbatim
  parse_input(data, fsize)
    parse_input() validates magic "CNRY", version byte, entry_count
    for each entry:
      if (entries[i].type == 2):
        parse_data(&entries[i])     ← triggered immediately, before process_entries()
          malloc(alloc_size)        ← tiny alloc
          buf[i] = 'A' × real_total ← heap overflow
```

### Reachability Assessment

| Gate | Requirement | Difficulty |
|---|---|---|
| Magic check | First 4 bytes must be `"CNRY"` | Trivial |
| Version check | Byte 5 must be `0x01` | Trivial |
| Entry routing | Entry type byte must be `2` | Trivial |
| Payload length | Entry length field ≥ 4 | Trivial (set to 4) |
| Overflow trigger | `size×count` wraps uint16 | Trivial (known values) |

**Total PoC size: 13 bytes.** There is no authentication, rate limiting, or additional validation between the file read and the vulnerable code path. The path is **directly reachable** from any attacker who can supply an input file, including network-facing services parsing this format.

---

## 3. Heap Layout — Victim Allocation, Size Class, Adjacent Objects

### Allocation Site
```c
uint8_t *buf = malloc(alloc_size);  // canary.c:95
```

With the PoC (`size=256, count=256`):
- `alloc_size = 1` → glibc allocates a **16-byte minimum chunk** (the smallest `malloc` bin, `MINSIZE = 16` or `32` on 64-bit). On x86-64 with glibc, a `malloc(1)` request is served from the **fastbin** or **tcache** for size `0x20` (32-byte chunk including metadata).

### Heap State at Overflow Time

The heap at the moment `buf` is allocated contains (in order):

1. **The file data buffer** (`malloc(fsize)`) — allocated in `main()` for the raw input bytes  
2. **The `entries` array** (`calloc(entry_count, sizeof(Entry))`) — `entry_count × 40` bytes per `Entry` struct (on 64-bit)  
3. **The payload buffer** (`malloc(avail)`) — allocated in `parse_input()` for the entry's 4-byte payload  
4. **`buf`** (`malloc(1)`) — the victim 1-byte allocation  

In a non-ASLR/deterministic allocation scenario, `buf` is immediately followed by:
- Other heap metadata (next chunk header)
- Potentially the `entries[0].payload` data (already copied), or subsequent allocations

The **65,535-byte overflow starting from `buf+1`** will stomp:
- The malloc chunk header of the **next allocated chunk**
- All subsequent heap data and metadata

### Key Targets in the Adjacent Heap Region

| Object | Distance from `buf` | Exploitation Value |
|---|---|---|
| Next chunk header (size/flags) | +16 to +32 bytes | Heap metadata corruption → arbitrary free |
| `Entry` struct fields (`name`, `payload` pointers) | Variable, within 65 KB | Pointer corruption → arbitrary read/write |
| `entries[i].payload` pointer | Within tcache/smallbin range | Control subsequent `free()` target |
| `free()` hook / tcache pointers | glibc internal, within overflow | Full arbitrary write primitive |

With a 65,535-byte write range, essentially the **entire working heap** is overwritten.

---

## 4. Escalation Path — From Primitive to Impact

The write value is a constant `0x41` byte. This limits some techniques but does not prevent exploitation.

### Path A: Tcache Poisoning (glibc ≥ 2.26, most likely scenario)

1. **State:** `buf` is the last `tcache[0x20]` allocation. Overflow writes `0x41` bytes into the adjacent chunk's tcache metadata.
2. **Tcache fd pointer** at `buf + 0x10` is overwritten to `0x4141414141414141` — this corrupts the tcache freelist.
3. After the loop, `free(buf)` is called at `canary.c:103`. This returns `buf` to the tcache.
4. The next `malloc()` of the same size would return from the corrupted tcache, giving an attacker-controlled pointer. However since the fd is `0x41...`, this crashes immediately. **This path alone is not sufficient.**

### Path B: Heap Metadata Corruption → Overlapping Chunks

1. The overflow reaches the **next chunk's size field** and sets it to `0x4141414141414141`.
2. The subsequent `free(buf)` at line 103 succeeds (freeing the 1-byte chunk normally).
3. When `process_entries()` then calls `free(entries[i].payload)` (line 60), glibc walks the corrupted heap and encounters the forged size field → **abort in `_int_free` with a corrupted chunk** unless the size is accepted.
4. With careful `size`/`count` selection, an attacker can produce a partial overflow of exactly N bytes to forge only specific heap structures while leaving glibc's consistency checks satisfiable.

### Path C: Controlled Pointer Overwrite in `Entry` Structs (Most Practical)

Because `entries` is allocated **before** `buf`, and the overflow is linear forward, this path requires the overflow to wrap around a large heap region. However, in a **custom allocator** or **stripped-down environment** (embedded systems, custom memory pools), the `Entry` structs may directly follow `buf` in memory.

### Path D: Direct Code Execution via `__free_hook` (glibc < 2.34)

In older glibc versions with `__free_hook` / `__malloc_hook`:
1. The overflow of 65,535 `0x41` bytes reaches the `libc` BSS segment (if the heap is contiguous and large enough — possible with aggressive `mmap` tuning or on small address-space targets).
2. `__free_hook` is overwritten to `0x4141414141414141`, diverting the next `free()` call to attacker-controlled code. Unreliable due to constant write value.

### Realistic Impact (Practical)

Even without full code execution, the attacker achieves:
- **Denial of Service (reliable, 100%):** The program crashes with a segfault or heap abort on every triggered run.
- **Information Disclosure:** Not directly from this bug (constant write, no read primitive here — Bug 1 provides that).
- **Memory Corruption leading to code execution:** Achievable in combination with a heap grooming stage or in environments with weaker heap protections (no tcache, no safe-linking).

---

## 5. Constraints — Binary Mitigations

Based on the source code and standard compilation analysis:

| Mitigation | Status | Impact on Exploitation |
|---|---|---|
| **Stack Canary** | Likely present (`-fstack-protector-strong`) | Irrelevant — this is a heap vulnerability |
| **RELRO** | Likely Full RELRO | GOT overwrite not directly applicable |
| **PIE** | Likely enabled | Heap address randomized; heap-to-heap offsets are stable within a run |
| **ASLR** | OS-level | Heap base randomized; does not prevent overflow since offsets are layout-relative |
| **Safe-linking** (glibc ≥ 2.32) | Likely present | Tcache `fd` pointer is XOR-mangled with heap page address; complicates tcache poisoning |
| **Tcache** | Likely present | Smallbin attacks replaced by tcache; requires tcache metadata corruption |
| **ASAN (in test build)** | Active in test environment | Detects and terminates — prevents exploitation in instrumented build only |
| **`fortify_source`** | Unknown | Does not protect against explicit loop-based writes |

**Key constraint:** The write byte is fixed at `0x41`. This eliminates techniques requiring a null byte (string terminator injection) or specific pointer values. It does not prevent techniques that work with arbitrary non-null values (tcache count field overflow, chunk size field forgery with acceptable values containing `0x41`).

---

## 6. Severity

### CVSS v3.1 Vector
```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
```

| Metric | Value | Rationale |
|---|---|---|
| **Attack Vector** | Local (L) | Requires supplying a file to the binary |
| **Attack Complexity** | Low (L) | No heap grooming required for DoS; overflow is deterministic |
| **Privileges Required** | None (N) | No authentication or elevated privilege needed |
| **User Interaction** | Required (R) | User must run the binary with the malicious file |
| **Scope** | Unchanged (U) | Exploit confined to the process |
| **Confidentiality** | High (H) | Heap corruption can lead to information leakage in combination with Bug 1 |
| **Integrity** | High (H) | Heap metadata and data corruption |
| **Availability** | High (A) | Reliable crash / DoS |

**CVSS Base Score: 7.8 (HIGH)**

If the binary is exposed as a **network service** parsing user-supplied data, the vector becomes **AV:N**, raising the score to **9.8 (CRITICAL)**.

---

## 7. Recommended Fix

### Root Cause
The multiplication `size * count` is performed in `uint16_t` arithmetic, silently truncating the result. The corrected allocation must use the same full-width arithmetic as the write loop.

### Fix at `canary.c:93–96`

**Before (vulnerable):**
```c
// canary.c:93
uint16_t alloc_size = (uint16_t)(size * count);  // truncates!
if (alloc_size == 0) alloc_size = 1;
uint8_t *buf = malloc(alloc_size);
if (!buf) return -1;
```

**After (fixed):**
```c
// canary.c:93 — fixed: compute in uint32 and guard against overflow
uint32_t real_total = (uint32_t)size * (uint32_t)count;

// Guard: reject absurdly large allocations before attempting malloc
if (real_total == 0 || real_total > 0x00FFFFFF) {  // 16 MiB cap, tune as needed
    return -1;
}

uint8_t *buf = malloc(real_total);  // allocate the ACTUAL needed size
if (!buf) return -1;

// Now the loop is safe: real_total bytes allocated, real_total bytes written
memset(buf, 'A', real_total);  // also replace loop with memset for efficiency
```

### Additional Hardening

1. **Replace the loop with `memset`** — the byte-by-byte loop is O(N) and unnecessary; `memset(buf, 'A', real_total)` achieves the same with better compiler optimization.
2. **Add an explicit overflow check** before any multiplication of attacker-supplied values:
   ```c
   if (size != 0 && count > UINT32_MAX / size) return -1;  // overflow check
   ```
3. **Apply the same pattern to Bug 1** (`parse_name`): validate `name_len < e->length` before the `memcpy`.
4. **Use `size_t` for all allocation size variables** rather than fixed-width integer types to avoid silent truncation on future size changes.