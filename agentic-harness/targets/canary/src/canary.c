/*
 * Canary target: 3 planted vulnerabilities for harness validation.
 *
 * Bug 1: heap-buffer-overflow in parse_name() — reads past allocation
 *         when name_len field exceeds actual data
 * Bug 2: heap-use-after-free in process_entries() — frees entry on
 *         error path, then continues to access it in the loop
 * Bug 3: integer overflow in parse_data() — uint16 size * count wraps
 *         to small allocation, large write follows
 *
 * Input format (binary):
 *   [4 bytes] magic: "CNRY"
 *   [1 byte]  version: 1
 *   [1 byte]  entry_count
 *   entries[]:
 *     [1 byte]  type (1=name, 2=data)
 *     [2 bytes] length (little-endian)
 *     [length bytes] payload
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint8_t type;
    uint16_t length;
    uint8_t *payload;
    char *name;
    int valid;
} Entry;

/* Bug 1: heap-buffer-overflow READ
 * name_len is read from the first byte of payload, then that many bytes
 * are copied — but name_len can exceed the actual payload size. */
static int parse_name(Entry *e) {
    if (e->length < 1) return -1;
    uint8_t name_len = e->payload[0];
    e->name = malloc(name_len + 1);
    if (!e->name) return -1;
    /* BUG: reads name_len bytes from payload+1, but payload may be
     * shorter than name_len+1. Should check: name_len+1 <= e->length */
    memcpy(e->name, e->payload + 1, name_len);
    e->name[name_len] = '\0';
    return 0;
}

/* Bug 2: heap-use-after-free
 * On parse error, the entry is freed but e->valid is still set to 1,
 * so the caller continues to access the freed entry. */
static int process_entries(Entry *entries, int count) {
    for (int i = 0; i < count; i++) {
        Entry *e = &entries[i];
        if (e->type == 1) {
            if (parse_name(e) < 0) {
                /* BUG: frees payload but doesn't clear pointer or skip.
                 * Sets valid=1 despite error. Caller will read freed name. */
                free(e->payload);
                e->payload = NULL;
                e->valid = 1;  /* should be 0 */
                continue;
            }
            printf("Name: %s\n", e->name);
        }
        e->valid = 1;
    }

    /* Access all "valid" entries — triggers UAF on error-path entries */
    for (int i = 0; i < count; i++) {
        if (entries[i].valid && entries[i].type == 1) {
            /* BUG: e->name was never set (parse_name failed), but we
             * access it anyway because valid was incorrectly set to 1 */
            if (entries[i].name) {
                printf("Valid name: %s\n", entries[i].name);
            }
        }
    }
    return 0;
}

/* Bug 3: integer overflow → heap-buffer-overflow WRITE
 * size is uint16, count is uint16. size*count can wrap to a small value
 * when both are large, causing a small allocation and large write. */
static int parse_data(Entry *e) {
    if (e->length < 4) return -1;
    uint16_t size = e->payload[0] | (e->payload[1] << 8);
    uint16_t count = e->payload[2] | (e->payload[3] << 8);

    /* BUG: uint16 * uint16 computed in 16-bit arithmetic wraps.
     * e.g., size=0x100, count=0x101 → 0x100*0x101 = 0x10100,
     * truncated to 0x0100 → allocates 256 bytes, writes 65792. */
    uint16_t total = size * count;
    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    /* Fill buffer — writes size*count bytes (the full, unwrapped amount) */
    uint32_t real_total = (uint32_t)size * (uint32_t)count;
    for (uint32_t i = 0; i < real_total && i < e->length - 4; i++) {
        buf[i] = e->payload[4 + (i % (e->length - 4))];
    }

    printf("Data: %u items of size %u (total %u bytes)\n", count, size, real_total);
    free(buf);
    return 0;
}

static int parse_input(const uint8_t *data, size_t len) {
    if (len < 6) {
        fprintf(stderr, "Input too short\n");
        return -1;
    }
    if (memcmp(data, "CNRY", 4) != 0) {
        fprintf(stderr, "Bad magic\n");
        return -1;
    }
    if (data[4] != 1) {
        fprintf(stderr, "Unsupported version %d\n", data[4]);
        return -1;
    }

    uint8_t entry_count = data[5];
    Entry *entries = calloc(entry_count, sizeof(Entry));
    if (!entries) return -1;

    size_t offset = 6;
    for (int i = 0; i < entry_count && offset < len; i++) {
        if (offset + 3 > len) break;
        entries[i].type = data[offset];
        entries[i].length = data[offset + 1] | (data[offset + 2] << 8);
        offset += 3;

        if (offset + entries[i].length > len) {
            entries[i].length = len - offset;
        }
        entries[i].payload = malloc(entries[i].length);
        if (entries[i].payload) {
            memcpy(entries[i].payload, data + offset, entries[i].length);
        }
        offset += entries[i].length;

        if (entries[i].type == 2) {
            parse_data(&entries[i]);
        }
    }

    process_entries(entries, entry_count);

    for (int i = 0; i < entry_count; i++) {
        free(entries[i].payload);
        free(entries[i].name);
    }
    free(entries);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(fsize);
    if (!data) {
        fclose(f);
        return 1;
    }

    fread(data, 1, fsize, f);
    fclose(f);

    int ret = parse_input(data, fsize);

    free(data);
    return ret;
}
