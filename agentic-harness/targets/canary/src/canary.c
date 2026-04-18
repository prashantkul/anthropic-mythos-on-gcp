/*
 * Canary target: 3 planted vulnerabilities for harness validation.
 *
 * Bug 1: heap-buffer-overflow READ in parse_name() — name_len field
 *         exceeds actual payload, memcpy reads past allocation
 * Bug 2: heap-use-after-free in process_entries() — payload freed on
 *         error path but pointer not cleared, second loop reads it
 * Bug 3: integer overflow in parse_data() — uint16 size * count wraps
 *         to small allocation, large memset follows
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
    if (e->length < 2) return -1;
    uint8_t name_len = e->payload[0];
    if (name_len == 0) return -1;
    e->name = malloc(name_len + 1);
    if (!e->name) return -1;
    /* BUG: reads name_len bytes from payload+1, but payload may be
     * shorter than name_len+1. Should check: name_len < e->length */
    memcpy(e->name, e->payload + 1, name_len);
    e->name[name_len] = '\0';
    return 0;
}

/* Bug 2: heap-use-after-free
 * On parse error, the entry payload is freed but the pointer is NOT
 * cleared. The second loop reads from the freed pointer. */
static int process_entries(Entry *entries, int count) {
    for (int i = 0; i < count; i++) {
        Entry *e = &entries[i];
        if (e->type == 1) {
            if (parse_name(e) < 0) {
                /* BUG: frees payload but does NOT null the pointer.
                 * Sets valid=1 despite error. Second loop will read
                 * from the freed payload pointer. */
                free(e->payload);
                e->valid = 1;
                continue;
            }
            e->valid = 1;
        } else {
            e->valid = 1;
        }
    }

    /* Second pass: access payload of all "valid" entries.
     * Triggers UAF for entries where payload was freed above. */
    for (int i = 0; i < count; i++) {
        if (entries[i].valid && entries[i].payload) {
            uint8_t tag = entries[i].payload[0];
            printf("Entry %d: tag=0x%02x, type=%d\n", i, tag, entries[i].type);
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

    if (size == 0 || count == 0) return -1;

    /* BUG: allocate using truncated uint16 result */
    uint16_t alloc_size = (uint16_t)(size * count);
    if (alloc_size == 0) alloc_size = 1;
    uint8_t *buf = malloc(alloc_size);
    if (!buf) return -1;

    /* Write using full uint32 amount — overflows the small buffer */
    uint32_t real_total = (uint32_t)size * (uint32_t)count;
    for (uint32_t i = 0; i < real_total; i++) {
        buf[i] = 'A';
    }

    printf("Data: %u items of size %u (%u allocated, %u written)\n",
           count, size, alloc_size, real_total);
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

        if (entries[i].length > 0) {
            uint16_t avail = (offset + entries[i].length > len)
                             ? (len - offset) : entries[i].length;
            entries[i].payload = malloc(avail);
            if (entries[i].payload) {
                memcpy(entries[i].payload, data + offset, avail);
            }
            offset += avail;
        }

        if (entries[i].type == 2) {
            parse_data(&entries[i]);
        }
    }

    process_entries(entries, entry_count);

    for (int i = 0; i < entry_count; i++) {
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
