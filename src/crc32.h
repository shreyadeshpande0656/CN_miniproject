// crc32.h - standard CRC-32 (IEEE 802.3, same as zlib / PNG / Ethernet).
// Header-only, no dependencies. Check value: crc32("123456789") == 0xCBF43926.
#ifndef CRC32_H
#define CRC32_H

#include <cstddef>
#include <cstdint>

namespace crc {
// Lookup table, built once on first use.
inline const uint32_t* table() {
    static uint32_t t[256];
    static bool ready = false;
    if (!ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        ready = true;
    }
    return t;
}
}  // namespace crc

// Incremental form: start with crc = 0, feed chunks one after another.
//   uint32_t c = 0;
//   c = crc32_update(c, chunk1, n1);
//   c = crc32_update(c, chunk2, n2);   // same result as one call over both chunks
inline uint32_t crc32_update(uint32_t crc, const uint8_t* data, size_t len) {
    const uint32_t* t = crc::table();
    uint32_t c = ~crc;
    for (size_t i = 0; i < len; i++)
        c = t[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return ~c;
}

inline uint32_t crc32(const uint8_t* data, size_t len) {
    return crc32_update(0, data, len);
}

#endif  // CRC32_H