// packet.h - wire format for the erasure-coded UDP file transfer.
//
// Every packet is built byte by byte in NETWORK (big-endian) order, so it does
// not depend on struct padding or on the CPU (Windows x86 <-> Mac ARM are fine).
//
//   COMMON HEADER (8 bytes)
//     magic    u16   0xEC5A  (rejects stray UDP traffic)
//     version  u8    1
//     type     u8    1 = META, 2 = DATA, 3 = DONE
//     file_id  u32   identifies one transfer (random, chosen by the client)
//
//   META body (client -> server, sent first and repeated)
//     file_size u64, block_size u16, K u32, file_crc u32,
//     name_len u8, name bytes (no terminator)
//     K = ceil(file_size / block_size)
//
//   DATA body (client -> server, one coded block)
//     seq u32          packet number. The GF(256) coefficient vector is NOT sent:
//                      both sides regenerate it from (file_id, seq, K) in coding.h
//     payload_len u16  then payload bytes (= block_size bytes)
//
//   DONE body (server -> client)
//     status u8 (1 = file rebuilt and CRC ok, 0 = CRC mismatch), packets_used u32
//
//   TRAILER (every packet)
//     crc32 u32   CRC-32 over everything before it. Bad CRC => packet is dropped.
//
// Largest packet = MAX_PACKET (1472 bytes) so it fits one Ethernet frame
// (1500 MTU - 20 IP - 8 UDP) and is never fragmented.
#ifndef PACKET_H
#define PACKET_H
 
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "crc32.h"
 
namespace pkt {
 
const uint16_t MAGIC   = 0xEC5A;
const uint8_t  VERSION = 1;
 
const uint8_t T_META = 1;
const uint8_t T_DATA = 2;
const uint8_t T_DONE = 3;
 
const size_t COMMON_HDR    = 8;      // magic + version + type + file_id
const size_t CRC_LEN       = 4;
const size_t MAX_PACKET    = 1472;
const size_t MAX_FILENAME  = 255;
const size_t DEFAULT_BLOCK = 1024;
// DATA overhead = 8 (common) + 4 (seq) + 2 (len) + 4 (crc) = 18 bytes
const size_t MAX_BLOCK     = MAX_PACKET - 18;   // 1454
 
enum Status {
    PKT_OK = 0,
    PKT_TOO_SHORT,
    PKT_BAD_MAGIC,
    PKT_BAD_VERSION,
    PKT_BAD_CRC,
    PKT_BAD_TYPE,
    PKT_BAD_FIELD
};
 
inline const char* status_str(Status s) {
    switch (s) {
        case PKT_OK:          return "ok";
        case PKT_TOO_SHORT:   return "too short";
        case PKT_BAD_MAGIC:   return "bad magic";
        case PKT_BAD_VERSION: return "bad version";
        case PKT_BAD_CRC:     return "bad crc";
        case PKT_BAD_TYPE:    return "bad type";
        case PKT_BAD_FIELD:   return "bad field";
    }
    return "?";
}
 
// One struct for all three packet kinds; only the fields of `type` are used.
struct Packet {
    uint8_t  type = 0;
    uint32_t file_id = 0;
 
    // META
    uint64_t    file_size = 0;
    uint16_t    block_size = 0;
    uint32_t    k = 0;
    uint32_t    file_crc = 0;
    std::string filename;
 
    // DATA
    uint32_t             seq = 0;
    std::vector<uint8_t> payload;
 
    // DONE
    uint8_t  status = 0;
    uint32_t packets_used = 0;
};
 
// ---- builders (so client/server code stays short) ----
inline Packet make_meta(uint32_t file_id, uint64_t file_size, uint16_t block_size,
                        uint32_t k, uint32_t file_crc, const std::string& name) {
    Packet p;
    p.type = T_META; p.file_id = file_id;
    p.file_size = file_size; p.block_size = block_size; p.k = k;
    p.file_crc = file_crc; p.filename = name;
    return p;
}
inline Packet make_data(uint32_t file_id, uint32_t seq,
                        const uint8_t* data, size_t len) {
    Packet p;
    p.type = T_DATA; p.file_id = file_id; p.seq = seq;
    p.payload.assign(data, data + len);
    return p;
}
inline Packet make_done(uint32_t file_id, uint8_t status, uint32_t packets_used) {
    Packet p;
    p.type = T_DONE; p.file_id = file_id;
    p.status = status; p.packets_used = packets_used;
    return p;
}
 
// ---- byte writer / reader (big-endian) ----
inline void put_u8(std::vector<uint8_t>& b, uint8_t v) { b.push_back(v); }
inline void put_u16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back((uint8_t)(v >> 8));
    b.push_back((uint8_t)(v & 0xFF));
}
inline void put_u32(std::vector<uint8_t>& b, uint32_t v) {
    put_u16(b, (uint16_t)(v >> 16));
    put_u16(b, (uint16_t)(v & 0xFFFF));
}
inline void put_u64(std::vector<uint8_t>& b, uint64_t v) {
    put_u32(b, (uint32_t)(v >> 32));
    put_u32(b, (uint32_t)(v & 0xFFFFFFFFu));
}
 
// Bounds-checked reader: reading past the end sets ok = false and returns 0.
struct Reader {
    const uint8_t* p;
    const uint8_t* end;
    bool ok;
    Reader(const uint8_t* b, size_t n) : p(b), end(b + n), ok(true) {}
    size_t left() const { return (size_t)(end - p); }
    uint8_t u8() {
        if (left() < 1) { ok = false; return 0; }
        return *p++;
    }
    uint16_t u16() {
        if (left() < 2) { ok = false; p = end; return 0; }
        uint16_t v = (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        return v;
    }
    uint32_t u32() {
        uint32_t hi = u16();
        uint32_t lo = u16();
        return (hi << 16) | lo;
    }
    uint64_t u64() {
        uint64_t hi = u32();
        uint64_t lo = u32();
        return (hi << 32) | lo;
    }
};
 
// ---- encode: Packet -> bytes ready for sendto() ----
inline std::vector<uint8_t> encode(const Packet& p) {
    std::vector<uint8_t> b;
    b.reserve(COMMON_HDR + 32 + p.payload.size() + p.filename.size());
 
    put_u16(b, MAGIC);
    put_u8(b, VERSION);
    put_u8(b, p.type);
    put_u32(b, p.file_id);
 
    switch (p.type) {
        case T_META: {
            put_u64(b, p.file_size);
            put_u16(b, p.block_size);
            put_u32(b, p.k);
            put_u32(b, p.file_crc);
            size_t n = p.filename.size() > MAX_FILENAME ? MAX_FILENAME : p.filename.size();
            put_u8(b, (uint8_t)n);
            b.insert(b.end(), p.filename.begin(), p.filename.begin() + n);
            break;
        }
        case T_DATA:
            put_u32(b, p.seq);
            put_u16(b, (uint16_t)p.payload.size());
            b.insert(b.end(), p.payload.begin(), p.payload.end());
            break;
        case T_DONE:
            put_u8(b, p.status);
            put_u32(b, p.packets_used);
            break;
        default:
            break;
    }
 
    put_u32(b, crc32(b.data(), b.size()));   // trailer
    return b;
}
 
// ---- decode: bytes from recvfrom() -> Packet, with full validation ----
// Returns PKT_OK only if the packet is intact and every field is sane.
// On anything else the caller should simply ignore the datagram.
inline Status decode(const uint8_t* buf, size_t len, Packet& out) {
    if (len < COMMON_HDR + CRC_LEN) return PKT_TOO_SHORT;
 
    Reader h(buf, COMMON_HDR);
    uint16_t magic   = h.u16();
    uint8_t  version = h.u8();
    uint8_t  type    = h.u8();
    uint32_t file_id = h.u32();
 
    if (magic != MAGIC)     return PKT_BAD_MAGIC;
    if (version != VERSION) return PKT_BAD_VERSION;
 
    size_t body_end = len - CRC_LEN;
    Reader t(buf + body_end, CRC_LEN);
    if (crc32(buf, body_end) != t.u32()) return PKT_BAD_CRC;
 
    Reader r(buf + COMMON_HDR, body_end - COMMON_HDR);
    Packet p;
    p.type = type;
    p.file_id = file_id;
 
    switch (type) {
        case T_META: {
            p.file_size  = r.u64();
            p.block_size = r.u16();
            p.k          = r.u32();
            p.file_crc   = r.u32();
            size_t n     = r.u8();
            if (!r.ok || r.left() != n) return PKT_BAD_FIELD;
            p.filename.assign((const char*)r.p, n);
            r.p += n;
            if (p.file_size == 0 || p.block_size == 0 || p.block_size > MAX_BLOCK)
                return PKT_BAD_FIELD;
            uint64_t k = p.file_size / p.block_size + (p.file_size % p.block_size ? 1 : 0);
            if (k != p.k) return PKT_BAD_FIELD;     // K must match file_size/block_size
            break;
        }
        case T_DATA: {
            p.seq = r.u32();
            size_t n = r.u16();
            if (!r.ok || n == 0 || n > MAX_BLOCK || r.left() != n) return PKT_BAD_FIELD;
            p.payload.assign(r.p, r.p + n);
            r.p += n;
            break;
        }
        case T_DONE:
            p.status       = r.u8();
            p.packets_used = r.u32();
            if (p.status > 1) return PKT_BAD_FIELD;
            break;
        default:
            return PKT_BAD_TYPE;
    }
 
    if (!r.ok || r.left() != 0) return PKT_BAD_FIELD;   // truncated or trailing bytes
    out = p;
    return PKT_OK;
}
 
}  // namespace pkt
 
#endif  // PACKET_H
 