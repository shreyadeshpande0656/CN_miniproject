// test_packet.cpp - self-test for crc32.h and packet.h (no networking involved).
//   g++ -std=c++14 -Wall -Wextra src/test_packet.cpp -o test_packet
#include <cstdio>
#include <cstring>
#include "packet.h"
 
static int g_fail = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("  FAIL (line %d): %s\n", __LINE__, #cond);     \
            g_fail++;                                                   \
        }                                                               \
    } while (0)
 
static pkt::Status dec(const std::vector<uint8_t>& b, pkt::Packet& out) {
    return pkt::decode(b.data(), b.size(), out);
}
 
int main() {
    using namespace pkt;
 
    std::printf("[1] CRC-32\n");
    const uint8_t* s = (const uint8_t*)"123456789";
    CHECK(crc32(s, 9) == 0xCBF43926u);                         // standard check value
    CHECK(crc32_update(crc32(s, 4), s + 4, 5) == 0xCBF43926u); // incremental == one-shot
    CHECK(crc32(s, 0) == 0u);
 
    std::printf("[2] META round trip\n");
    {
        Packet in = make_meta(0xDEADBEEF, 10000, 1024, 10, 0x12345678, "photo.jpg");
        std::vector<uint8_t> b = encode(in);
        Packet out;
        CHECK(dec(b, out) == PKT_OK);
        CHECK(out.type == T_META && out.file_id == 0xDEADBEEFu);
        CHECK(out.file_size == 10000 && out.block_size == 1024 && out.k == 10);
        CHECK(out.file_crc == 0x12345678u && out.filename == "photo.jpg");
    }
 
    std::printf("[3] DATA round trip + size limits\n");
    {
        std::vector<uint8_t> data(1024);
        for (size_t i = 0; i < data.size(); i++) data[i] = (uint8_t)(i * 7 + 3);
        Packet in = make_data(42, 123456, data.data(), data.size());
        std::vector<uint8_t> b = encode(in);
        CHECK(b.size() == 1024 + 18);
        Packet out;
        CHECK(dec(b, out) == PKT_OK);
        CHECK(out.type == T_DATA && out.file_id == 42 && out.seq == 123456);
        CHECK(out.payload == data);
 
        std::vector<uint8_t> big(MAX_BLOCK, 0xAB);
        std::vector<uint8_t> bb = encode(make_data(1, 1, big.data(), big.size()));
        CHECK(bb.size() == MAX_PACKET);                         // exactly fits one frame
    }
 
    std::printf("[4] DONE round trip\n");
    {
        Packet out;
        CHECK(dec(encode(make_done(7, 1, 1337)), out) == PKT_OK);
        CHECK(out.type == T_DONE && out.status == 1 && out.packets_used == 1337);
    }
 
    std::printf("[5] corruption / garbage is rejected\n");
    {
        std::vector<uint8_t> good = encode(make_data(5, 9, (const uint8_t*)"hello world!", 12));
        Packet out;
 
        std::vector<uint8_t> b = good;
        b[20] ^= 0x01;                                         // flip one payload bit
        CHECK(dec(b, out) == PKT_BAD_CRC);
 
        b = good; b[good.size() - 1] ^= 0xFF;                  // damage the CRC itself
        CHECK(dec(b, out) == PKT_BAD_CRC);
 
        b = good; b.pop_back();                                // lost last byte
        CHECK(dec(b, out) == PKT_BAD_CRC);
 
        b = good; b.resize(5);                                 // tiny fragment
        CHECK(dec(b, out) == PKT_TOO_SHORT);
 
        b = good; b[0] ^= 0xFF;                                // wrong magic
        CHECK(dec(b, out) == PKT_BAD_MAGIC);
 
        b = good; b[2] = 9;                                    // wrong version
        CHECK(dec(b, out) == PKT_BAD_VERSION);
 
        const uint8_t junk[] = "this is not one of our packets at all";
        CHECK(pkt::decode(junk, sizeof(junk), out) == PKT_BAD_MAGIC);
    }
 
    std::printf("[6] valid CRC but nonsense fields is rejected\n");
    {
        Packet out;
        // K inconsistent with file_size/block_size (10000/1024 -> K must be 10)
        CHECK(dec(encode(make_meta(1, 10000, 1024, 3, 0, "x")), out) == PKT_BAD_FIELD);
        // block_size 0
        CHECK(dec(encode(make_meta(1, 10000, 0, 3, 0, "x")), out) == PKT_BAD_FIELD);
        // empty file
        CHECK(dec(encode(make_meta(1, 0, 1024, 0, 0, "x")), out) == PKT_BAD_FIELD);
        // DONE with status 7
        CHECK(dec(encode(make_done(1, 7, 1)), out) == PKT_BAD_FIELD);
        // unknown type
        Packet weird; weird.type = 99;
        CHECK(dec(encode(weird), out) == PKT_BAD_TYPE);
    }
 
    if (g_fail == 0) std::printf("\nALL TESTS PASSED\n");
    else             std::printf("\n%d CHECK(S) FAILED\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
 