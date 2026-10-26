// coding.h - GF(256) random linear erasure coding (encoder + decoder).
//
// IDEA
//   The file is cut into K blocks of block_size bytes (last block zero-padded).
//   Every packet carries ONE coded block:
//        coded = c[0]*block[0] + c[1]*block[1] + ... + c[K-1]*block[K-1]
//   where * and + are arithmetic in the finite field GF(256) (+ is XOR).
//   The vector c (K bytes) is NOT sent: both sides rebuild it from
//   (file_id, seq, K) with make_coeffs(), so the packet stays small.
//
//   The decoder collects packets and keeps solving the linear system with
//   Gaussian elimination. Any K packets whose coefficient vectors are linearly
//   independent recover the file, no matter WHICH packets were lost.
//
// SYSTEMATIC CODE
//   Packets seq = 0 .. K-1 are the plain source blocks (c = unit vector), packets
//   seq >= K are random combinations ("repair packets"). With no loss the decoder
//   does almost no work; with loss, repair packets fill the gaps.
//   Client and server MUST agree on this, so it is a compile-time constant.
//
// LIMIT
//   K <= MAX_K. Coding cost grows with K (every repair packet touches all K
//   blocks), so big files need a larger block size or "generations" (a later upgrade).
#ifndef CODING_H
#define CODING_H
 
#include <cstddef>
#include <cstdint>
#include <vector>
 
// ---------------------------------------------------------------------------
// GF(256) arithmetic, polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D), generator 2.
// Addition and subtraction are both XOR.
// ---------------------------------------------------------------------------
namespace gf {
void    init();                                   // builds the tables (called automatically)
uint8_t mul(uint8_t a, uint8_t b);
uint8_t divide(uint8_t a, uint8_t b);             // b must be non-zero
uint8_t inv(uint8_t a);                           // a must be non-zero
// dst[i] ^= c * src[i]   for i in [0, n)
void    mul_add(uint8_t* dst, const uint8_t* src, uint8_t c, size_t n);
// buf[i] = c * buf[i]
void    scale(uint8_t* buf, uint8_t c, size_t n);
}  // namespace gf
 
namespace coding {
 
const uint32_t MAX_K      = 2048;
const bool     SYSTEMATIC = true;
 
// ceil(file_size / block_size)
uint64_t blocks_needed(uint64_t file_size, uint32_t block_size);
 
// Fills out[0..k-1] with the coefficient vector of packet `seq`.
// Deterministic: same (file_id, seq, k) gives the same bytes on every machine.
void make_coeffs(uint32_t file_id, uint32_t seq, uint32_t k, uint8_t* out);
 
// ---------------------------------------------------------------------------
// Encoder (client side)
// ---------------------------------------------------------------------------
class Encoder {
public:
    // Copies `size` bytes from `data` and pads to a whole number of blocks.
    Encoder(const uint8_t* data, uint64_t size, uint32_t block_size);
 
    bool     ok() const { return ok_; }          // false: empty file, bad block size or K > MAX_K
    uint32_t k() const { return k_; }
    uint32_t block_size() const { return bs_; }
 
    // Writes the payload of packet `seq` (block_size bytes) into out.
    // Any seq can be requested, as often as you like.
    void encode(uint32_t file_id, uint32_t seq, uint8_t* out) const;
 
private:
    uint32_t             k_;
    uint32_t             bs_;
    bool                 ok_;
    std::vector<uint8_t> blocks_;                // K * block_size bytes, zero padded
};
 
// ---------------------------------------------------------------------------
// Decoder (server side): incremental Gaussian elimination
// ---------------------------------------------------------------------------
class Decoder {
public:
    Decoder(uint32_t file_id, uint32_t k, uint32_t block_size);
 
    // Feed one received packet.
    //   returns  1  innovative (rank went up)
    //            0  useless (linearly dependent / duplicate / already complete)
    //           -1  rejected (payload length != block_size)
    int add_packet(uint32_t seq, const uint8_t* payload, size_t len);
 
    bool     complete() const { return rank_ == k_; }
    uint32_t rank() const { return rank_; }                 // independent packets so far
    uint32_t received() const { return received_; }         // packets fed in (valid length)
    uint32_t non_innovative() const { return received_ - rank_; }
 
    // Once complete(): back-substitute and write exactly file_size bytes.
    // Returns false if not complete yet or file_size does not fit K/block_size.
    bool extract(uint64_t file_size, std::vector<uint8_t>& out);
 
private:
    struct Row {
        bool                 used = false;
        bool                 unit = false;   // row is exactly "1 * block[c]" (coef not stored)
        std::vector<uint8_t> coef;           // K bytes, only when !unit; coef[c] == 1
        std::vector<uint8_t> data;           // block_size bytes
    };
 
    uint32_t         file_id_;
    uint32_t         k_;
    uint32_t         bs_;
    uint32_t         rank_;
    uint32_t         received_;
    bool             solved_;
    std::vector<Row> rows_;                  // rows_[c] = pivot row for column c
    std::vector<uint8_t> coef_;              // work buffers
    std::vector<uint8_t> data_;
};
 
}  // namespace coding
 
#endif  // CODING_H
 