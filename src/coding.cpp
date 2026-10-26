// coding.cpp - implementation of coding.h
#include "coding.h"
 
#include <cstring>
 
// ===========================================================================
// GF(256)
// ===========================================================================
namespace {
uint8_t g_exp[512];          // g_exp[i] = 2^i, doubled so exp[log a + log b] needs no modulo
uint8_t g_log[256];
uint8_t g_mul[256][256];     // full multiplication table (64 KB): g_mul[a][b] = a*b
bool    g_ready = false;
}  // namespace
 
namespace gf {
 
void init() {
    if (g_ready) return;
    unsigned x = 1;
    for (int i = 0; i < 255; i++) {
        g_exp[i] = (uint8_t)x;
        g_log[x] = (uint8_t)i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11D;
    }
    for (int i = 255; i < 512; i++) g_exp[i] = g_exp[i - 255];
    g_log[0] = 0;                                  // never used
 
    for (int a = 0; a < 256; a++)
        for (int b = 0; b < 256; b++)
            g_mul[a][b] = (a == 0 || b == 0) ? 0 : g_exp[g_log[a] + g_log[b]];
    g_ready = true;
}
 
uint8_t mul(uint8_t a, uint8_t b) {
    init();
    return g_mul[a][b];
}
 
uint8_t inv(uint8_t a) {
    init();
    return g_exp[255 - g_log[a]];                  // a != 0
}
 
uint8_t divide(uint8_t a, uint8_t b) {
    init();
    if (a == 0) return 0;
    return g_exp[g_log[a] + 255 - g_log[b]];       // b != 0
}
 
void mul_add(uint8_t* dst, const uint8_t* src, uint8_t c, size_t n) {
    if (c == 0) return;
    if (c == 1) {
        for (size_t i = 0; i < n; i++) dst[i] ^= src[i];
        return;
    }
    init();
    const uint8_t* row = g_mul[c];
    for (size_t i = 0; i < n; i++) dst[i] ^= row[src[i]];
}
 
void scale(uint8_t* buf, uint8_t c, size_t n) {
    if (c == 1) return;
    init();
    const uint8_t* row = g_mul[c];
    for (size_t i = 0; i < n; i++) buf[i] = row[buf[i]];
}
 
}  // namespace gf
 
// ===========================================================================
// coefficient generator
// ===========================================================================
namespace {
 
// splitmix64: tiny, fixed-width, identical on every platform.
struct SplitMix {
    uint64_t s;
    explicit SplitMix(uint64_t seed) : s(seed) {}
    uint64_t next() {
        uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
};
 
}  // namespace
 
namespace coding {
 
uint64_t blocks_needed(uint64_t file_size, uint32_t block_size) {
    if (block_size == 0) return 0;
    return file_size / block_size + ((file_size % block_size) ? 1 : 0);
}
 
void make_coeffs(uint32_t file_id, uint32_t seq, uint32_t k, uint8_t* out) {
    if (SYSTEMATIC && seq < k) {                   // source packet: unit vector
        std::memset(out, 0, k);
        out[seq] = 1;
        return;
    }
    SplitMix rng((((uint64_t)file_id << 32) | (uint64_t)seq) ^ 0x5DEECE66DA5A5A5AULL);
    bool any = false;
    uint32_t i = 0;
    while (i < k) {
        uint64_t r = rng.next();
        for (int b = 0; b < 8 && i < k; b++, i++) {
            out[i] = (uint8_t)(r & 0xFF);
            r >>= 8;
            if (out[i]) any = true;
        }
    }
    if (!any) out[seq % k] = 1;                    // all-zero vector would carry nothing
}
 
// ===========================================================================
// Encoder
// ===========================================================================
Encoder::Encoder(const uint8_t* data, uint64_t size, uint32_t block_size)
    : k_(0), bs_(block_size), ok_(false) {
    gf::init();
    if (size == 0 || block_size == 0) return;
    uint64_t k = blocks_needed(size, block_size);
    if (k > MAX_K) return;
    k_ = (uint32_t)k;
    blocks_.assign((size_t)k_ * bs_, 0);
    std::memcpy(blocks_.data(), data, (size_t)size);
    ok_ = true;
}
 
void Encoder::encode(uint32_t file_id, uint32_t seq, uint8_t* out) const {
    if (SYSTEMATIC && seq < k_) {                  // fast path: plain source block
        std::memcpy(out, &blocks_[(size_t)seq * bs_], bs_);
        return;
    }
    std::memset(out, 0, bs_);
    std::vector<uint8_t> coef(k_);
    make_coeffs(file_id, seq, k_, coef.data());
    for (uint32_t j = 0; j < k_; j++)
        if (coef[j]) gf::mul_add(out, &blocks_[(size_t)j * bs_], coef[j], bs_);
}
 
// ===========================================================================
// Decoder
//
// rows_[c] holds a "pivot row" for column c: coefficient vector with a 1 at c and
// zeros before c, plus the matching data. A new packet is reduced against all
// existing pivot rows; whatever is left is either zero (useless packet) or has a
// first non-pivot column f, and becomes the new pivot row for f.
// When rank == K the matrix is upper triangular; back-substitution finishes it.
// ===========================================================================
Decoder::Decoder(uint32_t file_id, uint32_t k, uint32_t block_size)
    : file_id_(file_id), k_(k), bs_(block_size), rank_(0), received_(0), solved_(false),
      rows_(k), coef_(k), data_(block_size) {
    gf::init();
}
 
int Decoder::add_packet(uint32_t seq, const uint8_t* payload, size_t len) {
    if (len != bs_) return -1;
    received_++;
    if (rank_ == k_) return 0;                     // already have everything
 
    make_coeffs(file_id_, seq, k_, coef_.data());
    std::memcpy(data_.data(), payload, bs_);
 
    int first_free = -1;
    for (uint32_t c = 0; c < k_; c++) {
        uint8_t a = coef_[c];
        if (a == 0) continue;
        Row& r = rows_[c];
        if (r.used) {
            if (r.unit) {
                coef_[c] = 0;                      // row is just 1*block[c]
            } else {
                // coef -= a * row.coef  (row.coef[c] == 1, so coef[c] becomes 0)
                gf::mul_add(&coef_[c], &r.coef[c], a, k_ - c);
            }
            gf::mul_add(data_.data(), r.data.data(), a, bs_);
        } else if (first_free < 0) {
            first_free = (int)c;
        }
    }
    if (first_free < 0) return 0;                  // reduced to zero: not innovative
 
    uint32_t f = (uint32_t)first_free;
    uint8_t  s = gf::inv(coef_[f]);                // normalise so the pivot becomes 1
    gf::scale(data_.data(), s, bs_);
 
    bool unit = true;
    for (uint32_t j = f + 1; j < k_; j++)
        if (coef_[j]) { unit = false; break; }
 
    Row& row = rows_[f];
    row.used = true;
    row.unit = unit;
    if (!unit) {
        gf::scale(&coef_[f], s, k_ - f);
        row.coef.assign(coef_.begin(), coef_.end());
    }
    row.data.assign(data_.begin(), data_.end());
    rank_++;
    return 1;
}
 
bool Decoder::extract(uint64_t file_size, std::vector<uint8_t>& out) {
    if (rank_ != k_) return false;
    if (file_size == 0 || blocks_needed(file_size, bs_) != k_) return false;
 
    if (!solved_) {
        // Back-substitution: rows below i are already plain source blocks.
        for (int i = (int)k_ - 1; i >= 0; i--) {
            Row& r = rows_[i];
            if (r.unit) continue;
            for (uint32_t j = (uint32_t)i + 1; j < k_; j++)
                if (r.coef[j]) gf::mul_add(r.data.data(), rows_[j].data.data(), r.coef[j], bs_);
            r.unit = true;
            r.coef.clear();
        }
        solved_ = true;
    }
 
    out.resize((size_t)file_size);
    size_t pos = 0;
    for (uint32_t i = 0; i < k_ && pos < file_size; i++) {
        size_t n = bs_;
        if (n > file_size - pos) n = (size_t)(file_size - pos);   // drop the padding
        std::memcpy(&out[pos], rows_[i].data.data(), n);
        pos += n;
    }
    return true;
}
 
}  // namespace coding
 