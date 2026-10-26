// test_coding.cpp - self-test and loss experiment for coding.h (no networking).
//   g++ -std=c++14 -O2 -Wall -Wextra src/test_coding.cpp src/coding.cpp -o test_coding
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>
 
#include "coding.h"
 
static int g_fail = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("  FAIL (line %d): %s\n", __LINE__, #cond);     \
            g_fail++;                                                   \
        }                                                               \
    } while (0)
 
static std::mt19937 g_rng(12345);
 
static std::vector<uint8_t> random_file(size_t n) {
    std::vector<uint8_t> f(n);
    for (size_t i = 0; i < n; i++) f[i] = (uint8_t)(g_rng() & 0xFF);
    return f;
}
 
struct Trial {
    bool     ok;          // file rebuilt bit-for-bit
    uint32_t k;
    uint32_t used;        // packets fed to the decoder before it completed
    uint32_t sent;
    uint32_t arrived;
};
 
// Simulates one transfer: encode N = ceil(K*redundancy) packets, drop each with
// probability `loss`, deliver the survivors in random order, decode.
static Trial run_trial(const std::vector<uint8_t>& file, uint32_t bs, double loss,
                       double redundancy, uint32_t file_id, uint32_t extra = 0) {
    Trial t = {false, 0, 0, 0, 0};
    coding::Encoder enc(file.data(), file.size(), bs);
    if (!enc.ok()) return t;
    t.k = enc.k();
    // `extra` guards tiny files: with K = 1 and a 30% loss rate, "2 packets" would
    // be lost entirely 9% of the time, which no decoder can fix.
    t.sent = (uint32_t)std::ceil(t.k * redundancy) + extra;
 
    std::uniform_real_distribution<double> u(0.0, 1.0);
    std::vector<uint32_t> arriving;
    for (uint32_t seq = 0; seq < t.sent; seq++)
        if (u(g_rng) >= loss) arriving.push_back(seq);
    std::shuffle(arriving.begin(), arriving.end(), g_rng);
    t.arrived = (uint32_t)arriving.size();
 
    coding::Decoder dec(file_id, t.k, bs);
    std::vector<uint8_t> buf(bs);
    for (size_t i = 0; i < arriving.size(); i++) {
        enc.encode(file_id, arriving[i], buf.data());
        dec.add_packet(arriving[i], buf.data(), bs);
        if (dec.complete()) break;
    }
    t.used = dec.received();
    if (!dec.complete()) return t;
 
    std::vector<uint8_t> out;
    t.ok = dec.extract(file.size(), out) && out == file;
    return t;
}
 
int main() {
    using namespace coding;
 
    // ---------------------------------------------------------------- [1]
    std::printf("[1] GF(256) field laws (exhaustive)\n");
    {
        CHECK(gf::mul(2, 2) == 4);
        CHECK(gf::mul(0x80, 2) == 0x1D);               // reduction by 0x11D
        CHECK(gf::mul(0, 77) == 0 && gf::mul(77, 0) == 0 && gf::mul(1, 77) == 77);
        bool laws = true;
        for (int a = 1; a < 256; a++) {
            if (gf::mul((uint8_t)a, gf::inv((uint8_t)a)) != 1) laws = false;
            for (int b = 0; b < 256; b++) {
                if (gf::mul((uint8_t)a, (uint8_t)b) != gf::mul((uint8_t)b, (uint8_t)a)) laws = false;
                if (b != 0 && gf::divide(gf::mul((uint8_t)a, (uint8_t)b), (uint8_t)b) != a) laws = false;
            }
        }
        CHECK(laws);                                   // inverse, commutative, division
        bool distrib = true;
        for (int a = 0; a < 256 && distrib; a++)
            for (int b = 0; b < 256; b++)
                for (int c = 0; c < 256; c += 5)
                    if (gf::mul((uint8_t)a, (uint8_t)(b ^ c)) !=
                        (gf::mul((uint8_t)a, (uint8_t)b) ^ gf::mul((uint8_t)a, (uint8_t)c))) {
                        distrib = false;
                        break;
                    }
        CHECK(distrib);
        // associativity on random triples
        bool assoc = true;
        for (int i = 0; i < 20000; i++) {
            uint8_t a = (uint8_t)g_rng(), b = (uint8_t)g_rng(), c = (uint8_t)g_rng();
            if (gf::mul(gf::mul(a, b), c) != gf::mul(a, gf::mul(b, c))) assoc = false;
        }
        CHECK(assoc);
        // mul_add / scale agree with scalar math
        uint8_t src[5] = {1, 2, 3, 250, 0}, dst[5] = {9, 9, 9, 9, 9};
        gf::mul_add(dst, src, 7, 5);
        bool ma = true;
        for (int i = 0; i < 5; i++) if (dst[i] != (9 ^ gf::mul(7, src[i]))) ma = false;
        CHECK(ma);
        gf::scale(src, 5, 5);
        CHECK(src[2] == gf::mul(3, 5) && src[4] == 0);
    }
 
    // ---------------------------------------------------------------- [2]
    std::printf("[2] coefficient generator\n");
    {
        std::vector<uint8_t> a(50), b(50), c(50), d(50);
        make_coeffs(7, 3, 50, a.data());                       // systematic: unit vector
        bool unit = (a[3] == 1);
        for (int i = 0; i < 50; i++) if (i != 3 && a[i] != 0) unit = false;
        CHECK(unit);
 
        make_coeffs(7, 60, 50, a.data());                      // repair packet
        make_coeffs(7, 60, 50, b.data());
        CHECK(a == b);                                         // deterministic
        make_coeffs(7, 61, 50, c.data());
        CHECK(a != c);                                         // differs by seq
        make_coeffs(8, 60, 50, d.data());
        CHECK(a != d);                                         // differs by file_id
        int nz = 0;
        for (int i = 0; i < 50; i++) if (a[i]) nz++;
        CHECK(nz > 30);                                        // dense, not degenerate
        // golden value: catches accidental changes that would break client/server agreement
        std::vector<uint8_t> g(4);
        make_coeffs(1, 100, 4, g.data());
        std::printf("    golden coeffs for (file_id=1, seq=100, K=4): %02X %02X %02X %02X\n",
                    g[0], g[1], g[2], g[3]);
    }
 
    // ---------------------------------------------------------------- [3]
    std::printf("[3] round trip with 30%% loss and reordering, many file sizes\n");
    {
        const size_t sizes[] = {1, 2, 255, 256, 257, 1000, 1023, 1024, 1025, 2048, 5000, 100000};
        const uint32_t bss[] = {256, 1024, 1454};
        bool all = true;
        for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++)
            for (size_t bi = 0; bi < 3; bi++) {
                std::vector<uint8_t> f = random_file(sizes[si]);
                Trial t = run_trial(f, bss[bi], 0.30, 2.0, 1000 + (uint32_t)si, 40);
                if (!t.ok) {
                    all = false;
                    std::printf("    failed: size=%zu block=%u K=%u arrived=%u\n",
                                sizes[si], bss[bi], t.k, t.arrived);
                }
            }
        CHECK(all);
    }
 
    // ---------------------------------------------------------------- [4]
    std::printf("[4] edge cases\n");
    {
        const uint32_t bs = 128, id = 99;
        std::vector<uint8_t> f = random_file(1000);            // K = 8
        Encoder enc(f.data(), f.size(), bs);
        CHECK(enc.ok() && enc.k() == 8);
        std::vector<uint8_t> buf(bs), out;
 
        Decoder dec(id, enc.k(), bs);
        CHECK(dec.extract(f.size(), out) == false);            // nothing received yet
 
        // K-1 packets can never be enough
        for (uint32_t s = 100; s < 100 + enc.k() - 1; s++) {   // repair packets only
            enc.encode(id, s, buf.data());
            dec.add_packet(s, buf.data(), bs);
        }
        CHECK(!dec.complete() && dec.rank() == enc.k() - 1);
 
        // duplicate packet is not innovative
        enc.encode(id, 100, buf.data());
        CHECK(dec.add_packet(100, buf.data(), bs) == 0);
        // wrong payload length is rejected and not counted
        uint32_t before = dec.received();
        CHECK(dec.add_packet(5, buf.data(), bs - 1) == -1);
        CHECK(dec.received() == before);
 
        // one more independent packet finishes it (repair-only decode, all-dense matrix)
        for (uint32_t s = 200; !dec.complete() && s < 260; s++) {
            enc.encode(id, s, buf.data());
            dec.add_packet(s, buf.data(), bs);
        }
        CHECK(dec.complete());
        CHECK(dec.extract(f.size() + bs, out) == false);       // inconsistent file size
        CHECK(dec.extract(f.size(), out) && out == f);
        CHECK(dec.extract(f.size(), out) && out == f);         // extract twice is safe
 
        // packets still arriving after completion are harmless
        enc.encode(id, 7, buf.data());
        CHECK(dec.add_packet(7, buf.data(), bs) == 0);
 
        // zero loss: source packets only, decoder does no real elimination
        Trial z = run_trial(f, bs, 0.0, 1.0, 5);
        CHECK(z.ok && z.used == z.k);
 
        // 1-byte file (K = 1) and invalid encoder inputs
        std::vector<uint8_t> one(1, 0xAB);
        CHECK(run_trial(one, 64, 0.5, 6.0, 3, 40).ok);
        Encoder bad1(f.data(), 0, 64);
        CHECK(!bad1.ok());
        std::vector<uint8_t> huge((size_t)(MAX_K + 1) * 8, 1);
        Encoder bad2(huge.data(), huge.size(), 8);
        CHECK(!bad2.ok());                                     // K > MAX_K
    }
 
    // ---------------------------------------------------------------- [5]
    std::printf("[5] loss experiment: K=100 blocks, 200 trials per row\n");
    std::printf("    loss  sent  success   avg packets used   overhead vs K\n");
    {
        const double losses[] = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5};
        std::vector<uint8_t> f = random_file(100 * 64);
        for (size_t li = 0; li < 6; li++) {
            double loss = losses[li];
            double redundancy = 1.25 / (1.0 - loss);           // sends 25% more than strictly needed
            int wins = 0, trials = 200;
            double used_sum = 0;
            uint32_t sent = 0;
            for (int i = 0; i < trials; i++) {
                Trial t = run_trial(f, 64, loss, redundancy, 5000 + (uint32_t)i);
                sent = t.sent;
                if (t.ok) { wins++; used_sum += t.used; }
            }
            double avg = wins ? used_sum / wins : 0;
            std::printf("    %3.0f%%  %4u  %5.1f%%   %16.2f   %+10.1f%%\n",
                        loss * 100, sent, 100.0 * wins / trials, avg,
                        wins ? (avg / 100.0 - 1.0) * 100.0 : 0.0);
            if (loss <= 0.3) CHECK(wins == trials);            // must be reliable with 25% spare
        }
    }
 
    // ---------------------------------------------------------------- [6]
    std::printf("[6] speed: 1 MiB file, 1024-byte blocks (K = 1024), 30%% loss\n");
    {
        std::vector<uint8_t> f = random_file(1024 * 1024);
        auto t0 = std::chrono::steady_clock::now();
        Trial t = run_trial(f, 1024, 0.30, 1.5, 77);
        double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        CHECK(t.ok);
        std::printf("    ok=%d  K=%u  sent=%u  arrived=%u  used=%u  time=%.2f s\n",
                    t.ok ? 1 : 0, t.k, t.sent, t.arrived, t.used, sec);
    }
 
    if (g_fail == 0) std::printf("\nALL TESTS PASSED\n");
    else             std::printf("\n%d CHECK(S) FAILED\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
 