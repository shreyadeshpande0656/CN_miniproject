// client.cpp - erasure-coded UDP file sender.
//
//   client <server_ip> <port> <file> [options]
//
//   --redundancy R   send ceil(K*R) packets up front (default 1.5; 1.0 = plain, no spare)
//   --block N        block size in bytes (default: 1024, raised automatically for big files)
//   --loss P         simulate packet loss: drop each outgoing packet with probability P (0..0.99)
//   --corrupt P      flip one random bit in a packet with probability P (tests the CRC check)
//   --seed S         seed of the loss/corruption simulator (same seed = same pattern)
//   --rate N         pacing in packets per second (default 3000, 0 = as fast as possible)
//   --max-extra N    after the first batch, how many EXTRA repair packets may be sent while
//                    waiting for the server's DONE (default 5*K+200; 0 = never send more)
//   --timeout S      give up after S seconds (default 30)
//   --delay-meta N   send the metadata packet only after N data packets (tests "data before META")
//
// The code is rateless: any packet number seq can be generated at any time, so if the
// server is not done yet, the client simply keeps sending fresh repair packets.
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>
 
#include "coding.h"
#include "net_compat.h"
#include "packet.h"
 
typedef std::chrono::steady_clock Clock;
 
static double elapsed(Clock::time_point t0) {
    return std::chrono::duration<double>(Clock::now() - t0).count();
}
 
// ---------------------------------------------------------------------------
// command line
// ---------------------------------------------------------------------------
struct Options {
    std::string    ip, path;
    unsigned short port       = 0;
    uint32_t       block      = 0;        // 0 = automatic
    double         redundancy = 1.5;
    double         loss       = 0.0;
    double         corrupt    = 0.0;
    uint32_t       seed       = 1;
    int            rate       = 3000;
    long           max_extra  = -1;       // -1 = automatic
    double         timeout    = 30.0;
    uint32_t       delay_meta = 0;
};
 
static void usage() {
    std::printf(
        "usage: client <server_ip> <port> <file> [options]\n"
        "  --redundancy R   packets sent up front = ceil(K*R)        (default 1.5)\n"
        "  --block N        block size in bytes                      (default 1024, auto-raised)\n"
        "  --loss P         simulated loss probability 0..0.99       (default 0)\n"
        "  --corrupt P      simulated bit-flip probability 0..1      (default 0)\n"
        "  --seed S         seed of the loss simulator               (default 1)\n"
        "  --rate N         packets per second, 0 = unlimited        (default 3000)\n"
        "  --max-extra N    extra repair packets allowed after the first batch (0 = none)\n"
        "  --timeout S      give up after S seconds                  (default 30)\n"
        "  --delay-meta N   send metadata only after N data packets  (default 0)\n"
        "example: client 127.0.0.1 9000 tests/sample.bin --loss 0.3\n");
}
 
static bool parse_args(int argc, char** argv, Options& o) {
    int pos = 0;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a.size() > 2 && a[0] == '-' && a[1] == '-') {
            if (i + 1 >= argc) { std::printf("missing value for %s\n", a.c_str()); return false; }
            const char* v = argv[++i];
            if      (a == "--redundancy") o.redundancy = std::atof(v);
            else if (a == "--block")      o.block      = (uint32_t)std::atoi(v);
            else if (a == "--loss")       o.loss       = std::atof(v);
            else if (a == "--corrupt")    o.corrupt    = std::atof(v);
            else if (a == "--seed")       o.seed       = (uint32_t)std::atoi(v);
            else if (a == "--rate")       o.rate       = std::atoi(v);
            else if (a == "--max-extra")  o.max_extra  = std::atol(v);
            else if (a == "--timeout")    o.timeout    = std::atof(v);
            else if (a == "--delay-meta") o.delay_meta = (uint32_t)std::atoi(v);
            else { std::printf("unknown option %s\n", a.c_str()); return false; }
        } else {
            if      (pos == 0) o.ip   = a;
            else if (pos == 1) o.port = (unsigned short)std::atoi(a.c_str());
            else if (pos == 2) o.path = a;
            else { std::printf("unexpected argument %s\n", a.c_str()); return false; }
            pos++;
        }
    }
    if (pos != 3) return false;
    if (o.port == 0)                                  { std::printf("bad port\n"); return false; }
    if (o.redundancy < 1.0)                           { std::printf("--redundancy must be >= 1.0\n"); return false; }
    if (o.loss < 0.0 || o.loss > 0.99)                { std::printf("--loss must be in 0..0.99\n"); return false; }
    if (o.corrupt < 0.0 || o.corrupt > 1.0)           { std::printf("--corrupt must be in 0..1\n"); return false; }
    if (o.block > pkt::MAX_BLOCK)                     { std::printf("--block must be <= %lu\n", (unsigned long)pkt::MAX_BLOCK); return false; }
    if (o.rate < 0 || o.timeout <= 0.0)               { std::printf("bad --rate or --timeout\n"); return false; }
    return true;
}
 
static bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    out.clear();
    uint8_t buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.insert(out.end(), buf, buf + n);
    std::fclose(f);
    return true;
}
 
static std::string base_name(const std::string& p) {
    size_t pos = p.find_last_of("/\\");
    return pos == std::string::npos ? p : p.substr(pos + 1);
}
 
// ---------------------------------------------------------------------------
// sender: loss/corruption simulation, pacing, counters
// ---------------------------------------------------------------------------
struct Tx {
    sock_t              s;
    sockaddr_in         dst;
    std::mt19937        rng;
    double              loss, corrupt;
    int                 rate;
    uint32_t            attempted, dropped, corrupted, transmitted;
    unsigned long       bytes;
    Clock::time_point   pace_base;
    uint32_t            pace_n;
 
    Tx(sock_t sock, const sockaddr_in& d, uint32_t seed, double l, double c, int r)
        : s(sock), dst(d), rng(seed), loss(l), corrupt(c), rate(r),
          attempted(0), dropped(0), corrupted(0), transmitted(0), bytes(0),
          pace_base(Clock::now()), pace_n(0) {}
 
    // Own mapping (not std::uniform_real_distribution) so that the same --seed gives the
    // same loss pattern with every compiler and OS.
    double rnd() { return (double)(rng() & 0xFFFFFF) / 16777216.0; }
 
    void send(const std::vector<uint8_t>& packet) {
        attempted++;
        if (loss > 0.0 && rnd() < loss) { dropped++; return; }
        std::vector<uint8_t> b = packet;
        if (corrupt > 0.0 && rnd() < corrupt) {
            size_t idx = rng() % b.size();
            b[idx] ^= (uint8_t)(1u << (rng() % 8));
            corrupted++;
        }
        int r = sendto(s, (const char*)b.data(), (int)b.size(), 0, (sockaddr*)&dst, sizeof(dst));
        if (r < 0) {
            static bool warned = false;
            if (!warned) { std::printf("sendto() failed: %d\n", net_errno()); warned = true; }
            return;
        }
        transmitted++;
        bytes += (unsigned long)b.size();
    }
 
    void pace_reset() { pace_base = Clock::now(); pace_n = 0; }
    void pace() {
        if (rate <= 0) return;
        pace_n++;
        double target = (double)pace_n / (double)rate;
        double now    = elapsed(pace_base);
        if (target > now) sleep_us((unsigned)((target - now) * 1e6));
    }
};
 
struct Reply {
    bool     got    = false;
    uint8_t  status = 0;
    uint32_t used   = 0;
};
 
// Non-blocking: drain the socket, look for our DONE.
static bool poll_done(sock_t s, uint32_t file_id, Reply& r) {
    char rbuf[2048];
    for (;;) {
        int n = recvfrom(s, rbuf, sizeof(rbuf), 0, NULL, NULL);
        if (n < 0) return r.got;                      // nothing (more) to read
        pkt::Packet p;
        if (pkt::decode((const uint8_t*)rbuf, (size_t)n, p) == pkt::PKT_OK &&
            p.type == pkt::T_DONE && p.file_id == file_id) {
            r.got = true; r.status = p.status; r.used = p.packets_used;
            return true;
        }
    }
}
 
static bool wait_done(sock_t s, uint32_t file_id, Reply& r, double seconds) {
    Clock::time_point t = Clock::now();
    while (elapsed(t) < seconds) {
        if (poll_done(s, file_id, r)) return true;
        sleep_us(2000);
    }
    return poll_done(s, file_id, r);
}
 
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    std::setvbuf(stdout, NULL, _IONBF, 0);
 
    Options o;
    if (!parse_args(argc, argv, o)) { usage(); return 2; }
 
    // ---- 1. read the file ----
    std::vector<uint8_t> data;
    if (!read_file(o.path, data)) { std::printf("cannot read '%s'\n", o.path.c_str()); return 2; }
    if (data.empty()) { std::printf("'%s' is empty; empty files are not supported\n", o.path.c_str()); return 2; }
 
    // ---- 2. block size, encoder ----
    uint32_t bs = o.block;
    if (bs == 0) {
        bs = (uint32_t)pkt::DEFAULT_BLOCK;
        if (coding::blocks_needed(data.size(), bs) > coding::MAX_K) {
            uint64_t need = (data.size() + coding::MAX_K - 1) / coding::MAX_K;
            if (need > pkt::MAX_BLOCK) bs = 0;
            else                       bs = (uint32_t)need;
        }
    }
    coding::Encoder enc(data.data(), data.size(), bs ? bs : 1);
    if (bs == 0 || !enc.ok()) {
        std::printf("file too large: at most %lu bytes (K <= %lu blocks of <= %lu bytes) "
                    "until generation-based coding is added\n",
                    (unsigned long)((uint64_t)coding::MAX_K * pkt::MAX_BLOCK),
                    (unsigned long)coding::MAX_K, (unsigned long)pkt::MAX_BLOCK);
        return 2;
    }
    const uint32_t K = enc.k();
    uint32_t N = (uint32_t)std::ceil((double)K * o.redundancy);
    if (N < K) N = K;
    const uint32_t file_crc = crc32(data.data(), data.size());
    const std::string name = base_name(o.path);
 
    uint64_t tnow = (uint64_t)std::chrono::system_clock::now().time_since_epoch().count();
    const uint32_t file_id = (uint32_t)(tnow ^ (tnow >> 32) ^ 0x9E3779B9u);
 
    // ---- 3. socket ----
    if (!net_init()) { std::printf("network init failed\n"); return 2; }
    sock_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == SOCK_BAD) { std::printf("socket() failed: %d\n", net_errno()); return 2; }
    sock_disable_udp_connreset(s);
    sock_set_nonblocking(s, true);
    sockaddr_in dst;
    if (!make_addr(dst, o.ip.c_str(), o.port)) {
        std::printf("bad server address '%s' (use a numeric IP such as 127.0.0.1)\n", o.ip.c_str());
        return 2;
    }
 
    std::printf("sending '%s' (%lu bytes) to %s:%u\n", name.c_str(), (unsigned long)data.size(),
                o.ip.c_str(), (unsigned)o.port);
    std::printf("  K = %lu blocks of %lu bytes, file id %08lX, file crc32 %08lX\n",
                (unsigned long)K, (unsigned long)bs, (unsigned long)file_id, (unsigned long)file_crc);
    std::printf("  first batch: %lu packets (redundancy %.2f), simulated loss %.0f%%, corruption %.0f%%\n",
                (unsigned long)N, o.redundancy, o.loss * 100.0, o.corrupt * 100.0);
 
    Tx tx(s, dst, o.seed, o.loss, o.corrupt, o.rate);
    Reply reply;
    uint32_t seq = 0;                 // next packet number to generate (0..K-1 source, K.. repair)
    uint32_t meta_sent = 0;
    std::vector<uint8_t> payload(bs);
 
    auto send_meta = [&](int copies) {
        std::vector<uint8_t> m = pkt::encode(
            pkt::make_meta(file_id, data.size(), (uint16_t)bs, K, file_crc, name));
        for (int c = 0; c < copies; c++) { tx.send(m); meta_sent++; }
    };
    auto send_data = [&]() {
        enc.encode(file_id, seq, payload.data());
        tx.send(pkt::encode(pkt::make_data(file_id, seq, payload.data(), bs)));
        seq++;
    };
    // metadata: a burst at the start (or at --delay-meta), then one copy every 32 packets
    auto meta_due = [&](uint32_t i) {
        if (i == o.delay_meta) send_meta(3);
        else if (i > o.delay_meta && (i - o.delay_meta) % 32 == 0) send_meta(1);
    };
 
    Clock::time_point t0 = Clock::now();
 
    // ---- 4. first batch ----
    tx.pace_reset();
    for (uint32_t i = 0; i < N && !reply.got; i++) {
        meta_due(seq);
        send_data();
        tx.pace();
        poll_done(s, file_id, reply);
    }
 
    // ---- 5. not done yet: keep sending fresh repair packets until DONE ----
    uint32_t extra_cap = (o.max_extra >= 0) ? (uint32_t)o.max_extra : 5 * K + 200;
    uint32_t extra = 0;
    int      rounds = 0;
    double   idle_after_cap = 0.0;
    while (!reply.got && elapsed(t0) < o.timeout) {
        // Short pauses: DONE normally arrives within a few ms, and the longer we wait,
        // the longer a transfer that needs top-up packets takes. The pause grows a bit
        // so a slow-to-decode server is not flooded.
        double w = 0.05 + 0.03 * rounds;
        if (w > 0.25) w = 0.25;
        rounds++;
        if (wait_done(s, file_id, reply, w)) break;
        if (extra >= extra_cap) {
            idle_after_cap += w;
            if (idle_after_cap >= 1.5) break;         // nothing more to send, stop waiting
            continue;
        }
        send_meta(1);
        uint32_t batch = K / 10 > 16 ? K / 10 : 16;
        tx.pace_reset();
        for (uint32_t b = 0; b < batch && extra < extra_cap && !reply.got; b++) {
            send_data();
            extra++;
            tx.pace();
            poll_done(s, file_id, reply);
        }
    }
    double secs = elapsed(t0);
 
    // ---- 6. report ----
    const uint32_t generated = seq;
    std::printf("\n---- client summary ----\n");
    std::printf("data packets generated : %lu  (planned first batch %lu, extra top-up packets %lu)\n",
                (unsigned long)generated, (unsigned long)N, (unsigned long)extra);
    std::printf("metadata packets       : %lu\n", (unsigned long)meta_sent);
    std::printf("dropped by simulator   : %lu of %lu  (%.1f%%)\n", (unsigned long)tx.dropped,
                (unsigned long)tx.attempted,
                tx.attempted ? 100.0 * tx.dropped / tx.attempted : 0.0);
    if (tx.corrupted) std::printf("corrupted on purpose   : %lu\n", (unsigned long)tx.corrupted);
    std::printf("sent on the network    : %lu packets, %lu bytes\n",
                (unsigned long)tx.transmitted, tx.bytes);
    std::printf("time                   : %.2f s  (%.0f KB/s of file data)\n", secs,
                secs > 0 ? data.size() / 1024.0 / secs : 0.0);
 
    int rc;
    if (reply.got && reply.status == 1) {
        std::printf("server reply           : DONE, file rebuilt and CRC ok (decoder used %lu packets for K = %lu)\n",
                    (unsigned long)reply.used, (unsigned long)K);
        rc = 0;
    } else if (reply.got) {
        std::printf("server reply           : DONE but the rebuilt file FAILED the CRC check\n");
        rc = 1;
    } else {
        std::printf("server reply           : none (server not running, or too many packets lost)\n");
        rc = 1;
    }
    std::printf("RESULT role=client ok=%d K=%lu block=%lu generated=%lu dropped=%lu transmitted=%lu time=%.3f\n",
                rc == 0 ? 1 : 0, (unsigned long)K, (unsigned long)bs, (unsigned long)generated,
                (unsigned long)tx.dropped, (unsigned long)tx.transmitted, secs);
 
    sock_close(s);
    net_cleanup();
    return rc;
}
 