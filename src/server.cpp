// server.cpp - erasure-coded UDP file receiver.
//
//   server <port> <out_dir> [--once] [--timeout S]
//
//   --once        exit after the first transfer finishes (handy for demos and scripts)
//   --timeout S   give up on a transfer after S seconds without any packet (default 20)
//
// For every transfer (identified by file_id) the server keeps a Decoder. DATA packets are
// fed into it as they arrive (in any order, with gaps, with duplicates). As soon as K
// independent packets are in, it rebuilds the file, checks the CRC32 from the metadata,
// writes the file to out_dir and tells the client with a DONE packet.
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>
 
#include "coding.h"
#include "net_compat.h"
#include "packet.h"
 
typedef std::chrono::steady_clock Clock;
 
static double secs_between(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double>(b - a).count();
}
 
struct Pending {                       // DATA packet that arrived before its METADATA
    uint32_t             seq;
    std::vector<uint8_t> payload;
};
 
struct Session {
    uint32_t    file_id = 0;
    bool        have_meta = false;
    uint64_t    file_size = 0;
    uint32_t    block_size = 0, k = 0, file_crc = 0;
    std::string name;
    std::unique_ptr<coding::Decoder> dec;
    sockaddr_in client;
    bool        finished = false, success = false;
    uint32_t    packets_used = 0;
    uint32_t    data_packets = 0;      // valid DATA packets seen for this transfer
    uint32_t    progress_next = 1;     // next 10% step to announce
    Clock::time_point first_seen, last_seen, last_done_sent;
    std::vector<Pending> pending;
 
    Session() { std::memset(&client, 0, sizeof(client)); }
};
 
struct Server {
    sock_t       sock = SOCK_BAD;
    std::string  out_dir;
    double       idle_timeout = 20.0;
    bool         once = false;
    std::map<uint32_t, std::unique_ptr<Session> > sessions;
    unsigned long datagrams = 0;
    unsigned long rejected[8] = {0, 0, 0, 0, 0, 0, 0, 0};   // indexed by pkt::Status
    bool         lingering = false;
    Clock::time_point linger_until;
    bool         stop = false;
    int          exit_code = 0;
};
 
static const size_t   MAX_SESSIONS = 16;
static const size_t   MAX_PENDING  = 2 * coding::MAX_K;
 
// Small string helpers (no sprintf/snprintf: they differ between old MinGW and macOS).
static std::string num_str(unsigned long v) {
    char tmp[24];
    int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v > 0) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    std::string s;
    while (n > 0) s += tmp[--n];
    return s;
}
static std::string hex8(uint32_t v) {
    const char* d = "0123456789abcdef";
    std::string s(8, '0');
    for (int i = 7; i >= 0; i--) { s[(size_t)i] = d[v & 0xF]; v >>= 4; }
    return s;
}
static std::string addr_str(const sockaddr_in& a) {
    return std::string(inet_ntoa(a.sin_addr)) + ":" + num_str(ntohs(a.sin_port));
}
 
// Never trust a file name from the network: keep only the last path component and
// harmless characters, so "../../x" or "C:\\Windows\\x" cannot escape out_dir.
static std::string safe_name(const std::string& in, uint32_t id) {
    size_t pos = in.find_last_of("/\\");
    std::string base = (pos == std::string::npos) ? in : in.substr(pos + 1);
    std::string out;
    for (size_t i = 0; i < base.size(); i++) {
        unsigned char c = (unsigned char)base[i];
        if (std::isalnum(c) || c == '.' || c == '_' || c == '-') out += (char)c;
        else out += '_';
    }
    while (!out.empty() && out[0] == '.') out.erase(0, 1);
    if (out.size() > 100) out.resize(100);
    if (out.empty()) out = "file_" + hex8(id) + ".bin";
    return out;
}
 
static bool write_file(const std::string& path, const std::vector<uint8_t>& d) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    size_t w = std::fwrite(d.data(), 1, d.size(), f);
    int c = std::fclose(f);
    return w == d.size() && c == 0;
}
 
static void send_done(Server& srv, Session& s, int copies) {
    std::vector<uint8_t> b = pkt::encode(pkt::make_done(s.file_id, s.success ? 1 : 0, s.packets_used));
    for (int i = 0; i < copies; i++)
        sendto(srv.sock, (const char*)b.data(), (int)b.size(), 0, (sockaddr*)&s.client, sizeof(s.client));
    s.last_done_sent = Clock::now();
}
 
// The client may still be sending (our DONE can be lost too): answer again, but not
// for every single packet.
static void resend_done_limited(Server& srv, Session& s) {
    if (secs_between(s.last_done_sent, Clock::now()) > 0.01) send_done(srv, s, 1);
}
 
static void finish(Server& srv, Session& s) {
    Clock::time_point now = Clock::now();
    double secs = secs_between(s.first_seen, now);
    uint32_t received = s.dec->received();
    uint32_t wasted   = s.dec->non_innovative();
 
    std::vector<uint8_t> out;
    bool ok = s.dec->extract(s.file_size, out);
    uint32_t crc = ok ? crc32(out.data(), out.size()) : 0;
    bool crc_ok = ok && crc == s.file_crc;
 
    std::string path = srv.out_dir + "/" + safe_name(s.name, s.file_id);
    bool written = false;
    if (crc_ok) {
        written = write_file(path, out);
        if (!written)
            std::printf("  cannot write '%s' (does the folder exist?)\n", path.c_str());
    }
    s.success      = crc_ok && written;
    s.finished     = true;
    s.packets_used = received;
 
    std::printf("\n---- transfer %08lX finished ----\n", (unsigned long)s.file_id);
    if (s.success) std::printf("file rebuilt            : %s  (%lu bytes)\n", path.c_str(), (unsigned long)s.file_size);
    else if (!crc_ok) std::printf("file NOT saved          : CRC32 mismatch (expected %08lX, got %08lX)\n",
                                   (unsigned long)s.file_crc, (unsigned long)crc);
    std::printf("K                       : %lu blocks of %lu bytes\n", (unsigned long)s.k, (unsigned long)s.block_size);
    std::printf("packets needed to decode: %lu  (%lu not independent, overhead %.2f%%)\n",
                (unsigned long)received, (unsigned long)wasted,
                100.0 * ((double)received / (double)s.k - 1.0));
    std::printf("invalid datagrams so far: %lu  (bad CRC/magic/format, all ignored)\n",
                srv.rejected[pkt::PKT_TOO_SHORT] + srv.rejected[pkt::PKT_BAD_MAGIC] +
                srv.rejected[pkt::PKT_BAD_VERSION] + srv.rejected[pkt::PKT_BAD_CRC] +
                srv.rejected[pkt::PKT_BAD_TYPE] + srv.rejected[pkt::PKT_BAD_FIELD]);
    std::printf("                          of which bad CRC: %lu\n", srv.rejected[pkt::PKT_BAD_CRC]);
    std::printf("time since first packet : %.2f s\n", secs);
    std::printf("RESULT role=server ok=%d K=%lu used=%lu wasted=%lu crc_rejected=%lu time=%.3f\n",
                s.success ? 1 : 0, (unsigned long)s.k, (unsigned long)received,
                (unsigned long)wasted, srv.rejected[pkt::PKT_BAD_CRC], secs);
 
    s.dec.reset();                     // free the decoder memory
    s.pending.clear();
    send_done(srv, s, 3);
 
    if (srv.once) {
        srv.lingering   = true;        // stay a moment to re-answer a client that missed DONE
        srv.linger_until = now + std::chrono::seconds(2);
        srv.exit_code   = s.success ? 0 : 1;
    }
}
 
// Feed one DATA payload into the session's decoder.
static void feed(Server& srv, Session& s, uint32_t seq, const uint8_t* payload, size_t len) {
    int r = s.dec->add_packet(seq, payload, len);
    if (r < 0) return;
    s.data_packets++;
    if (r == 1) {
        while (s.progress_next <= 9 && (uint64_t)s.dec->rank() * 10 >= (uint64_t)s.progress_next * s.k) {
            std::printf("  progress %2lu%%  (rank %lu / %lu, %lu packets received)\n",
                        (unsigned long)(s.progress_next * 10), (unsigned long)s.dec->rank(),
                        (unsigned long)s.k, (unsigned long)s.dec->received());
            s.progress_next++;
        }
    }
    if (s.dec->complete()) finish(srv, s);
}
 
static void on_meta(Server& srv, Session& s, const pkt::Packet& p) {
    if (s.finished) { resend_done_limited(srv, s); return; }
    if (s.have_meta) return;                           // repeated metadata: nothing to do
    if (p.k > coding::MAX_K) {
        std::printf("transfer %08lX rejected: K = %lu is above the limit of %lu\n",
                    (unsigned long)p.file_id, (unsigned long)p.k, (unsigned long)coding::MAX_K);
        return;
    }
    s.have_meta  = true;
    s.file_size  = p.file_size;
    s.block_size = p.block_size;
    s.k          = p.k;
    s.file_crc   = p.file_crc;
    s.name       = p.filename;
    s.dec.reset(new coding::Decoder(s.file_id, s.k, s.block_size));
    std::printf("transfer %08lX: '%s', %lu bytes, K = %lu blocks of %lu bytes\n",
                (unsigned long)s.file_id, s.name.c_str(), (unsigned long)s.file_size,
                (unsigned long)s.k, (unsigned long)s.block_size);
 
    if (!s.pending.empty())
        std::printf("  replaying %lu packets that arrived before the metadata\n", (unsigned long)s.pending.size());
    std::vector<Pending> early;
    early.swap(s.pending);
    for (size_t i = 0; i < early.size() && !s.finished; i++)
        feed(srv, s, early[i].seq, early[i].payload.data(), early[i].payload.size());
}
 
static void on_data(Server& srv, Session& s, const pkt::Packet& p) {
    if (s.finished) { resend_done_limited(srv, s); return; }
    if (!s.have_meta) {                                // keep it until the metadata shows up
        if (s.pending.size() < MAX_PENDING) {
            Pending pd;
            pd.seq = p.seq;
            pd.payload = p.payload;
            s.pending.push_back(pd);
        }
        return;
    }
    feed(srv, s, p.seq, p.payload.data(), p.payload.size());
}
 
static Session* get_session(Server& srv, uint32_t id, const sockaddr_in& from) {
    std::map<uint32_t, std::unique_ptr<Session> >::iterator it = srv.sessions.find(id);
    if (it != srv.sessions.end()) return it->second.get();
    if (srv.sessions.size() >= MAX_SESSIONS) return NULL;
    std::unique_ptr<Session> s(new Session());
    s->file_id = id;
    s->client = from;
    s->first_seen = s->last_seen = s->last_done_sent = Clock::now();
    std::printf("new transfer %08lX from %s\n", (unsigned long)id, addr_str(from).c_str());
    Session* raw = s.get();
    srv.sessions[id] = std::move(s);
    return raw;
}
 
static void handle_datagram(Server& srv, const uint8_t* buf, size_t n, const sockaddr_in& from) {
    srv.datagrams++;
    pkt::Packet p;
    pkt::Status st = pkt::decode(buf, n, p);
    if (st != pkt::PKT_OK) { srv.rejected[(int)st]++; return; }
    if (p.type == pkt::T_DONE) return;                 // not meant for a server
 
    Session* s = get_session(srv, p.file_id, from);
    if (!s) return;
    s->last_seen = Clock::now();
    s->client = from;
    if (p.type == pkt::T_META) on_meta(srv, *s, p);
    else                       on_data(srv, *s, p);
}
 
// Give up on transfers that went silent and say what was missing.
static void sweep(Server& srv) {
    Clock::time_point now = Clock::now();
    for (std::map<uint32_t, std::unique_ptr<Session> >::iterator it = srv.sessions.begin();
         it != srv.sessions.end();) {
        Session& s = *it->second;
        if (!s.finished && secs_between(s.last_seen, now) > srv.idle_timeout) {
            std::printf("\n---- transfer %08lX FAILED: no packets for %.0f s ----\n",
                        (unsigned long)s.file_id, srv.idle_timeout);
            if (s.have_meta) {
                std::printf("rank reached %lu of K = %lu: at least %lu more independent packets were needed\n",
                            (unsigned long)s.dec->rank(), (unsigned long)s.k,
                            (unsigned long)(s.k - s.dec->rank()));
                std::printf("RESULT role=server ok=0 K=%lu rank=%lu\n", (unsigned long)s.k, (unsigned long)s.dec->rank());
            } else {
                std::printf("the metadata packet never arrived (%lu data packets were waiting)\n",
                            (unsigned long)s.pending.size());
            }
            if (srv.once) { srv.stop = true; srv.exit_code = 1; }
            it = srv.sessions.erase(it);
        } else {
            ++it;
        }
    }
    if (srv.lingering && now >= srv.linger_until) srv.stop = true;
}
 
static void usage() {
    std::printf("usage: server <port> <out_dir> [--once] [--timeout S]\n"
                "example: server 9000 received\n");
}
 
int main(int argc, char** argv) {
    std::setvbuf(stdout, NULL, _IONBF, 0);
 
    Server srv;
    unsigned short port = 0;
    int pos = 0;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--once") srv.once = true;
        else if (a == "--timeout" && i + 1 < argc) srv.idle_timeout = std::atof(argv[++i]);
        else if (a.size() > 1 && a[0] == '-' && a[1] == '-') { usage(); return 2; }
        else if (pos == 0) { port = (unsigned short)std::atoi(a.c_str()); pos++; }
        else if (pos == 1) { srv.out_dir = a; pos++; }
        else { usage(); return 2; }
    }
    if (pos != 2 || port == 0 || srv.idle_timeout <= 0.0) { usage(); return 2; }
    while (srv.out_dir.size() > 1 && (srv.out_dir.back() == '/' || srv.out_dir.back() == '\\'))
        srv.out_dir.erase(srv.out_dir.size() - 1);
 
    if (!net_init()) { std::printf("network init failed\n"); return 2; }
    srv.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (srv.sock == SOCK_BAD) { std::printf("socket() failed: %d\n", net_errno()); return 2; }
    sock_disable_udp_connreset(srv.sock);
    sock_set_rcvbuf(srv.sock, 4 * 1024 * 1024);         // absorb bursts from the client
    sock_set_recv_timeout(srv.sock, 200);               // wake up regularly for timeouts
 
    sockaddr_in me;
    make_addr(me, NULL, port);
    if (bind(srv.sock, (sockaddr*)&me, sizeof(me)) != 0) {
        std::printf("bind() failed: %d (port %u already in use?)\n", net_errno(), (unsigned)port);
        return 2;
    }
    std::printf("server listening on UDP port %u, saving files to '%s'%s\n", (unsigned)port,
                srv.out_dir.c_str(), srv.once ? "  (will exit after one transfer)" : "");
 
    char rbuf[2048];
    while (!srv.stop) {
        sockaddr_in from;
        socklen_c   fl = sizeof(from);
        std::memset(&from, 0, sizeof(from));
        int n = recvfrom(srv.sock, rbuf, sizeof(rbuf), 0, (sockaddr*)&from, &fl);
        if (n >= 0) {
            handle_datagram(srv, (const uint8_t*)rbuf, (size_t)n, from);
        } else if (!net_is_timeout()) {
            std::printf("recvfrom() failed: %d\n", net_errno());
            sleep_us(100000);
        }
        sweep(srv);
    }
 
    sock_close(srv.sock);
    net_cleanup();
    return srv.exit_code;
}
 