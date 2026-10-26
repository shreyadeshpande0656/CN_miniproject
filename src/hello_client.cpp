//cat > src/hello_client.cpp << 'EOF'
#include <cstdio>
#include <cstdlib>
#include "net_compat.h"

int main(int argc, char** argv) {
    const char*    ip   = (argc > 1) ? argv[1] : "127.0.0.1";
    unsigned short port = (argc > 2) ? (unsigned short)std::atoi(argv[2]) : 9000;
    if (!net_init()) { std::printf("net init failed\n"); return 1; }

    sock_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == SOCK_BAD) { std::printf("socket() failed: %d\n", net_errno()); return 1; }
    sock_disable_udp_connreset(s);
    sock_set_recv_timeout(s, 3000);

    sockaddr_in srv;
    if (!make_addr(srv, ip, port)) { std::printf("bad IP address: %s\n", ip); return 1; }

    const char* msg = "hello from client";
    int sent = sendto(s, msg, (int)std::strlen(msg), 0, (sockaddr*)&srv, sizeof(srv));
    if (sent < 0) { std::printf("sendto() failed: %d\n", net_errno()); return 1; }
    std::printf("sent %d bytes to %s:%u\n", sent, ip, (unsigned)port);

    char buf[1500];
    int n = recvfrom(s, buf, sizeof(buf) - 1, 0, NULL, NULL);
    if (n < 0) {
        if (net_is_timeout()) std::printf("no reply within 3 s (server not running? firewall?)\n");
        else                  std::printf("recvfrom() failed: %d\n", net_errno());
        return 1;
    }
    buf[n] = '\0';
    std::printf("reply: \"%s\"\n", buf);
    sock_close(s);
    net_cleanup();
    return 0;
}
//EOF