//cat > src/hello_server.cpp << 'EOF'
#include <cstdio>
#include <cstdlib>
#include "net_compat.h"

int main(int argc, char** argv) {
    unsigned short port = (argc > 1) ? (unsigned short)std::atoi(argv[1]) : 9000;
    if (!net_init()) { std::printf("net init failed\n"); return 1; }

    sock_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == SOCK_BAD) { std::printf("socket() failed: %d\n", net_errno()); return 1; }
    sock_disable_udp_connreset(s);

    sockaddr_in me;
    make_addr(me, NULL, port);
    if (bind(s, (sockaddr*)&me, sizeof(me)) != 0) {
        std::printf("bind() failed: %d (port in use?)\n", net_errno());
        return 1;
    }
    std::printf("hello_server listening on UDP port %u ...\n", (unsigned)port);

    char buf[1500];
    for (;;) {
        sockaddr_in from;
        socklen_c fl = sizeof(from);
        int n = recvfrom(s, buf, sizeof(buf) - 1, 0, (sockaddr*)&from, &fl);
        if (n < 0) { std::printf("recvfrom() failed: %d\n", net_errno()); break; }
        buf[n] = '\0';
        std::printf("got %d bytes from %s:%u -> \"%s\"\n", n,
                    inet_ntoa(from.sin_addr), (unsigned)ntohs(from.sin_port), buf);
        const char* reply = "hello back from server";
        sendto(s, reply, (int)std::strlen(reply), 0, (sockaddr*)&from, fl);
    }
    sock_close(s);
    net_cleanup();
    return 0;
}
//EOF