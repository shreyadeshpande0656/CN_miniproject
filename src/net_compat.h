// net_compat.h
// Thin cross-platform socket layer (Windows Winsock / POSIX).
// Written for MinGW.org GCC 6.3 -> compile with -std=c++14, link with -lws2_32.
#ifndef NET_COMPAT_H
#define NET_COMPAT_H
 
#include <cstdio>
#include <cstring>
 
#ifdef _WIN32
  #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0601
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
 
  typedef SOCKET sock_t;
  typedef int    socklen_c;
  #define SOCK_BAD INVALID_SOCKET
 
  inline bool net_init() {
      WSADATA w;
      return WSAStartup(MAKEWORD(2, 2), &w) == 0;
  }
  inline void net_cleanup() { WSACleanup(); }
  inline void sock_close(sock_t s) { closesocket(s); }
  inline int  net_errno() { return WSAGetLastError(); }
 
  inline bool sock_set_nonblocking(sock_t s, bool on) {
      u_long mode = on ? 1 : 0;
      return ioctlsocket(s, FIONBIO, &mode) == 0;
  }
  inline void sock_set_rcvbuf(sock_t s, int bytes) {
      setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char*)&bytes, sizeof(bytes));
  }
  // Windows Sleep() has millisecond granularity (often ~15 ms unless the timer
  // resolution is raised), so callers must not rely on short sleeps being exact.
  inline void sleep_us(unsigned us) {
      DWORD ms = (DWORD)((us + 999) / 1000);
      if (ms == 0) ms = 1;
      Sleep(ms);
  }
 
  // Windows quirk: SO_RCVTIMEO takes a DWORD in milliseconds.
  inline bool sock_set_recv_timeout(sock_t s, int ms) {
      DWORD t = (DWORD)ms;
      return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t)) == 0;
  }
  inline bool net_is_timeout() {
      int e = WSAGetLastError();
      return e == WSAETIMEDOUT || e == WSAEWOULDBLOCK;
  }
  // Windows quirk: after sendto() to a port nobody listens on, a later recvfrom()
  // fails with WSAECONNRESET (10054) because of the ICMP "port unreachable" reply.
  // This ioctl turns that behaviour off so UDP receive loops are not killed.
  inline void sock_disable_udp_connreset(sock_t s) {
      DWORD bytes = 0;
      BOOL  off   = FALSE;
      const DWORD kSioUdpConnReset = 0x9800000C;   // SIO_UDP_CONNRESET
      WSAIoctl(s, kSioUdpConnReset, &off, sizeof(off), NULL, 0, &bytes, NULL, NULL);
  }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/time.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <errno.h>
  #include <fcntl.h>
 
  typedef int       sock_t;
  typedef socklen_t socklen_c;
  #define SOCK_BAD (-1)
 
  inline bool net_init() { return true; }
  inline void net_cleanup() {}
  inline void sock_close(sock_t s) { close(s); }
  inline int  net_errno() { return errno; }
 
  inline bool sock_set_nonblocking(sock_t s, bool on) {
      int flags = fcntl(s, F_GETFL, 0);
      if (flags < 0) return false;
      flags = on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
      return fcntl(s, F_SETFL, flags) == 0;
  }
  inline void sock_set_rcvbuf(sock_t s, int bytes) {
      setsockopt(s, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
  }
  inline void sleep_us(unsigned us) { usleep(us); }
 
  inline bool sock_set_recv_timeout(sock_t s, int ms) {
      struct timeval tv;
      tv.tv_sec  = ms / 1000;
      tv.tv_usec = (ms % 1000) * 1000;
      return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
  }
  inline bool net_is_timeout() {
      return errno == EAGAIN || errno == EWOULDBLOCK;
  }
  inline void sock_disable_udp_connreset(sock_t) {}
#endif
 
// Fill a sockaddr_in. Uses inet_addr (present even on old MinGW; inet_pton is not).
inline bool make_addr(sockaddr_in& a, const char* ip, unsigned short port) {
    std::memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    if (ip == NULL) {                       // server: listen on all interfaces
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        return true;
    }
    unsigned long v = inet_addr(ip);
    if (v == INADDR_NONE) return false;
    a.sin_addr.s_addr = v;
    return true;
}
 
#endif // NET_COMPAT_H
 
