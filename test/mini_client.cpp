#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main() {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    unsigned char pkt[64]; int plen = 0;
    pkt[plen++] = 0x12; pkt[plen++] = 0x34; // id
    pkt[plen++] = 0; pkt[plen++] = 0;       // flags
    pkt[plen++] = 0; pkt[plen++] = 1;       // qd
    pkt[plen++] = 0; pkt[plen++] = 0; pkt[plen++] = 0; pkt[plen++] = 0; pkt[plen++] = 0; pkt[plen++] = 0;
    // qname: _FC9F5ED42C8A._tcp.local
    pkt[plen++] = 13; memcpy(pkt+plen, "_FC9F5ED42C8A", 13); plen += 13;
    pkt[plen++] = 4;  memcpy(pkt+plen, "_tcp", 4); plen += 4;
    pkt[plen++] = 5;  memcpy(pkt+plen, "local", 5); plen += 5;
    pkt[plen++] = 0;
    pkt[plen++] = 0; pkt[plen++] = 12; // PTR
    pkt[plen++] = 0; pkt[plen++] = 1;  // IN
    struct sockaddr_in dst; memset(&dst,0,sizeof(dst));
    dst.sin_family = AF_INET; dst.sin_port = htons(15353);
    dst.sin_addr.s_addr = inet_addr("127.0.0.1");
    printf("send %d bytes\n", plen);
    sendto(s, pkt, plen, 0, (struct sockaddr*)&dst, sizeof(dst));
    struct pollfd p; p.fd = s; p.events = POLLIN; p.revents = 0;
    int r = poll(&p, 1, 2000);
    printf("poll=%d\n", r);
    if (r > 0) {
        unsigned char buf[2048];
        int n = recv(s, buf, sizeof(buf), 0);
        printf("recv %d bytes, flags=%02x%02x\n", n, buf[2], buf[3]);
    }
    return 0;
}
