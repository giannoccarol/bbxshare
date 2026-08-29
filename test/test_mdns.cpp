// Test host (Linux): compila ShareService.cpp con Qt6Core e verifica
// che il responder mDNS risponda come si aspetta Android Quick Share.
// Build: g++ -fPIC test_mdns.cpp ../src/ShareService.cpp \
//   $(pkg-config --cflags --libs Qt6Core) -lpthread -o test_mdns
#include "../src/ShareService.hpp"

#include <QtCore/QCoreApplication>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fail(const char *msg)
{
    fprintf(stderr, "FAIL: %s\n", msg);
    return 1;
}

// invia query mDNS, ritorna la risposta (o -1)
static int query(int sock, const QByteArray &qname, int qtype,
                 unsigned char *resp, int respCap, int dstPort = 15353)
{
    QByteArray pkt;
    quint16 id = (quint16)(rand() & 0xFFFF), v;
    v = htons(id); pkt.append((const char *)&v, 2);
    v = 0; pkt.append((const char *)&v, 2);
    v = htons(1); pkt.append((const char *)&v, 2);
    v = 0; pkt.append((const char *)&v, 2);
    v = 0; pkt.append((const char *)&v, 2);
    v = 0; pkt.append((const char *)&v, 2);
    pkt.append(qname);
    v = htons(qtype); pkt.append((const char *)&v, 2);
    v = htons(1); pkt.append((const char *)&v, 2);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dstPort);
    dst.sin_addr.s_addr = inet_addr("127.0.0.1");
    sendto(sock, pkt.constData(), pkt.size(), 0, (struct sockaddr *)&dst, sizeof(dst));

    struct pollfd p;
    p.fd = sock; p.events = POLLIN; p.revents = 0;
    int pr = poll(&p, 1, 2000);
    if (pr <= 0) {
        fprintf(stderr, "DBG: poll=%d errno=%d (pkt %d byte)\n", pr, errno, pkt.size());
        return -1;
    }
    struct sockaddr_in src;
    socklen_t sl = sizeof(src);
    int n = recvfrom(sock, resp, respCap, 0, (struct sockaddr *)&src, &sl);
    return n;
}

static bool containsTxt(const unsigned char *buf, int n, const char *needle)
{
    return memmem(buf, n, needle, strlen(needle)) != 0;
}

static int skipName(const unsigned char *p, int pos, int n)
{
    while (pos < n) {
        unsigned char l = p[pos];
        if (l == 0) return pos + 1;
        if ((l & 0xC0) == 0xC0) return pos + 2;
        pos += 1 + l;
    }
    return pos;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    srand((unsigned)time(0));

    ShareService svc;
    svc.start(15353); // porta arbitraria: su host 5353 e' presa da avahi/resolved
    usleep(400000); // avvio thread + bind

    { // probe: la porta deve essere presa dal responder
        int s2 = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in a2;
        memset(&a2, 0, sizeof(a2));
        a2.sin_family = AF_INET;
        a2.sin_port = htons(15353);
        a2.sin_addr.s_addr = htonl(INADDR_ANY);
        int br = bind(s2, (struct sockaddr *)&a2, sizeof(a2));
        fprintf(stderr, "DBG: probe bind 15353 = %d (errno %d, atteso -1/98)\n", br, errno);
        close(s2);
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return fail("socket");

    unsigned char resp[4096];

    // 1. PTR query come fa il telefono
    // NB: lunghezza esplicita (la literal contiene \x00 root); label = 13 byte
    QByteArray typeQn("\x0D_FC9F5ED42C8A\x04_tcp\x05local\x00", 26);
    int n = query(sock, typeQn, 12, resp, sizeof(resp));
    if (n < 12) return fail("nessuna risposta alla query PTR");
    if (!(resp[2] & 0x80)) return fail("flag QR non impostato");
    if (!containsTxt(resp, n, "n=")) return fail("manca TXT n=");

    // 2. decodifica TXT n= e verifica endpoint info
    char *p = (char *)memmem(resp, n, "n=", 2);
    // la stringa TXT e' length-prefixed: il byte prima di "n=" e' la lunghezza
    QByteArray b64(p + 2, (unsigned char)p[-1] - 2);
    QByteArray ei = QByteArray::fromBase64(
        b64, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (ei.size() != 1 + 16 + 1 + 9)
        return fail("endpoint info di lunghezza inattesa");
    if ((unsigned char)ei[0] != (1 << 1)) return fail("bitfield endpoint info errato");
    if (memcmp(ei.constData() + 18, "BBX Share", 9) != 0)
        return fail("nome device nell'endpoint info errato");

    // 3. nome istanza dal rdata del PTR, poi SRV su di essa
    int ancount = (resp[6] << 8) | resp[7];
    if (ancount < 1) return fail("nessun record in risposta");
    int pos = 12;
    int qdc = (resp[4] << 8) | resp[5];
    for (int q = 0; q < qdc; ++q) pos = skipName(resp, pos, n) + 4;
    QByteArray instDn;
    for (int r = 0; r < ancount && pos + 10 <= n; ++r) {
        pos = skipName(resp, pos, n);
        quint16 rtype = (resp[pos] << 8) | resp[pos + 1];
        quint16 rdlen = (resp[pos + 8] << 8) | resp[pos + 9];
        if (rtype == 12 && instDn.isEmpty())
            instDn = QByteArray((const char *)resp + pos + 10, rdlen);
        pos += 10 + rdlen;
    }
    if (instDn.isEmpty()) return fail("PTR rdata non trovato");
    int lbl = (unsigned char)instDn[0];
    QByteArray inst = instDn.mid(1, lbl);

    n = query(sock, instDn, 33, resp, sizeof(resp));
    if (n < 12) return fail("nessuna risposta alla query SRV");
    // cerca la porta nel rdata SRV
    ancount = (resp[6] << 8) | resp[7];
    qdc = (resp[4] << 8) | resp[5];
    pos = 12;
    for (int q = 0; q < qdc; ++q) pos = skipName(resp, pos, n) + 4;
    int port = 0;
    for (int r = 0; r < ancount && pos + 10 <= n; ++r) {
        pos = skipName(resp, pos, n);
        quint16 rtype = (resp[pos] << 8) | resp[pos + 1];
        quint16 rdlen = (resp[pos + 8] << 8) | resp[pos + 9];
        if (rtype == 33 && port == 0)
            port = (resp[pos + 14] << 8) | resp[pos + 15]; // prio(2) weight(2) port(2)
        pos += 10 + rdlen;
    }
    if (port <= 0) return fail("SRV con porta non trovato");

    printf("OK — PTR/TXT/SRV rispondono, istanza %s, porta TCP %d\n",
           inst.constData(), port);
    return 0;
}
