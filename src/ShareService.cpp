#include "ShareService.hpp"
#include "QuickShareSession.hpp"
#include "QuickShareSender.hpp"

#include <QtCore/QByteArray>
#include <QtCore/QFileInfo>
#include <QtCore/QHash>
#include <QtCore/QMetaObject>
#include <QtCore/QUrl>
#include <QtCore/QSet>

#include <bb/system/InvokeManager>
#include <bb/system/InvokeReply>
#include <bb/system/InvokeReplyError>
#include <bb/system/InvokeRequest>
#include <bb/system/InvokeTargetReply>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/*
 * Dettagli protocollo da NearDrop PROTOCOL.md (grishka) e rquickshare:
 * - tipo servizio mDNS: "_FC9F5ED42C8A._tcp" (SHA256("NearbySharing")[:3])
 * - nome istanza: base64 URL-safe senza padding di:
 *     0x23 | endpoint ID (4 byte ASCII alfanumerici) | FC 9F 5E | 00 00
 * - TXT "n": base64 URL-safe di:
 *     deviceType<<1 (bitfield: visibilita'=0 => visibile) |
 *     16 byte random | nome device con prefix di 1 byte di lunghezza
 */

namespace {

const int     MDNS_PORT    = 5353;
const quint32 RECORD_TTL   = 120;
const char SERVICE_TYPE[] = "_FC9F5ED42C8A._tcp.local";
const char HOST_LABEL[]   = "bbxshare";
const char DEVICE_NAME[]  = "BBX Share";

const quint16 QTYPE_A   = 1;
const quint16 QTYPE_PTR = 12;
const quint16 QTYPE_TXT = 16;
const quint16 QTYPE_SRV = 33;
const quint16 QTYPE_ANY = 255;

struct ShareCtx {
    QByteArray instanceLabel;   // base64 url-safe, senza padding
    QByteArray endpointInfoB64; // valore TXT "n"
    quint16 tcpPort;
    quint16 mdnsPort;
    quint32 localIp;            // network byte order
    ShareService *svc;
    bool scanActive;
    qint64 scanDeadlineMs;
    qint64 nextScanQueryMs;
    int scanQueriesLeft;
    qint64 nextAnnounceMs;
    int announceBurstLeft;
    QHash<QString, QString> scanSeen;
    QSet<QByteArray> discoveredInstances;
    QHash<QByteArray, QByteArray> discoveredSrvHosts;
    QHash<QByteArray, QByteArray> discoveredTxts;
    QHash<QByteArray, QByteArray> discoveredAddresses;
    QHash<QByteArray, int> discoveredSrvPorts;
};

qint64 monotonicMs()
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return (qint64)time(0) * 1000;
    return (qint64)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

void postStatus(ShareCtx *ctx, const QString &msg)
{
#ifdef HOST_TRACE
    fprintf(stderr, "[share] %s\n", msg.toUtf8().constData());
#endif
    QMetaObject::invokeMethod(ctx->svc, "setStatus", Qt::QueuedConnection,
                              Q_ARG(QString, msg));
}

// evento visibile nella lista della UI (main thread via coda)
void postEvent(ShareCtx *ctx, const QString &title, const QString &detail)
{
#ifdef HOST_TRACE
    fprintf(stderr, "[share] %s - %s\n", title.toUtf8().constData(),
            detail.toUtf8().constData());
#endif
    QMetaObject::invokeMethod(ctx->svc, "appendEvent", Qt::QueuedConnection,
                              Q_ARG(QString, title), Q_ARG(QString, detail));
}

// base64 URL-safe senza padding (come NearDrop/rquickshare)
QByteArray urlSafeB64(const unsigned char *data, int len)
{
    static const char *alpha =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    QByteArray out;
    for (int i = 0; i < len; i += 3) {
        int b0 = data[i];
        int b1 = (i + 1 < len) ? data[i + 1] : 0;
        int b2 = (i + 2 < len) ? data[i + 2] : 0;
        out.append(alpha[b0 >> 2]);
        out.append(alpha[((b0 & 3) << 4) | (b1 >> 4)]);
        if (i + 1 < len) out.append(alpha[((b1 & 15) << 2) | (b2 >> 6)]);
        if (i + 2 < len) out.append(alpha[b2 & 63]);
    }
    return out;
}

// "a.b.c" -> label DNS length-prefixed + root
QByteArray dnsName(const QByteArray &fqdn)
{
    QByteArray out;
    const char *p = fqdn.constData();
    const char *end = p + fqdn.size();
    while (p < end) {
        const char *dot = (const char *)memchr(p, '.', end - p);
        int l = dot ? (int)(dot - p) : (int)(end - p);
        out.append((char)l);
        out.append(p, l);
        if (!dot) break;
        p = dot + 1;
    }
    out.append('\0');
    return out;
}

QByteArray discoveryQuery()
{
    QByteArray packet(12, '\0');
    packet[5] = 1; // one question
    packet.append(dnsName(QByteArray(SERVICE_TYPE)));
    quint16 type = htons(QTYPE_PTR);
    quint16 klass = htons(1);
    packet.append((const char *)&type, 2);
    packet.append((const char *)&klass, 2);
    return packet;
}

bool readDnsName(const unsigned char *buf, int size, int *position,
                 QByteArray *name)
{
    int pos = *position;
    int jumps = 0;
    bool jumped = false;
    QByteArray value;
    while (pos >= 0 && pos < size && jumps++ < 32) {
        const unsigned char length = buf[pos];
        if (length == 0) {
            ++pos;
            if (!jumped) *position = pos;
            *name = value.toLower();
            return true;
        }
        if ((length & 0xc0) == 0xc0) {
            if (pos + 1 >= size) return false;
            const int target = ((length & 0x3f) << 8) | buf[pos + 1];
            if (!jumped) *position = pos + 2;
            pos = target;
            jumped = true;
            continue;
        }
        if (length > 63 || pos + 1 + length > size) return false;
        if (!value.isEmpty()) value.append('.');
        value.append((const char *)buf + pos + 1, length);
        pos += length + 1;
    }
    return false;
}

QByteArray decodeEndpointInfo(const QByteArray &txt)
{
    QByteArray value = txt;
    value.replace('-', '+');
    value.replace('_', '/');
    while (value.size() % 4) value.append('=');
    return QByteArray::fromBase64(value);
}

bool isReadableDeviceName(const QString &name)
{
    if (name.isEmpty() || name.contains(QChar(0xfffd))) return false;
    for (int i = 0; i < name.size(); ++i) {
        const ushort c = name.at(i).unicode();
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

QString fallbackDeviceName(const QByteArray &endpoint)
{
    if (endpoint.isEmpty()) return QString::fromUtf8("Dispositivo vicino");
    const int type = ((unsigned char)endpoint.at(0) & 7) >> 1;
    switch (type) {
    case 1: return QString::fromUtf8("Telefono vicino");
    case 2: return QString::fromUtf8("Tablet vicino");
    case 3: return QString::fromUtf8("Computer vicino");
    default: return QString::fromUtf8("Dispositivo vicino");
    }
}

void postDevice(ShareCtx *ctx, const QString &name,
                const QString &address, int port)
{
    const QString key = address + QLatin1String(":") + QString::number(port);
    if (ctx->scanSeen.value(key) == name) return;
    ctx->scanSeen.insert(key, name);
    QMetaObject::invokeMethod(ctx->svc, "addDevice", Qt::QueuedConnection,
                              Q_ARG(QString, name), Q_ARG(QString, address),
                              Q_ARG(int, port));
}

void parseDiscoveryPacket(ShareCtx *ctx, const unsigned char *buf, int size)
{
    if (!ctx->scanActive || size < 12) return;
    const int questions = ((int)buf[4] << 8) | buf[5];
    const int answers = ((int)buf[6] << 8) | buf[7];
    const int authorities = ((int)buf[8] << 8) | buf[9];
    const int additionals = ((int)buf[10] << 8) | buf[11];
    int pos = 12;
    QByteArray ignored;
    for (int i = 0; i < questions; ++i) {
        if (!readDnsName(buf, size, &pos, &ignored) || pos + 4 > size) return;
        pos += 4;
    }

    const int totalRecords = answers + authorities + additionals;
    for (int i = 0; i < totalRecords; ++i) {
        QByteArray name;
        if (!readDnsName(buf, size, &pos, &name) || pos + 10 > size) return;
        const quint16 type = ((quint16)buf[pos] << 8) | buf[pos + 1];
        pos += 2;
        pos += 2; // class
        pos += 4; // ttl
        const quint16 length = ((quint16)buf[pos] << 8) | buf[pos + 1];
        pos += 2;
        if (pos + length > size) return;
        const int rdata = pos;
        if (type == QTYPE_PTR) {
            int p = rdata;
            QByteArray target;
            if (readDnsName(buf, size, &p, &target))
                ctx->discoveredInstances.insert(target);
        } else if (type == QTYPE_SRV && length >= 6) {
            int p = rdata + 6;
            QByteArray target;
            if (readDnsName(buf, size, &p, &target)) {
                ctx->discoveredSrvHosts.insert(name, target);
                ctx->discoveredSrvPorts.insert(
                    name, ((int)buf[rdata + 4] << 8) | buf[rdata + 5]);
            }
        } else if (type == QTYPE_TXT) {
            int p = rdata;
            const int end = rdata + length;
            while (p < end) {
                const int n = (unsigned char)buf[p++];
                if (p + n > end) break;
                QByteArray entry((const char *)buf + p, n);
                if (entry.startsWith("n="))
                    ctx->discoveredTxts.insert(name, entry.mid(2));
                p += n;
            }
        } else if (type == QTYPE_A && length == 4) {
            ctx->discoveredAddresses.insert(
                name, QByteArray((const char *)buf + rdata, 4));
        }
        pos = rdata + length;
    }

    QSet<QByteArray>::const_iterator it = ctx->discoveredInstances.constBegin();
    for (; it != ctx->discoveredInstances.constEnd(); ++it) {
        const QByteArray instance = *it;
        const QByteArray host = ctx->discoveredSrvHosts.value(instance);
        const QByteArray ip = ctx->discoveredAddresses.value(host);
        const int port = ctx->discoveredSrvPorts.value(instance, 0);
        if (host.isEmpty() || ip.size() != 4 || port <= 0) continue;
        char ipText[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, ip.constData(), ipText, sizeof(ipText));
        // Non mostrare mai il nome istanza mDNS: e' un token Base64 tecnico,
        // non un nome destinato all'utente.
        QString deviceName;
        const QByteArray encoded = ctx->discoveredTxts.value(instance);
        const QByteArray endpoint = decodeEndpointInfo(encoded);
        if (endpoint.size() >= 18 && (endpoint.at(0) & 0x10) == 0) {
            const int nameLength = (unsigned char)endpoint.at(17);
            if (nameLength > 0 && endpoint.size() >= 18 + nameLength) {
                const QString candidate = QString::fromUtf8(
                    endpoint.constData() + 18, nameLength).trimmed();
                if (isReadableDeviceName(candidate)) deviceName = candidate;
            }
        }
        // Il nome dell'endpoint e' opzionale (device invisibile o TXT parziale).
        // In quel caso usa un'etichetta leggibile, mai il token mDNS.
        if (deviceName.isEmpty()) deviceName = fallbackDeviceName(endpoint);
        // Ignora l'annuncio locale anche se il TXT e' arrivato separatamente.
        if (ctx->localIp && ip.size() == 4 &&
            memcmp(ip.constData(), &ctx->localIp, 4) == 0)
            continue;
        if (deviceName == QString::fromUtf8(DEVICE_NAME)) continue;
        postDevice(ctx, deviceName, QString::fromLatin1(ipText), port);
    }
}

// ponytail: IP della route di default calcolato una volta sola; ricalcolare se la rete cambia
quint32 detectLocalIp()
{
    quint32 ip = 0;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(MDNS_PORT);
        inet_pton(AF_INET, "224.0.0.251", &dst.sin_addr);
        if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
            struct sockaddr_in me;
            socklen_t l = sizeof(me);
            if (getsockname(s, (struct sockaddr *)&me, &l) == 0)
                ip = me.sin_addr.s_addr;
        }
        close(s);
    }
    return ip;
}

void appendRecord(QByteArray &pkt, const QByteArray &name, quint16 type,
                  bool cacheFlush, quint32 ttl, const QByteArray &rdata)
{
    pkt.append(name);
    quint16 v = htons(type);
    pkt.append((const char *)&v, 2);
    v = htons(cacheFlush ? 0x8001 : 0x0001);
    pkt.append((const char *)&v, 2);
    v = htonl(ttl);
    pkt.append((const char *)&v, 4);
    v = htons((quint16)rdata.size());
    pkt.append((const char *)&v, 2);
    pkt.append(rdata);
}

QByteArray buildResponse(ShareCtx *ctx, int id, bool cacheFlush,
                         bool answerPtr, const QByteArray &ptrName,
                         bool answerSrv, bool answerTxt, bool answerA)
{
    const QByteArray typeDn = dnsName(SERVICE_TYPE);
    const QByteArray instDn = dnsName(ctx->instanceLabel + "." + SERVICE_TYPE);
    const QByteArray hostDn = dnsName(QByteArray(HOST_LABEL) + ".local");

    QByteArray srvRd;
    quint16 zero = 0, port = htons(ctx->tcpPort);
    srvRd.append((const char *)&zero, 2); // priority
    srvRd.append((const char *)&zero, 2); // weight
    srvRd.append((const char *)&port, 2);
    srvRd.append(hostDn);

    QByteArray txtRd;
    QByteArray txtEntry = "n=" + ctx->endpointInfoB64;
    txtRd.append((char)txtEntry.size());
    txtRd.append(txtEntry);

    QByteArray aRd((const char *)&ctx->localIp, 4);

    QByteArray pkt;
    pkt.append(QByteArray(12, '\0')); // header placeholder

    quint16 an = 0, ar = 0;
    if (answerPtr) {
        appendRecord(pkt, ptrName, QTYPE_PTR, false, RECORD_TTL, instDn);
        ++an;
    }
    // SRV/TXT/A: come risposte se direttamente richiesti, altrimenti additional
    struct { const QByteArray *name; quint16 type; const QByteArray *rd; bool want; } recs[3] = {
        { &instDn, QTYPE_SRV, &srvRd, answerSrv },
        { &instDn, QTYPE_TXT, &txtRd, answerTxt },
        { &hostDn, QTYPE_A,   &aRd,   answerA   },
    };
    for (int pass = 0; pass < 2; ++pass) {
        for (int i = 0; i < 3; ++i) {
            bool asAnswer = recs[i].want;
            if ((pass == 0) == asAnswer) {
                appendRecord(pkt, *recs[i].name, recs[i].type, cacheFlush,
                             RECORD_TTL, *recs[i].rd);
                if (asAnswer) ++an; else ++ar;
            }
        }
    }

    quint16 v = htons((quint16)id);
    memcpy(pkt.data(), &v, 2);
    v = htons(0x8400); // QR=1, AA=1
    memcpy(pkt.data() + 2, &v, 2);
    v = htons(an);
    memcpy(pkt.data() + 6, &v, 2);
    v = htons(ar);
    memcpy(pkt.data() + 10, &v, 2);
    return pkt;
}

void sendMulticast(int udp, const QByteArray &pkt)
{
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(MDNS_PORT);
    inet_pton(AF_INET, "224.0.0.251", &dst.sin_addr);
    sendto(udp, pkt.constData(), pkt.size(), 0, (struct sockaddr *)&dst, sizeof(dst));
}

void sendAnnounce(ShareCtx *ctx, int udp)
{
    QByteArray pkt = buildResponse(ctx, 0, true, true, dnsName(SERVICE_TYPE),
                                   false, false, false);
    sendMulticast(udp, pkt);
}

void handlePacket(ShareCtx *ctx, int udp, const unsigned char *buf, int n,
                  const struct sockaddr_in &src)
{
    if (n < 12) return; // malformato
    if (buf[2] & 0x80) {
        parseDiscoveryPacket(ctx, buf, n);
        return; // risposta mDNS: non è una query da rispondere
    }
    unsigned qd = ((unsigned)buf[4] << 8) | buf[5];
    if (qd == 0) return;

    const QByteArray typeL = QByteArray(SERVICE_TYPE).toLower();
    const QByteArray instL = ctx->instanceLabel.toLower() + "." + typeL;
    const QByteArray hostL = QByteArray(HOST_LABEL).toLower() + ".local";

    bool legacy = ntohs(src.sin_port) != MDNS_PORT;
    int id = ((int)buf[0] << 8) | buf[1];
    int pos = 12;

    for (unsigned qi = 0; qi < qd && pos + 5 <= n; ++qi) {
        int start = pos;
        bool compressed = false;
        QByteArray dotted;
        while (pos < n) {
            unsigned char l = buf[pos];
            if (l == 0) { ++pos; break; }
            if ((l & 0xC0) == 0xC0) { compressed = true; pos += 2; break; }
            if (pos + 1 + l > n) return;
            if (!dotted.isEmpty()) dotted.append('.');
            dotted.append((const char *)buf + pos + 1, l);
            pos += 1 + l;
        }
        if (pos + 4 > n) return;
        quint16 qtype = ((quint16)buf[pos] << 8) | buf[pos + 1];
        pos += 4;
        if (compressed) continue; // le question compresse sono rare; ignorale

        dotted = dotted.toLower();
        bool wantPtr = dotted == typeL && (qtype == QTYPE_PTR || qtype == QTYPE_ANY);
        bool wantSrv = dotted == instL && (qtype == QTYPE_SRV || qtype == QTYPE_ANY);
        bool wantTxt = dotted == instL && (qtype == QTYPE_TXT || qtype == QTYPE_ANY);
        bool wantA   = dotted == hostL && (qtype == QTYPE_A   || qtype == QTYPE_ANY);
        if (!wantPtr && !wantSrv && !wantTxt && !wantA) continue;

        QByteArray ptrName((const char *)buf + start, pos - 4 - start);
        QByteArray pkt = buildResponse(ctx, legacy ? id : 0, !legacy,
                                       wantPtr, ptrName, wantSrv, wantTxt, wantA);
        if (legacy)
            sendto(udp, pkt.constData(), pkt.size(), 0,
                   (struct sockaddr *)&src, sizeof(src));
        else
            sendMulticast(udp, pkt);

        postStatus(ctx, QString::fromUtf8("mDNS query tipo %1 da %2 -> risposto")
                            .arg(qtype)
                            .arg(QString::fromUtf8(inet_ntoa(src.sin_addr))));
        return; // rispondi solo alla prima question utile
    }
}

struct SessionArgs {
    int fd;
    QString address;
    ShareService *service;
};

struct SenderArgs {
    QString path;
    QString address;
    int port;
    QString deviceName;
    ShareService *service;
};

void *sessionMain(void *arg)
{
    SessionArgs *args = (SessionArgs *)arg;
    QuickShareSession session(args->fd, args->address, args->service);
    delete args;
    session.run();
    return 0;
}

void *senderMain(void *arg)
{
    SenderArgs *args = (SenderArgs *)arg;
    QuickShareSender sender(args->path, args->address, args->port,
                            args->deviceName, args->service);
    const bool success = sender.run();
    QMetaObject::invokeMethod(args->service, "sendFinished", Qt::QueuedConnection,
                              Q_ARG(bool, success));
    delete args;
    return 0;
}

void handleTcpConn(ShareCtx *ctx, int fd, const struct sockaddr_in &cli)
{
    SessionArgs *args = new SessionArgs;
    args->fd = fd;
    args->address = QString::fromUtf8(inet_ntoa(cli.sin_addr));
    args->service = ctx->svc;
    pthread_t thread;
    if (pthread_create(&thread, 0, &sessionMain, args) != 0) {
        postStatus(ctx, QString::fromUtf8("Avvio sessione TCP fallito: %1")
                           .arg(strerror(errno)));
        close(fd);
        delete args;
        return;
    }
    pthread_detach(thread);
}

void *workerMain(void *arg)
{
    ShareCtx *ctx = (ShareCtx *)arg;

    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (udp < 0 || tcp < 0) {
        postStatus(ctx, QString::fromUtf8("Errore socket: %1").arg(strerror(errno)));
        return 0;
    }

    int one = 1;
    setsockopt(udp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(udp, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
    setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(ctx->mdnsPort);
    if (bind(udp, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        postStatus(ctx, QString::fromUtf8("Bind mDNS fallita: %1").arg(strerror(errno)));
        return 0;
    }

    ctx->localIp = detectLocalIp();
    struct ip_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
    mr.imr_interface.s_addr = ctx->localIp ? ctx->localIp : htonl(INADDR_ANY);
    if (setsockopt(udp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) != 0)
        postStatus(ctx, QString::fromUtf8("Attenzione: join multicast fallita: %1")
                            .arg(strerror(errno)));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;
    socklen_t alen = sizeof(addr);
    if (bind(tcp, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(tcp, 4) != 0 ||
        getsockname(tcp, (struct sockaddr *)&addr, &alen) != 0) {
        postStatus(ctx, QString::fromUtf8("Listener TCP fallito: %1").arg(strerror(errno)));
        return 0;
    }
    ctx->tcpPort = ntohs(addr.sin_port);

    postStatus(ctx, QString::fromUtf8("Attivo — visibile come \"%1\" — IP %2, TCP %3")
                        .arg(DEVICE_NAME)
                        .arg(QString::fromUtf8(inet_ntoa(*((struct in_addr *)&ctx->localIp))))
                        .arg(ctx->tcpPort));
    postEvent(ctx, QString::fromUtf8("Servizio avviato"),
              QString::fromUtf8("Visibile sulla Wi-Fi come %1 · porta TCP %2")
                  .arg(DEVICE_NAME).arg(ctx->tcpPort));

    // Burst iniziale: rende BBX Share visibile appena Android apre Quick Share,
    // senza aspettare il normale refresh mDNS.
    sendAnnounce(ctx, udp);
    ctx->announceBurstLeft = 3;
    ctx->nextAnnounceMs = monotonicMs() + 150;

    struct pollfd fds[2];
    for (;;) {
        qint64 now = monotonicMs();
        if (ctx->svc->takeScanRequest()) {
            ctx->scanActive = true;
            ctx->scanDeadlineMs = now + 5000;
            ctx->nextScanQueryMs = now + 200;
            ctx->scanQueriesLeft = 3;
            ctx->scanSeen.clear();
            ctx->discoveredInstances.clear();
            ctx->discoveredSrvHosts.clear();
            ctx->discoveredTxts.clear();
            ctx->discoveredAddresses.clear();
            ctx->discoveredSrvPorts.clear();
            sendMulticast(udp, discoveryQuery());
        }
        now = monotonicMs();
        if (ctx->scanActive && ctx->scanQueriesLeft > 0 &&
            now >= ctx->nextScanQueryMs) {
            sendMulticast(udp, discoveryQuery());
            --ctx->scanQueriesLeft;
            ctx->nextScanQueryMs = now +
                (ctx->scanQueriesLeft == 2 ? 300 :
                 ctx->scanQueriesLeft == 1 ? 700 : 1200);
        }
        if (ctx->scanActive && now >= ctx->scanDeadlineMs) {
            ctx->scanActive = false;
            QMetaObject::invokeMethod(ctx->svc, "setScanning", Qt::QueuedConnection,
                                      Q_ARG(bool, false));
            postStatus(ctx, QString::fromUtf8("Ricerca terminata"));
        }
        if (now >= ctx->nextAnnounceMs) {
            sendAnnounce(ctx, udp);
            if (ctx->announceBurstLeft > 0) {
                --ctx->announceBurstLeft;
                ctx->nextAnnounceMs = now +
                    (ctx->announceBurstLeft == 2 ? 350 :
                     ctx->announceBurstLeft == 1 ? 1000 : 15000);
            } else {
                ctx->nextAnnounceMs = now + 15000;
            }
        }
        fds[0].fd = udp; fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = tcp; fds[1].events = POLLIN; fds[1].revents = 0;
        int r = poll(fds, 2,
                     (ctx->scanActive || ctx->announceBurstLeft > 0) ? 100 : 500);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) continue;
        if (fds[0].revents & POLLIN) {
            unsigned char buf[4096];
            struct sockaddr_in src;
            socklen_t sl = sizeof(src);
            int n = recvfrom(udp, buf, sizeof(buf), 0, (struct sockaddr *)&src, &sl);
#ifdef HOST_TRACE
            fprintf(stderr, "[share] udp packet %d byte da porta %u\n", n, ntohs(src.sin_port));
#endif
            if (n >= 12) handlePacket(ctx, udp, buf, n, src);
        }
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in cli;
            socklen_t cl = sizeof(cli);
            int fd = accept(tcp, (struct sockaddr *)&cli, &cl);
            if (fd >= 0) handleTcpConn(ctx, fd, cli);
        }
    }
    return 0;
}

} // namespace

ShareService::ShareService(QObject *parent)
    : QObject(parent), m_status(QString::fromUtf8("Avvio del servizio...")),
      m_started(false), m_transferPending(false), m_consentDecision(-1),
      m_transferActive(false), m_transferProgress(0.0f),
      m_invokeManager(new bb::system::InvokeManager(this)),
      m_scanning(false), m_selectedDevicePort(0), m_sendActive(false),
      m_sendFailed(false),
      m_scanRequested(false)
{
    m_events = new bb::cascades::ArrayDataModel(this);
    m_devices = new bb::cascades::ArrayDataModel(this);
    const bool connected = connect(
        m_invokeManager,
        SIGNAL(invoked(const bb::system::InvokeRequest&)),
        this,
        SLOT(handleInvoke(const bb::system::InvokeRequest&)));
    Q_ASSERT(connected);
    Q_UNUSED(connected);
}

bool ShareService::takeScanRequest()
{
    QMutexLocker locker(&m_discoveryMutex);
    const bool requested = m_scanRequested;
    m_scanRequested = false;
    return requested;
}

bool ShareService::beginConsent(const QString &title, const QString &detail)
{
    {
        QMutexLocker locker(&m_consentMutex);
        if (m_consentDecision == 0)
            return false;
        m_consentDecision = 0;
    }
    QMetaObject::invokeMethod(this, "showPendingTransfer", Qt::QueuedConnection,
                              Q_ARG(QString, title), Q_ARG(QString, detail));
    return true;
}

int ShareService::consentDecision()
{
    QMutexLocker locker(&m_consentMutex);
    return m_consentDecision;
}

void ShareService::finishConsent()
{
    {
        QMutexLocker locker(&m_consentMutex);
        m_consentDecision = -1;
    }
    QMetaObject::invokeMethod(this, "clearPendingTransfer", Qt::QueuedConnection);
}

void ShareService::acceptTransfer()
{
    QMutexLocker locker(&m_consentMutex);
    if (m_consentDecision == 0)
        m_consentDecision = 1;
}

void ShareService::rejectTransfer()
{
    QMutexLocker locker(&m_consentMutex);
    if (m_consentDecision == 0)
        m_consentDecision = -1;
}

void ShareService::showPendingTransfer(const QString &title, const QString &detail)
{
    m_pendingTitle = title;
    m_pendingDetail = detail;
    m_transferPending = true;
    emit pendingTransferChanged();
}

void ShareService::clearPendingTransfer()
{
    m_transferPending = false;
    m_pendingTitle.clear();
    m_pendingDetail.clear();
    emit pendingTransferChanged();
}

void ShareService::clearHistory()
{
    m_events->clear();
    emit eventsChanged();
}

void ShareService::setTransferProgress(float progress, const QString &text)
{
    m_transferActive = true;
    m_transferProgress = qBound(0.0f, progress, 1.0f);
    m_transferProgressText = text;
    emit transferProgressChanged();
}

void ShareService::clearTransferProgress()
{
    m_transferActive = false;
    m_transferProgress = 0.0f;
    m_transferProgressText.clear();
    emit transferProgressChanged();
}

void ShareService::appendEvent(const QString &title, const QString &detail)
{
    QVariantMap row;
    row["title"] = title;
    row["detail"] = detail;
    // I file completati vengono resi direttamente apribili dalla cronologia.
    if (detail.startsWith(QLatin1String("/accounts/")) && QFileInfo(detail).isFile())
        row["path"] = detail;
    m_events->append(row);
    emit eventsChanged();
}

void ShareService::openReceivedFile(const QString &path)
{
    const QFileInfo file(path);
    if (!file.exists()) {
        appendEvent(QString::fromUtf8("File non trovato"), path);
        return;
    }

    // OPEN su una directory file:// viene risolto dal broker verso il File
    // Manager di sistema. Se la ROM non espone quel target, ripieghiamo sul
    // viewer associato al file vero e proprio.
    bb::system::InvokeRequest request;
    request.setAction(QLatin1String("bb.action.OPEN"));
    request.setUri(QUrl::fromLocalFile(file.absolutePath()));

    bb::system::InvokeReply *reply = m_invokeManager->invoke(request);
    if (!reply) {
        bb::system::InvokeRequest fallback;
        fallback.setAction(QLatin1String("bb.action.OPEN"));
        fallback.setUri(QUrl::fromLocalFile(file.absoluteFilePath()));
        m_invokeManager->invoke(fallback);
        return;
    }
    reply->setProperty("bbxFallbackPath", file.absoluteFilePath());
    connect(reply, SIGNAL(finished()), this, SLOT(handleOpenFolderReply()));
}

void ShareService::handleOpenFolderReply()
{
    bb::system::InvokeReply *reply = qobject_cast<bb::system::InvokeReply *>(sender());
    if (!reply || reply->error() == bb::system::InvokeReplyError::None)
        return;

    const QString path = reply->property("bbxFallbackPath").toString();
    if (path.isEmpty())
        return;

    bb::system::InvokeRequest fallback;
    fallback.setAction(QLatin1String("bb.action.OPEN"));
    fallback.setUri(QUrl::fromLocalFile(path));
    m_invokeManager->invoke(fallback);
}

void ShareService::selectOutgoingFile(const QString &path)
{
    const QFileInfo file(path);
    if (!file.exists() || !file.isFile()) {
        appendEvent(QString::fromUtf8("File non selezionabile"), path);
        return;
    }

    m_outgoingPath = file.absoluteFilePath();
    m_outgoingName = file.fileName();
    const qint64 bytes = file.size();
    if (bytes >= 1024 * 1024)
        m_outgoingDetail = QString::fromUtf8("%1 MB · pronto per l'invio")
            .arg((double)bytes / (1024.0 * 1024.0), 0, 'f', 1);
    else
        m_outgoingDetail = QString::fromUtf8("%1 KB · pronto per l'invio")
            .arg(qMax<qint64>(1, (bytes + 1023) / 1024));
    emit outgoingChanged();
}

void ShareService::clearOutgoingFile()
{
    if (m_outgoingPath.isEmpty())
        return;
    m_outgoingPath.clear();
    m_outgoingName.clear();
    m_outgoingDetail.clear();
    emit outgoingChanged();
}

void ShareService::clearDevices()
{
    m_devices->clear();
    emit devicesChanged();
}

void ShareService::setScanning(bool scanning)
{
    if (m_scanning == scanning) return;
    m_scanning = scanning;
    emit scanningChanged();
}

void ShareService::addDevice(const QString &name, const QString &address, int port)
{
    for (int i = 0; i < m_devices->size(); ++i) {
        QVariantMap existing = m_devices->data(QVariantList() << i).toMap();
        if (existing.value("address").toString() == address &&
            existing.value("port").toInt() == port) {
            if (!name.isEmpty() && existing.value("name").toString() != name) {
                existing["name"] = name;
                m_devices->replace(i, existing);
                if (m_selectedDeviceAddress == address && m_selectedDevicePort == port) {
                    m_selectedDeviceName = name;
                    emit deviceSelectionChanged();
                }
                emit devicesChanged();
            }
            return;
        }
    }
    QVariantMap row;
    row["name"] = name;
    row["address"] = address;
    row["port"] = port;
    m_devices->append(row);
    emit devicesChanged();
}

void ShareService::scanDevices()
{
    if (m_scanning) return;
    clearDevices();
    setScanning(true);
    setStatus(QString::fromUtf8("Ricerca dispositivi vicini…"));
    QMutexLocker locker(&m_discoveryMutex);
    m_scanRequested = true;
}

void ShareService::selectDevice(const QString &address, int port, const QString &name)
{
    m_selectedDeviceAddress = address;
    m_selectedDevicePort = port;
    m_selectedDeviceName = name;
    emit deviceSelectionChanged();
}

void ShareService::clearDeviceSelection()
{
    if (!deviceReady()) return;
    m_selectedDeviceAddress.clear();
    m_selectedDeviceName.clear();
    m_selectedDevicePort = 0;
    emit deviceSelectionChanged();
}

void ShareService::sendOutgoing()
{
    if (m_sendActive || !outgoingReady() || !deviceReady()) return;
    m_sendActive = true;
    m_sendFailed = false;
    m_sendStatus = QString::fromUtf8("Connessione al dispositivo…");
    emit sendStateChanged();
    setTransferProgress(0.0f, QString::fromUtf8("Connessione…"));
    SenderArgs *args = new SenderArgs;
    args->path = m_outgoingPath;
    args->address = m_selectedDeviceAddress;
    args->port = m_selectedDevicePort;
    args->deviceName = m_selectedDeviceName;
    args->service = this;
    pthread_t th;
    if (pthread_create(&th, 0, &senderMain, args) != 0) {
        delete args;
        m_sendActive = false;
        m_sendFailed = true;
        m_sendStatus = QString::fromUtf8("Impossibile avviare l'invio");
        emit sendStateChanged();
        clearTransferProgress();
        setStatus(QString::fromUtf8("Avvio invio fallito"));
        return;
    }
    pthread_detach(th);
}

void ShareService::setSendStatus(const QString &status)
{
    m_sendStatus = status;
    emit sendStateChanged();
}

void ShareService::sendFinished(bool success)
{
    m_sendActive = false;
    m_sendFailed = !success;
    if (m_sendStatus.isEmpty())
        m_sendStatus = success ? QString::fromUtf8("Invio completato")
                               : QString::fromUtf8("Invio non riuscito");
    if (m_transferActive)
        clearTransferProgress();
    emit sendStateChanged();
}

void ShareService::handleInvoke(const bb::system::InvokeRequest &request)
{
    if (request.action() != QLatin1String("bb.action.SHARE"))
        return;

    const QString path = request.uri().toLocalFile();
    if (!path.isEmpty()) {
        selectOutgoingFile(path);
        appendEvent(QString::fromUtf8("File scelto da Condividi"),
                    QFileInfo(path).fileName());
    }
}

void ShareService::setStatus(const QString &status)
{
    m_status = status;
    emit statusChanged(m_status);
}

void ShareService::start(int mdnsPort)
{
    if (m_started) return;
    m_started = true;

    ShareCtx *ctx = new ShareCtx;
    ctx->svc = this;
    ctx->tcpPort = 0;
    ctx->mdnsPort = (quint16)mdnsPort;
    ctx->localIp = 0;
    ctx->scanActive = false;
    ctx->scanDeadlineMs = 0;
    ctx->nextScanQueryMs = 0;
    ctx->scanQueriesLeft = 0;
    ctx->nextAnnounceMs = 0;
    ctx->announceBurstLeft = 0;

    // endpoint ID: 4 caratteri ASCII alfanumerici casuali
    static const char *alpha =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    srand((unsigned)time(0) ^ (unsigned)getpid());
    unsigned char id[4];
    for (int i = 0; i < 4; ++i) id[i] = (unsigned char)alpha[rand() % 62];

    unsigned char nb[10] = { 0x23, id[0], id[1], id[2], id[3],
                             0xFC, 0x9F, 0x5E, 0, 0 };
    ctx->instanceLabel = urlSafeB64(nb, 10);

    // endpoint info: bitfield (tipo device phone=1, visibile) + 16 byte random + nome
    unsigned char ei[64];
    int eiLen = 0;
    ei[eiLen++] = 1 << 1; // deviceType=phone, visibility=0 (visibile)
    for (int i = 0; i < 16; ++i) ei[eiLen++] = (unsigned char)(rand() & 0xFF);
    int nameLen = (int)strlen(DEVICE_NAME);
    ei[eiLen++] = (unsigned char)nameLen;
    memcpy(ei + eiLen, DEVICE_NAME, nameLen);
    eiLen += nameLen;
    ctx->endpointInfoB64 = urlSafeB64(ei, eiLen);

    pthread_t th;
    pthread_create(&th, 0, &workerMain, ctx);
    pthread_detach(th);
}
