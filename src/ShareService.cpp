#include "ShareService.hpp"
#include "DiscoveryUtils.hpp"
#include "QuickShareSession.hpp"
#include "QuickShareSender.hpp"

#include <QtCore/QByteArray>
#include <QtCore/QAtomicInt>
#include <QtCore/QDate>
#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QHash>
#include <QtCore/QMetaObject>
#include <QtCore/QSettings>
#include <QtCore/QUrl>
#include <QtCore/QSet>
#include <QtCore/QStringList>
#include <QtCore/QTimer>

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

#ifdef Q_OS_BLACKBERRY
#include <btapi/btle.h>
#endif

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
const quint32 LEGACY_RECORD_TTL = 10;
const int     ANNOUNCE_STEADY_MS = 4000;
const int     BLE_WAKE_THROTTLE_MS = 2500;
const char SERVICE_TYPE[] = "_FC9F5ED42C8A._tcp.local";
const char DEVICE_NAME_BASE[] = "BBX Share";

const quint16 QTYPE_A   = 1;
const quint16 QTYPE_PTR = 12;
const quint16 QTYPE_TXT = 16;
const quint16 QTYPE_SRV = 33;
const quint16 QTYPE_ANY = 255;

struct ShareCtx {
    QByteArray instanceLabel;   // base64 url-safe, senza padding
    QByteArray hostLabel;       // univoco per processo, evita bbxshare.local condiviso
    QByteArray endpointInfoB64; // valore TXT "n"
    QByteArray deviceName;
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
    QAtomicInt bleWakeRequested;
    qint64 lastBleWakeMs;
    bool bleWakeActive;
    qint64 nextBleInitMs;
    qint64 nextIpCheckMs;
    QHash<QByteArray, qint64> discoveredInstanceExpiry;
    QHash<QByteArray, QByteArray> discoveredSrvHosts;
    QHash<QByteArray, qint64> discoveredSrvExpiry;
    QHash<QByteArray, QByteArray> discoveredTxts;
    QHash<QByteArray, qint64> discoveredTxtExpiry;
    QHash<QByteArray, QByteArray> discoveredAddresses;
    QHash<QByteArray, qint64> discoveredAddressExpiry;
    QHash<QByteArray, int> discoveredSrvPorts;
    QHash<QByteArray, qint64> followupQueries;
    QByteArray publishedDeviceSignature;
    // IP (network order) -> scadenza. Chi ha fatto una query mDNS: riceve
    // anche le copie unicast degli announce, il multicast e' spesso
    // filtrato dal Wi-Fi power save dei telefoni.
    QHash<quint32, qint64> recentQueriers;
};

qint64 monotonicMs()
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return (qint64)time(0) * 1000;
    return (qint64)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

QByteArray localDeviceName()
{
    QByteArray result(DEVICE_NAME_BASE);
    char host[64] = {0};
    if (gethostname(host, sizeof(host) - 1) != 0) return result;

    const QByteArray hostname(host);
    const int dash = hostname.lastIndexOf('-');
    const QByteArray suffix = dash >= 0 ? hostname.mid(dash + 1).trimmed()
                                        : QByteArray();
    if (suffix.size() < 2 || suffix.size() > 8) return result;
    for (int i = 0; i < suffix.size(); ++i) {
        const char c = suffix.at(i);
        if (!((c >= '0' && c <= '9') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z')))
            return result;
    }
    return result + " " + suffix.toUpper();
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

void generateDnsIdentity(ShareCtx *ctx)
{
    static const char *alpha =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    unsigned char id[4];
    for (int i = 0; i < 4; ++i)
        id[i] = (unsigned char)alpha[rand() % 62];
    unsigned char nearbyName[10] = {
        0x23, id[0], id[1], id[2], id[3], 0xFC, 0x9F, 0x5E, 0, 0
    };
    ctx->instanceLabel = urlSafeB64(nearbyName, 10);

    static const char hex[] = "0123456789abcdef";
    ctx->hostLabel = "bbxshare-";
    for (int i = 0; i < 8; ++i) {
        const unsigned char value = (unsigned char)(rand() & 0xff);
        ctx->hostLabel.append(hex[value >> 4]);
        ctx->hostLabel.append(hex[value & 15]);
    }
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

QByteArray recordQuery(const QByteArray &name, quint16 queryType)
{
    QByteArray packet(12, '\0');
    packet[5] = 1; // one question
    packet.append(dnsName(name));
    quint16 type = htons(queryType);
    quint16 klass = htons(1);
    packet.append((const char *)&type, 2);
    packet.append((const char *)&klass, 2);
    return packet;
}

QByteArray discoveryQuery()
{
    return recordQuery(QByteArray(SERVICE_TYPE), QTYPE_PTR);
}

void sendMulticast(int udp, const QByteArray &pkt);

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

bool packetContainsOwner(const unsigned char *buf, int size,
                         const QByteArray &owner)
{
    if (size < 12 || !(buf[2] & 0x80)) return false;
    const int questions = ((int)buf[4] << 8) | buf[5];
    const int records = (((int)buf[6] << 8) | buf[7]) +
                        (((int)buf[8] << 8) | buf[9]) +
                        (((int)buf[10] << 8) | buf[11]);
    int pos = 12;
    QByteArray name;
    for (int i = 0; i < questions; ++i) {
        if (!readDnsName(buf, size, &pos, &name) || pos + 4 > size) return false;
        pos += 4;
    }
    for (int i = 0; i < records; ++i) {
        if (!readDnsName(buf, size, &pos, &name) || pos + 10 > size) return false;
        const int length = ((int)buf[pos + 8] << 8) | buf[pos + 9];
        if (name == owner) return true;
        pos += 10 + length;
        if (pos > size) return false;
    }
    return false;
}

bool probeDnsIdentity(ShareCtx *ctx, int udp)
{
    const QByteArray instance =
        (ctx->instanceLabel + "." + SERVICE_TYPE).toLower();
    const QByteArray host = (ctx->hostLabel + ".local").toLower();
    for (int attempt = 0; attempt < 3; ++attempt) {
        sendMulticast(udp, recordQuery(instance, QTYPE_ANY));
        sendMulticast(udp, recordQuery(host, QTYPE_ANY));
        const qint64 deadline = monotonicMs() + 250;
        while (monotonicMs() < deadline) {
            struct pollfd pfd;
            pfd.fd = udp;
            pfd.events = POLLIN;
            pfd.revents = 0;
            const int waitMs = (int)qMax<qint64>(1, deadline - monotonicMs());
            const int ready = poll(&pfd, 1, waitMs);
            if (ready <= 0) break;
            unsigned char packet[4096];
            struct sockaddr_in source;
            socklen_t sourceLength = sizeof(source);
            const int size = recvfrom(udp, packet, sizeof(packet), 0,
                                      (struct sockaddr *)&source, &sourceLength);
            if (packetContainsOwner(packet, size, instance) ||
                packetContainsOwner(packet, size, host))
                return false;
        }
    }
    return true;
}

QByteArray decodeEndpointInfo(const QByteArray &txt)
{
    QByteArray value = txt;
    value.replace('-', '+');
    value.replace('_', '/');
    while (value.size() % 4) value.append('=');
    return QByteArray::fromBase64(value);
}

qint64 recordExpiry(qint64 now, quint32 ttl)
{
    const quint32 boundedTtl = qMin<quint32>(ttl, 24U * 60U * 60U);
    return now + (qint64)boundedTtl * 1000;
}

bool expireDiscoveryRecords(ShareCtx *ctx, qint64 now)
{
    bool changed = false;
    QHash<QByteArray, qint64>::iterator it;
    for (it = ctx->discoveredInstanceExpiry.begin();
         it != ctx->discoveredInstanceExpiry.end();) {
        if (it.value() <= now) {
            const QByteArray key = it.key();
            it = ctx->discoveredInstanceExpiry.erase(it);
            ctx->discoveredSrvHosts.remove(key);
            ctx->discoveredSrvPorts.remove(key);
            ctx->discoveredSrvExpiry.remove(key);
            ctx->discoveredTxts.remove(key);
            ctx->discoveredTxtExpiry.remove(key);
            changed = true;
        } else ++it;
    }
    for (it = ctx->discoveredSrvExpiry.begin(); it != ctx->discoveredSrvExpiry.end();) {
        if (it.value() <= now) {
            const QByteArray key = it.key();
            it = ctx->discoveredSrvExpiry.erase(it);
            ctx->discoveredSrvHosts.remove(key);
            ctx->discoveredSrvPorts.remove(key);
            changed = true;
        } else ++it;
    }
    for (it = ctx->discoveredTxtExpiry.begin(); it != ctx->discoveredTxtExpiry.end();) {
        if (it.value() <= now) {
            const QByteArray key = it.key();
            it = ctx->discoveredTxtExpiry.erase(it);
            ctx->discoveredTxts.remove(key);
            changed = true;
        } else ++it;
    }
    for (it = ctx->discoveredAddressExpiry.begin();
         it != ctx->discoveredAddressExpiry.end();) {
        if (it.value() <= now) {
            const QByteArray key = it.key();
            it = ctx->discoveredAddressExpiry.erase(it);
            ctx->discoveredAddresses.remove(key);
            changed = true;
        } else ++it;
    }
    return changed;
}

void publishDiscoveredDevices(ShareCtx *ctx)
{
    QStringList orderedInstances;
    QHash<QByteArray, qint64>::const_iterator keyIt =
        ctx->discoveredInstanceExpiry.constBegin();
    for (; keyIt != ctx->discoveredInstanceExpiry.constEnd(); ++keyIt)
        orderedInstances.append(QString::fromLatin1(keyIt.key()));
    orderedInstances.sort();

    QVariantList rows;
    QByteArray signature;
    for (int i = 0; i < orderedInstances.size(); ++i) {
        const QByteArray instance = orderedInstances.at(i).toLatin1();
        const QByteArray host = ctx->discoveredSrvHosts.value(instance);
        const QByteArray ip = ctx->discoveredAddresses.value(host);
        const int port = ctx->discoveredSrvPorts.value(instance, 0);
        if (host.isEmpty() || ip.size() != 4 || port <= 0) continue;
        if (ctx->localIp && memcmp(ip.constData(), &ctx->localIp, 4) == 0)
            continue;
        char ipText[INET_ADDRSTRLEN] = {0};
        if (!inet_ntop(AF_INET, ip.constData(), ipText, sizeof(ipText)))
            continue;
        const QByteArray endpoint =
            decodeEndpointInfo(ctx->discoveredTxts.value(instance));
        const QString deviceName = BbxDiscovery::endpointDisplayName(endpoint);
        QVariantMap row;
        row["instance"] = QString::fromLatin1(instance);
        row["name"] = deviceName;
        row["address"] = QString::fromLatin1(ipText);
        row["port"] = port;
        rows.append(row);
        signature.append(instance).append('|').append(deviceName.toUtf8())
                 .append('|').append(ipText).append('|')
                 .append(QByteArray::number(port)).append('\n');
    }
    if (signature == ctx->publishedDeviceSignature) return;
    ctx->publishedDeviceSignature = signature;
    QMetaObject::invokeMethod(ctx->svc, "syncDevices", Qt::QueuedConnection,
                              Q_ARG(QVariantList, rows));
}

void sendFollowupQuery(ShareCtx *ctx, int udp, const QByteArray &name,
                       quint16 type, qint64 now)
{
    const QByteArray key = QByteArray::number(type) + ':' + name;
    if (ctx->followupQueries.value(key, 0) > now) return;
    ctx->followupQueries.insert(key, now + 1000);
    sendMulticast(udp, recordQuery(name, type));
}

void sendResolutionQueries(ShareCtx *ctx, int udp, qint64 now)
{
    QHash<QByteArray, qint64>::const_iterator it =
        ctx->discoveredInstanceExpiry.constBegin();
    for (; it != ctx->discoveredInstanceExpiry.constEnd(); ++it) {
        const QByteArray instance = it.key();
        if (!ctx->discoveredSrvHosts.contains(instance))
            sendFollowupQuery(ctx, udp, instance, QTYPE_SRV, now);
        if (!ctx->discoveredTxts.contains(instance))
            sendFollowupQuery(ctx, udp, instance, QTYPE_TXT, now);
        const QByteArray host = ctx->discoveredSrvHosts.value(instance);
        if (!host.isEmpty() && !ctx->discoveredAddresses.contains(host))
            sendFollowupQuery(ctx, udp, host, QTYPE_A, now);
    }
}

void parseDiscoveryPacket(ShareCtx *ctx, int udp,
                          const unsigned char *buf, int size)
{
    if (size < 12) return;
    const qint64 now = monotonicMs();
    bool changed = expireDiscoveryRecords(ctx, now);
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
        const quint32 ttl = ((quint32)buf[pos] << 24) |
                            ((quint32)buf[pos + 1] << 16) |
                            ((quint32)buf[pos + 2] << 8) | buf[pos + 3];
        pos += 4;
        const quint16 length = ((quint16)buf[pos] << 8) | buf[pos + 1];
        pos += 2;
        if (pos + length > size) return;
        const int rdata = pos;
        if (type == QTYPE_PTR && name == QByteArray(SERVICE_TYPE).toLower()) {
            int p = rdata;
            QByteArray target;
            if (readDnsName(buf, size, &p, &target)) {
                if (ttl == 0) {
                    ctx->discoveredInstanceExpiry.remove(target);
                    ctx->discoveredSrvHosts.remove(target);
                    ctx->discoveredSrvPorts.remove(target);
                    ctx->discoveredSrvExpiry.remove(target);
                    ctx->discoveredTxts.remove(target);
                    ctx->discoveredTxtExpiry.remove(target);
                } else {
                    ctx->discoveredInstanceExpiry.insert(target,
                                                         recordExpiry(now, ttl));
                }
                changed = true;
            }
        } else if (type == QTYPE_SRV && length >= 6 &&
                   name.endsWith('.' + QByteArray(SERVICE_TYPE).toLower())) {
            int p = rdata + 6;
            QByteArray target;
            if (readDnsName(buf, size, &p, &target)) {
                if (ttl == 0) {
                    ctx->discoveredSrvHosts.remove(name);
                    ctx->discoveredSrvPorts.remove(name);
                    ctx->discoveredSrvExpiry.remove(name);
                } else {
                    ctx->discoveredSrvHosts.insert(name, target);
                    ctx->discoveredSrvPorts.insert(
                        name, ((int)buf[rdata + 4] << 8) | buf[rdata + 5]);
                    ctx->discoveredSrvExpiry.insert(name, recordExpiry(now, ttl));
                }
                changed = true;
            }
        } else if (type == QTYPE_TXT &&
                   name.endsWith('.' + QByteArray(SERVICE_TYPE).toLower())) {
            if (ttl == 0) {
                ctx->discoveredTxts.remove(name);
                ctx->discoveredTxtExpiry.remove(name);
                changed = true;
                pos = rdata + length;
                continue;
            }
            int p = rdata;
            const int end = rdata + length;
            while (p < end) {
                const int n = (unsigned char)buf[p++];
                if (p + n > end) break;
                QByteArray entry((const char *)buf + p, n);
                if (entry.startsWith("n=")) {
                    ctx->discoveredTxts.insert(name, entry.mid(2));
                    ctx->discoveredTxtExpiry.insert(name, recordExpiry(now, ttl));
                    changed = true;
                }
                p += n;
            }
        } else if (type == QTYPE_A && length == 4) {
            if (ttl == 0) {
                ctx->discoveredAddresses.remove(name);
                ctx->discoveredAddressExpiry.remove(name);
            } else {
                ctx->discoveredAddresses.insert(
                    name, QByteArray((const char *)buf + rdata, 4));
                ctx->discoveredAddressExpiry.insert(name, recordExpiry(now, ttl));
            }
            changed = true;
        }
        pos = rdata + length;
    }
    sendResolutionQueries(ctx, udp, now);
    if (changed) publishDiscoveredDevices(ctx);
}

// ponytail: IP della route di default, ricalcolato ogni 10s in refreshLocalIp()
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
                         bool answerSrv, bool answerTxt, bool answerA,
                         const QByteArray &question = QByteArray(),
                         quint32 ttl = RECORD_TTL)
{
    const QByteArray typeDn = dnsName(SERVICE_TYPE);
    const QByteArray instDn = dnsName(ctx->instanceLabel + "." + SERVICE_TYPE);
    const QByteArray hostDn = dnsName(ctx->hostLabel + ".local");

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
    pkt.append(question);

    quint16 an = 0, ar = 0;
    if (answerPtr) {
        appendRecord(pkt, ptrName, QTYPE_PTR, false, ttl, instDn);
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
                             ttl, *recs[i].rd);
                if (asAnswer) ++an; else ++ar;
            }
        }
    }

    quint16 v = htons((quint16)id);
    memcpy(pkt.data(), &v, 2);
    v = htons(0x8400); // QR=1, AA=1
    memcpy(pkt.data() + 2, &v, 2);
    v = htons(question.isEmpty() ? 0 : 1);
    memcpy(pkt.data() + 4, &v, 2);
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
    // Copie unicast ai querier recenti: il power save Wi-Fi dei telefoni
    // Android scarta il multicast, l'unicast arriva sempre.
    const qint64 now = monotonicMs();
    for (QHash<quint32, qint64>::iterator it = ctx->recentQueriers.begin();
         it != ctx->recentQueriers.end();) {
        if (it.value() < now) {
            it = ctx->recentQueriers.erase(it);
            continue;
        }
        struct sockaddr_in peer;
        memset(&peer, 0, sizeof(peer));
        peer.sin_family = AF_INET;
        peer.sin_port = htons(MDNS_PORT);
        peer.sin_addr.s_addr = it.key();
        sendto(udp, pkt.constData(), pkt.size(), 0,
               (struct sockaddr *)&peer, sizeof(peer));
        ++it;
    }
}

void armAnnounceBurst(ShareCtx *ctx, qint64 now)
{
    ctx->announceBurstLeft = 4;
    ctx->nextAnnounceMs = now + 120;
}

// L'IP della route di default puo' non essere pronto all'avvio dell'app
// (Wi-Fi in fase di associazione) o cambiare a runtime: verificato ogni 10s.
void refreshLocalIp(ShareCtx *ctx, int udp, qint64 now)
{
    const quint32 ip = detectLocalIp();
    if (ip == ctx->localIp) return;

    if (ctx->localIp) {
        struct ip_mreq drop;
        memset(&drop, 0, sizeof(drop));
        drop.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
        drop.imr_interface.s_addr = ctx->localIp;
        setsockopt(udp, IPPROTO_IP, IP_DROP_MEMBERSHIP, &drop, sizeof(drop));
    }
    ctx->localIp = ip;
    if (!ip) return;

    struct ip_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
    mr.imr_interface.s_addr = ip;
    if (setsockopt(udp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) != 0)
        postStatus(ctx, QObject::tr("Attenzione: join multicast fallita: %1")
                            .arg(strerror(errno)));
    setsockopt(udp, IPPROTO_IP, IP_MULTICAST_IF, &ip, sizeof(ip));
    postStatus(ctx, QObject::tr("IP locale aggiornato: %1")
                        .arg(QString::fromUtf8(inet_ntoa(*((struct in_addr *)&ip)))));
    armAnnounceBurst(ctx, now);
}

#ifdef Q_OS_BLACKBERRY
void bleAdvertisement(const char *, int8_t, bt_le_advert_packet_event_t,
                      const char *data, int length, void *userData)
{
    ShareCtx *ctx = (ShareCtx *)userData;
    if (ctx && BbxDiscovery::containsQuickShareService(data, length))
        ctx->bleWakeRequested.fetchAndStoreOrdered(1);
}

bool startBleWakeListener(ShareCtx *ctx)
{
    static bt_le_callbacks_t callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.advert_ext = &bleAdvertisement;
    if (bt_le_init(&callbacks) != EOK) return false;

    // 100 ms di intervallo, 50 ms di finestra: risposta rapida senza tenere
    // la radio in ascolto continuo.
    bt_le_set_scan_params(0x00A0, 0x0050, BT_LE_ADVERT_SCAN_PASSIVE);
    if (bt_le_add_scan_device(BT_LE_BDADDR_ANY, ctx) != EOK) {
        bt_le_deinit();
        return false;
    }
    return true;
}
#endif

void handlePacket(ShareCtx *ctx, int udp, const unsigned char *buf, int n,
                  const struct sockaddr_in &src)
{
    if (n < 12) return; // malformato
    if (buf[2] & 0x80) {
        parseDiscoveryPacket(ctx, udp, buf, n);
        return; // risposta mDNS: non è una query da rispondere
    }
    unsigned qd = ((unsigned)buf[4] << 8) | buf[5];
    if (qd == 0) return;

    const QByteArray typeL = QByteArray(SERVICE_TYPE).toLower();
    const QByteArray instL = ctx->instanceLabel.toLower() + "." + typeL;
    const QByteArray hostL = ctx->hostLabel.toLower() + ".local";

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
        quint16 qclass = ((quint16)buf[pos + 2] << 8) | buf[pos + 3];
        pos += 4;
        if (compressed) continue; // le question compresse sono rare; ignorale

        dotted = dotted.toLower();
        bool wantPtr = dotted == typeL && (qtype == QTYPE_PTR || qtype == QTYPE_ANY);
        bool wantSrv = dotted == instL && (qtype == QTYPE_SRV || qtype == QTYPE_ANY);
        bool wantTxt = dotted == instL && (qtype == QTYPE_TXT || qtype == QTYPE_ANY);
        bool wantA   = dotted == hostL && (qtype == QTYPE_A   || qtype == QTYPE_ANY);
        if (!wantPtr && !wantSrv && !wantTxt && !wantA) continue;

        QByteArray ptrName((const char *)buf + start, pos - 4 - start);
        QByteArray question((const char *)buf + start, pos - start);
        const bool wantsUnicast = (qclass & 0x8000) != 0;
        QByteArray pkt = buildResponse(ctx, legacy ? id : 0, !legacy,
                                       wantPtr, ptrName, wantSrv, wantTxt, wantA,
                                       legacy ? question : QByteArray(),
                                       legacy ? LEGACY_RECORD_TTL : RECORD_TTL);
        if (legacy || wantsUnicast) {
            sendto(udp, pkt.constData(), pkt.size(), 0,
                   (struct sockaddr *)&src, sizeof(src));
        } else {
            sendMulticast(udp, pkt);
            // Stessa risposta anche in unicast: il telefono che ha chiesto
            // non sempre riceve il multicast (power save Wi-Fi).
            sendto(udp, pkt.constData(), pkt.size(), 0,
                   (struct sockaddr *)&src, sizeof(src));
        }
        // I resolver legacy usano una porta effimera e sono one-shot. Solo i
        // querier mDNS completi su 5353 ricevono i successivi refresh unicast.
        if (!legacy)
            ctx->recentQueriers.insert(src.sin_addr.s_addr,
                                       monotonicMs() + 300000);

        postStatus(ctx, QObject::tr("mDNS query tipo %1 da %2 -> risposto")
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
    QStringList paths;
    QString address;
    int port;
    QString deviceName;
    QString localDeviceName;
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
    QuickShareSender sender(args->paths, args->address, args->port,
                            args->deviceName, args->localDeviceName,
                            args->service);
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
        postStatus(ctx, QObject::tr("Avvio sessione TCP fallito: %1")
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
        postStatus(ctx, QObject::tr("Errore socket: %1").arg(strerror(errno)));
        if (udp >= 0) close(udp);
        if (tcp >= 0) close(tcp);
        delete ctx;
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
        postStatus(ctx, QObject::tr("Bind mDNS fallita: %1").arg(strerror(errno)));
        close(udp);
        close(tcp);
        delete ctx;
        return 0;
    }

    ctx->localIp = detectLocalIp();
    struct ip_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
    mr.imr_interface.s_addr = ctx->localIp ? ctx->localIp : htonl(INADDR_ANY);
    if (setsockopt(udp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) != 0)
        postStatus(ctx, QObject::tr("Attenzione: join multicast fallita: %1")
                            .arg(strerror(errno)));
    if (ctx->localIp)
        setsockopt(udp, IPPROTO_IP, IP_MULTICAST_IF,
                   &ctx->localIp, sizeof(ctx->localIp));
    const unsigned char multicastTtl = 255;
    setsockopt(udp, IPPROTO_IP, IP_MULTICAST_TTL,
               &multicastTtl, sizeof(multicastTtl));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;
    socklen_t alen = sizeof(addr);
    if (bind(tcp, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(tcp, 4) != 0 ||
        getsockname(tcp, (struct sockaddr *)&addr, &alen) != 0) {
        postStatus(ctx, QObject::tr("Listener TCP fallito: %1").arg(strerror(errno)));
        close(udp);
        close(tcp);
        delete ctx;
        return 0;
    }
    ctx->tcpPort = ntohs(addr.sin_port);

    // Le porte alternative sono usate solo dai test host e non partecipano
    // al dominio mDNS reale su 5353.
    bool identityAvailable = ctx->mdnsPort != MDNS_PORT;
    for (int attempt = 0; attempt < 5 && !identityAvailable; ++attempt) {
        identityAvailable = probeDnsIdentity(ctx, udp);
        if (!identityAvailable)
            generateDnsIdentity(ctx);
    }
    if (!identityAvailable)
        postStatus(ctx, QObject::tr("warning_mdns_name_uniqueness"));

    postStatus(ctx, QObject::tr("status_active_endpoint")
                        .arg(QString::fromUtf8(ctx->deviceName))
                        .arg(QString::fromUtf8(inet_ntoa(*((struct in_addr *)&ctx->localIp))))
                        .arg(ctx->tcpPort));

#ifdef Q_OS_BLACKBERRY
    ctx->bleWakeActive = startBleWakeListener(ctx);
    ctx->nextBleInitMs = monotonicMs() + 10000;
#endif

    // Burst iniziale: rende BBX Share visibile appena Android apre Quick Share,
    // senza aspettare il normale refresh mDNS.
    sendAnnounce(ctx, udp);
    armAnnounceBurst(ctx, monotonicMs());

    struct pollfd fds[2];
    for (; !ctx->svc->stopRequested();) {
        qint64 now = monotonicMs();
        if (now >= ctx->nextIpCheckMs) {
            ctx->nextIpCheckMs = now + 10000;
            refreshLocalIp(ctx, udp, now);
        }
#ifdef Q_OS_BLACKBERRY
        if (!ctx->bleWakeActive && now >= ctx->nextBleInitMs) {
            ctx->bleWakeActive = startBleWakeListener(ctx);
            ctx->nextBleInitMs = now + 10000;
        }
#endif
        if (ctx->bleWakeRequested.fetchAndStoreOrdered(0) != 0 &&
            now - ctx->lastBleWakeMs >= BLE_WAKE_THROTTLE_MS) {
            // Android e' entrato nella superficie Quick Share: ripubblica
            // immediatamente, come fa rquickshare su Linux.
            sendAnnounce(ctx, udp);
            armAnnounceBurst(ctx, now);
            ctx->lastBleWakeMs = now;
            postStatus(ctx, QObject::tr("Segnale Quick Share BLE rilevato: annuncio Wi-Fi inviato"));
        }
        if (ctx->svc->takeScanRequest()) {
            ctx->scanActive = true;
            ctx->scanDeadlineMs = now + 5000;
            ctx->nextScanQueryMs = now + 1000;
            ctx->scanQueriesLeft = 2;
            sendMulticast(udp, discoveryQuery());
            sendAnnounce(ctx, udp);
            armAnnounceBurst(ctx, now);
        }
        QString resolveInstance;
        if (ctx->svc->takeResolveRequest(&resolveInstance)) {
            const QByteArray instance = resolveInstance.toLatin1().toLower();
            if (!instance.isEmpty()) {
                sendMulticast(udp, recordQuery(instance, QTYPE_SRV));
                sendMulticast(udp, recordQuery(instance, QTYPE_TXT));
            }
        }
        now = monotonicMs();
        if (ctx->scanActive && ctx->scanQueriesLeft > 0 &&
            now >= ctx->nextScanQueryMs) {
            sendMulticast(udp, discoveryQuery());
            --ctx->scanQueriesLeft;
            ctx->nextScanQueryMs = now + 2000;
        }
        if (ctx->scanActive && now >= ctx->scanDeadlineMs) {
            ctx->scanActive = false;
            QMetaObject::invokeMethod(ctx->svc, "setScanning", Qt::QueuedConnection,
                                      Q_ARG(bool, false));
            postStatus(ctx, QObject::tr("Ricerca terminata"));
        }
        if (now >= ctx->nextAnnounceMs) {
            sendAnnounce(ctx, udp);
            if (ctx->announceBurstLeft > 0) {
                --ctx->announceBurstLeft;
                ctx->nextAnnounceMs = now +
                    (ctx->announceBurstLeft == 3 ? 250 :
                     ctx->announceBurstLeft == 2 ? 500 :
                     ctx->announceBurstLeft == 1 ? 1000 : ANNOUNCE_STEADY_MS);
            } else {
                ctx->nextAnnounceMs = now + ANNOUNCE_STEADY_MS;
            }
        }
        if (expireDiscoveryRecords(ctx, now))
            publishDiscoveredDevices(ctx);
        if (ctx->scanActive)
            sendResolutionQueries(ctx, udp, now);
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
#ifdef Q_OS_BLACKBERRY
    if (ctx->bleWakeActive)
        bt_le_deinit();
#endif
    close(udp);
    close(tcp);
    delete ctx;
    return 0;
}

} // namespace

ShareService::ShareService(QObject *parent)
    : QObject(parent), m_status(QObject::tr("Avvio del servizio...")),
      m_started(false), m_transferPending(false), m_consentDecision(-1),
      m_transferActive(false), m_transferProgress(0.0f),
      m_invokeManager(new bb::system::InvokeManager(this)),
      m_scanning(false), m_selectedDevicePort(0), m_sendActive(false),
      m_sendFailed(false),
      m_scanRequested(false), m_sendRefreshPending(false),
      m_stopRequested(0), m_workerStarted(false)
{
    m_events = new bb::cascades::ArrayDataModel(this);
    m_devices = new bb::cascades::ArrayDataModel(this);
    loadHistory();
    const bool connected = connect(
        m_invokeManager,
        SIGNAL(invoked(const bb::system::InvokeRequest&)),
        this,
        SLOT(handleInvoke(const bb::system::InvokeRequest&)));
    Q_ASSERT(connected);
    Q_UNUSED(connected);
}

ShareService::~ShareService()
{
    m_stopRequested.fetchAndStoreOrdered(1);
    if (m_workerStarted)
        pthread_join(m_workerThread, 0);
}

bool ShareService::takeScanRequest()
{
    QMutexLocker locker(&m_discoveryMutex);
    const bool requested = m_scanRequested;
    m_scanRequested = false;
    return requested;
}

bool ShareService::takeResolveRequest(QString *instance)
{
    QMutexLocker locker(&m_discoveryMutex);
    if (m_resolveInstanceRequested.isEmpty()) return false;
    *instance = m_resolveInstanceRequested;
    m_resolveInstanceRequested.clear();
    return true;
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
    saveHistory();
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

// Registra solo i trasferimenti reali (file inviati/ricevuti). Lo storico e'
// persistente: fino a 50 voci su file ini nella cartella dati dell'app.
void ShareService::appendEvent(const QString &name, const QString &detail,
                               const QString &path)
{
    const QDateTime now = QDateTime::currentDateTime();
    const QString stamp = now.date() == QDate::currentDate()
        ? now.toString(QString::fromUtf8("HH:mm"))
        : now.toString(QString::fromUtf8("dd/MM HH:mm"));

    QVariantMap row;
    row["title"] = name;
    row["detail"] = detail + QString::fromUtf8(" \u00b7 ") + stamp;
    if (QFileInfo(path).isFile())
        row["path"] = path;
    m_events->insert(0, row);
    emit eventsChanged();
    saveHistory();
}

void ShareService::saveHistory()
{
    QStringList rows;
    const int count = qMin(m_events->size(), 50);
    for (int i = 0; i < count; ++i) {
        const QVariantMap row = m_events->value(i).toMap();
        rows.append(row.value("title").toString() + QChar(0x1f) +
                    row.value("detail").toString() + QChar(0x1f) +
                    row.value("path").toString());
    }
    QSettings settings(QDir::homePath() + QString::fromUtf8("/history.ini"),
                       QSettings::IniFormat);
    settings.setValue(QString::fromUtf8("history/version"), 2);
    settings.setValue(QString::fromUtf8("history/rows"), rows);
}

void ShareService::loadHistory()
{
    QSettings settings(QDir::homePath() + QString::fromUtf8("/history.ini"),
                       QSettings::IniFormat);
    // version 2 = voci gia' in formato localizzato; scarta lo storico pre-i18n
    const int version = settings.value(QString::fromUtf8("history/version"), 0).toInt();
    const QStringList rows = version >= 2
        ? settings.value(QString::fromUtf8("history/rows")).toStringList()
        : QStringList();
    bool migrated = false;
    for (int i = rows.size() - 1; i >= 0; --i) {
        const QStringList fields = rows[i].split(QChar(0x1f));
        if (fields.size() != 3)
            continue;
        QVariantMap row;
        row["title"] = fields[0];
        QString detail = fields[1];
        // Version 2 persisted the already-rendered Italian sentence. Rebuild
        // the two transfer prefixes through QObject::tr() so old entries also
        // follow the current device language after the translator is loaded.
        const QString separator = QString::fromUtf8(" · ");
        const QString receivedPrefix = QString::fromUtf8("Ricevuto da ");
        const QString sentPrefix = QString::fromUtf8("Inviato a ");
        QString sourcePrefix;
        QString translatedTemplate;
        if (detail.startsWith(receivedPrefix)) {
            sourcePrefix = receivedPrefix;
            translatedTemplate = QObject::tr("history_received_from");
        } else if (detail.startsWith(sentPrefix)) {
            sourcePrefix = sentPrefix;
            translatedTemplate = QObject::tr("history_sent_to");
        }
        if (!sourcePrefix.isEmpty()) {
            const int firstSeparator = detail.indexOf(separator, sourcePrefix.size());
            const int secondSeparator = firstSeparator < 0 ? -1
                : detail.indexOf(separator, firstSeparator + separator.size());
            if (firstSeparator > sourcePrefix.size() && secondSeparator > firstSeparator) {
                const QString peer = detail.mid(sourcePrefix.size(),
                                                firstSeparator - sourcePrefix.size());
                const QString size = detail.mid(firstSeparator + separator.size(),
                                                secondSeparator - firstSeparator - separator.size());
                const QString stamp = detail.mid(secondSeparator + separator.size());
                detail = translatedTemplate.arg(peer, size) + separator + stamp;
                migrated = true;
            }
        }
        row["detail"] = detail;
        if (QFileInfo(fields[2]).isFile())
            row["path"] = fields[2];
        m_events->append(row);
    }
    if (!m_events->isEmpty())
        emit eventsChanged();
    if (migrated)
        saveHistory();
}

void ShareService::openReceivedFile(const QString &path)
{
    const QFileInfo file(path);
    if (!file.exists())
        return;

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
    selectOutgoingFiles(QStringList() << path);
}

void ShareService::selectOutgoingFiles(const QStringList &paths)
{
    QStringList accepted;
    qint64 bytes = 0;
    for (int i = 0; i < paths.size(); ++i) {
        const QFileInfo file(paths.at(i));
        if (!file.exists() || !file.isFile()) continue;
        const QString absolute = file.absoluteFilePath();
        if (accepted.contains(absolute)) continue;
        if (file.size() < 0 || bytes > Q_INT64_C(0x7fffffffffffffff) - file.size())
            return;
        accepted.append(absolute);
        bytes += file.size();
    }
    if (accepted.isEmpty()) return;
    m_outgoingPaths = accepted;
    m_outgoingPath = accepted.first();
    m_outgoingName = accepted.size() == 1
        ? QFileInfo(accepted.first()).fileName()
        : QObject::tr("%1 file").arg(accepted.size());
    if (bytes >= 1024 * 1024)
        m_outgoingDetail = QObject::tr("size_mb_ready")
            .arg((double)bytes / (1024.0 * 1024.0), 0, 'f', 1);
    else
        m_outgoingDetail = QObject::tr("size_kb_ready")
            .arg(qMax<qint64>(1, (bytes + 1023) / 1024));
    emit outgoingChanged();
}

void ShareService::clearOutgoingFile()
{
    if (m_outgoingPaths.isEmpty())
        return;
    m_outgoingPaths.clear();
    m_outgoingPath.clear();
    m_outgoingName.clear();
    m_outgoingDetail.clear();
    emit outgoingChanged();
}

void ShareService::clearDevices()
{
    m_devices->clear();
    emit devicesChanged();
    if (m_selectedDeviceInstance.isEmpty() && m_selectedDeviceName.isEmpty() &&
        m_selectedDeviceAddress.isEmpty() && m_selectedDevicePort == 0)
        return;
    m_selectedDeviceInstance.clear();
    m_selectedDeviceName.clear();
    m_selectedDeviceAddress.clear();
    m_selectedDevicePort = 0;
    emit deviceSelectionChanged();
}

void ShareService::setScanning(bool scanning)
{
    if (m_scanning == scanning) return;
    m_scanning = scanning;
    emit scanningChanged();
}

void ShareService::syncDevices(const QVariantList &devices)
{
    bool selectedFound = false;
    QString selectedName, selectedAddress;
    int selectedPort = 0;
    for (int i = 0; i < devices.size(); ++i) {
        const QVariantMap row = devices.at(i).toMap();
        if (!m_selectedDeviceInstance.isEmpty() &&
            row.value("instance").toString() == m_selectedDeviceInstance) {
            selectedFound = true;
            selectedName = row.value("name").toString();
            selectedAddress = row.value("address").toString();
            selectedPort = row.value("port").toInt();
        }
    }

    m_devices->clear();
    for (int i = 0; i < devices.size(); ++i)
        m_devices->append(devices.at(i).toMap());
    emit devicesChanged();

    if (selectedFound) {
        if (m_selectedDeviceName != selectedName ||
            m_selectedDeviceAddress != selectedAddress ||
            m_selectedDevicePort != selectedPort) {
            m_selectedDeviceName = selectedName;
            m_selectedDeviceAddress = selectedAddress;
            m_selectedDevicePort = selectedPort;
            emit deviceSelectionChanged();
        }
    } else if (!m_selectedDeviceInstance.isEmpty()) {
        m_selectedDeviceInstance.clear();
        m_selectedDeviceName.clear();
        m_selectedDeviceAddress.clear();
        m_selectedDevicePort = 0;
        emit deviceSelectionChanged();
    }
}

void ShareService::scanDevices()
{
    if (m_scanning) return;
    setScanning(true);
    setStatus(QObject::tr("status_search_nearby"));
    QMutexLocker locker(&m_discoveryMutex);
    m_scanRequested = true;
}

void ShareService::selectDevice(const QString &address, int port,
                                const QString &name, const QString &instance)
{
    m_selectedDeviceAddress = address;
    m_selectedDevicePort = port;
    m_selectedDeviceName = name;
    m_selectedDeviceInstance = instance;
    emit deviceSelectionChanged();
}

void ShareService::clearDeviceSelection()
{
    if (!deviceReady()) return;
    m_selectedDeviceAddress.clear();
    m_selectedDeviceName.clear();
    m_selectedDeviceInstance.clear();
    m_selectedDevicePort = 0;
    emit deviceSelectionChanged();
}

void ShareService::sendOutgoing()
{
    if (m_sendActive || m_sendRefreshPending || !outgoingReady() ||
        !deviceReady() || m_selectedDeviceInstance.isEmpty()) return;
    {
        QMutexLocker locker(&m_discoveryMutex);
        m_resolveInstanceRequested = m_selectedDeviceInstance;
    }
    m_sendRefreshPending = true;
    setStatus(QObject::tr("status_search_nearby"));
    QTimer::singleShot(2000, this, SLOT(sendOutgoingResolved()));
}

void ShareService::sendOutgoingResolved()
{
    m_sendRefreshPending = false;
    if (m_sendActive || !outgoingReady() || !deviceReady()) return;
    bool current = false;
    for (int i = 0; i < m_devices->size(); ++i) {
        const QVariantMap row = m_devices->value(i).toMap();
        if (row.value("instance").toString() == m_selectedDeviceInstance) {
            m_selectedDeviceAddress = row.value("address").toString();
            m_selectedDevicePort = row.value("port").toInt();
            m_selectedDeviceName = row.value("name").toString();
            current = true;
            break;
        }
    }
    if (!current) {
        clearDeviceSelection();
        setStatus(QObject::tr("error_device_unavailable"));
        return;
    }
    m_sendActive = true;
    m_sendFailed = false;
    m_sendStatus = QObject::tr("status_connecting_device");
    emit sendStateChanged();
    setTransferProgress(0.0f, QObject::tr("status_connecting"));
    SenderArgs *args = new SenderArgs;
    args->paths = m_outgoingPaths;
    args->address = m_selectedDeviceAddress;
    args->port = m_selectedDevicePort;
    args->deviceName = m_selectedDeviceName;
    args->localDeviceName = m_localDeviceName;
    args->service = this;
    pthread_t th;
    if (pthread_create(&th, 0, &senderMain, args) != 0) {
        delete args;
        m_sendActive = false;
        m_sendFailed = true;
        m_sendStatus = QObject::tr("Impossibile avviare l'invio");
        emit sendStateChanged();
        clearTransferProgress();
        setStatus(QObject::tr("Avvio invio fallito"));
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
        m_sendStatus = success ? QObject::tr("Invio completato")
                               : QObject::tr("Invio non riuscito");
    if (m_transferActive)
        clearTransferProgress();
    emit sendStateChanged();
}

void ShareService::handleInvoke(const bb::system::InvokeRequest &request)
{
    if (request.action() != QLatin1String("bb.action.SHARE"))
        return;

    const QString path = request.uri().toLocalFile();
    if (!path.isEmpty())
        selectOutgoingFile(path);
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
    ctx->bleWakeRequested = 0;
    ctx->lastBleWakeMs = 0;
    ctx->bleWakeActive = false;
    ctx->nextBleInitMs = 0;
    ctx->nextIpCheckMs = 0;
    ctx->deviceName = localDeviceName();
    m_localDeviceName = QString::fromUtf8(ctx->deviceName);

    srand((unsigned)time(0) ^ (unsigned)getpid());
    generateDnsIdentity(ctx);

    // endpoint info: bitfield (tipo device phone=1, visibile) + 16 byte random + nome
    unsigned char ei[64];
    int eiLen = 0;
    ei[eiLen++] = 1 << 1; // deviceType=phone, visibility=0 (visibile)
    for (int i = 0; i < 16; ++i) ei[eiLen++] = (unsigned char)(rand() & 0xFF);
    int nameLen = qMin(ctx->deviceName.size(), 45);
    ei[eiLen++] = (unsigned char)nameLen;
    memcpy(ei + eiLen, ctx->deviceName.constData(), nameLen);
    eiLen += nameLen;
    ctx->endpointInfoB64 = urlSafeB64(ei, eiLen);

    m_stopRequested.fetchAndStoreOrdered(0);
    if (pthread_create(&m_workerThread, 0, &workerMain, ctx) != 0) {
        delete ctx;
        m_started = false;
        setStatus(QObject::tr("Impossibile avviare il servizio di rete"));
        return;
    }
    m_workerStarted = true;
}
