#include "QuickShareSender.hpp"

#include "ProtoWire.hpp"
#include "ShareService.hpp"

#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QMetaObject>
#include <QtCore/QTime>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace {

const int MAX_FRAME_SIZE = 5 * 1024 * 1024;
const int MAX_CONTROL_PAYLOAD_SIZE = 5 * 1024 * 1024;
const qint64 MIN_TRANSFER_DEADLINE_MS = 5 * 60 * 1000;
const qint64 MAX_TRANSFER_DEADLINE_MS = 6 * 60 * 60 * 1000;

bool nestedBytes(const QByteArray &outer, int field, QByteArray *inner)
{
    return ProtoWire::bytes(outer, field, inner);
}

bool nestedVarint(const QByteArray &outer, int field, quint64 *value)
{
    return ProtoWire::varint(outer, field, value);
}

QByteArray hmacSha256(const QByteArray &key, const QByteArray &data)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    HMAC(EVP_sha256(), key.constData(), key.size(),
         (const unsigned char *)data.constData(), data.size(), digest, &size);
    return QByteArray((const char *)digest, (int)size);
}

bool secureEquals(const QByteArray &left, const QByteArray &right)
{
    return left.size() == right.size() &&
           CRYPTO_memcmp(left.constData(), right.constData(), left.size()) == 0;
}

QByteArray sha256(const QByteArray &data)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data.constData(), data.size(), digest);
    return QByteArray((const char *)digest, SHA256_DIGEST_LENGTH);
}

QByteArray sha512(const QByteArray &data)
{
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512((const unsigned char *)data.constData(), data.size(), digest);
    return QByteArray((const char *)digest, SHA512_DIGEST_LENGTH);
}

}

QuickShareSender::QuickShareSender(const QStringList &paths, const QString &address,
                                   int port, const QString &deviceName,
                                   const QString &localDeviceName,
                                   ShareService *service)
    : m_fd(-1), m_paths(paths), m_address(address), m_port(port),
      m_deviceName(deviceName), m_localDeviceName(localDeviceName),
      m_service(service), m_sendSequence(0), m_receiveSequence(0),
      m_totalSize(0), m_sentBytes(0), m_transferDeadlineMs(0),
      m_safeDisconnect(false), m_ecKey(0)
{
}

QuickShareSender::~QuickShareSender()
{
    if (m_ecKey)
        EC_KEY_free((EC_KEY *)m_ecKey);
    if (m_fd >= 0)
        close(m_fd);
}

void QuickShareSender::status(const QString &message) const
{
    QMetaObject::invokeMethod(m_service, "setStatus", Qt::QueuedConnection,
                              Q_ARG(QString, message));
    QMetaObject::invokeMethod(m_service, "setSendStatus", Qt::QueuedConnection,
                              Q_ARG(QString, message));
}

bool QuickShareSender::fail(const QString &message)
{
    status(QObject::tr("Errore invio: %1").arg(message));
    QMetaObject::invokeMethod(m_service, "clearTransferProgress", Qt::QueuedConnection);
    return false;
}

QByteArray QuickShareSender::randomBytes(int size) const
{
    QByteArray result(size, 0);
    if (RAND_bytes((unsigned char *)result.data(), size) != 1) {
        for (int i = 0; i < size; ++i)
            result[i] = (char)(qrand() & 0xff);
    }
    return result;
}

bool QuickShareSender::connectPeer()
{
    m_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_fd < 0)
        return fail(QObject::tr("socket TCP: %1").arg(strerror(errno)));

    const int flags = fcntl(m_fd, F_GETFL, 0);
    fcntl(m_fd, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons((quint16)m_port);
    if (inet_pton(AF_INET, m_address.toUtf8().constData(), &peer.sin_addr) != 1)
        return fail(QObject::tr("indirizzo device non valido"));
    int rc = connect(m_fd, (struct sockaddr *)&peer, sizeof(peer));
    if (rc != 0 && errno != EINPROGRESS)
        return fail(QObject::tr("connessione a %1:%2: %3")
                    .arg(m_address).arg(m_port).arg(strerror(errno)));
    if (rc != 0) {
        struct pollfd pfd;
        pfd.fd = m_fd; pfd.events = POLLOUT; pfd.revents = 0;
        if (poll(&pfd, 1, 10000) <= 0)
            return fail(QObject::tr("timeout connessione al device"));
        int error = 0; socklen_t len = sizeof(error);
        getsockopt(m_fd, SOL_SOCKET, SO_ERROR, &error, &len);
        if (error != 0)
            return fail(QObject::tr("connessione rifiutata: %1").arg(strerror(error)));
    }
    fcntl(m_fd, F_SETFL, flags);
    // Se il receiver smette di leggere (Wi-Fi in power save, app in background),
    // send()/recv() bloccanti non devono restare appesi per sempre.
    struct timeval ioTimeout;
    ioTimeout.tv_sec = 30;
    ioTimeout.tv_usec = 0;
    setsockopt(m_fd, SOL_SOCKET, SO_SNDTIMEO, &ioTimeout, sizeof(ioTimeout));
    setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, &ioTimeout, sizeof(ioTimeout));
    return true;
}

bool QuickShareSender::receiveExact(char *data, int size, int timeoutMs)
{
    int done = 0;
    while (done < size) {
        struct pollfd pfd;
        pfd.fd = m_fd; pfd.events = POLLIN; pfd.revents = 0;
        if (poll(&pfd, 1, timeoutMs) <= 0)
            return false;
        int count = recv(m_fd, data + done, size - done, 0);
        if (count <= 0)
            return false;
        done += count;
    }
    return true;
}

bool QuickShareSender::sendAll(const char *data, int size)
{
    int done = 0;
    while (done < size) {
        if (m_transferDeadlineMs > 0 &&
            m_transferTimer.elapsed() > m_transferDeadlineMs)
            return false;
        struct pollfd pfd;
        pfd.fd = m_fd; pfd.events = POLLOUT; pfd.revents = 0;
        int waitMs = 10000;
        if (m_transferDeadlineMs > 0)
            waitMs = (int)qMin<qint64>(waitMs,
                qMax<qint64>(1, m_transferDeadlineMs - m_transferTimer.elapsed()));
        if (poll(&pfd, 1, waitMs) <= 0 || !(pfd.revents & POLLOUT))
            return false;
        int count = send(m_fd, data + done, size - done, 0);
        if (count <= 0)
            return false;
        done += count;
    }
    return true;
}

bool QuickShareSender::readFrame(QByteArray *frame, int timeoutMs)
{
    unsigned char bytes[4];
    if (!receiveExact((char *)bytes, 4, timeoutMs))
        return false;
    quint32 length = ((quint32)bytes[0] << 24) | ((quint32)bytes[1] << 16) |
                     ((quint32)bytes[2] << 8) | bytes[3];
    if (!length || length > (quint32)MAX_FRAME_SIZE)
        return fail(QObject::tr("frame ricevuto non valido"));
    frame->resize((int)length);
    return receiveExact(frame->data(), (int)length, timeoutMs);
}

bool QuickShareSender::sendFrame(const QByteArray &frame)
{
    quint32 length = (quint32)frame.size();
    unsigned char bytes[4] = {(unsigned char)(length >> 24),
                              (unsigned char)(length >> 16),
                              (unsigned char)(length >> 8), (unsigned char)length};
    return sendAll((const char *)bytes, 4) && sendAll(frame.constData(), frame.size());
}

QByteArray QuickShareSender::hkdf(const QByteArray &ikm, const QByteArray &salt,
                                  const QByteArray &info, int size) const
{
    const QByteArray prk = hmacSha256(salt, ikm);
    QByteArray output, previous;
    unsigned char counter = 1;
    while (output.size() < size) {
        QByteArray input = previous + info;
        input.append((char)counter++);
        previous = hmacSha256(prk, input);
        output.append(previous);
    }
    return output.left(size);
}

QByteArray QuickShareSender::aesCrypt(const QByteArray &input, const QByteArray &key,
                                      const QByteArray &iv, bool encrypt) const
{
    if (key.size() != 32 || iv.size() != 16)
        return QByteArray();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return QByteArray();
    int ok = encrypt ? EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), 0,
                    (const unsigned char *)key.constData(), (const unsigned char *)iv.constData())
                     : EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), 0,
                    (const unsigned char *)key.constData(), (const unsigned char *)iv.constData());
    QByteArray output(input.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int first = 0, last = 0;
    if (ok)
        ok = encrypt ? EVP_EncryptUpdate(ctx, (unsigned char *)output.data(), &first,
                    (const unsigned char *)input.constData(), input.size())
                     : EVP_DecryptUpdate(ctx, (unsigned char *)output.data(), &first,
                    (const unsigned char *)input.constData(), input.size());
    if (ok)
        ok = encrypt ? EVP_EncryptFinal_ex(ctx, (unsigned char *)output.data() + first, &last)
                     : EVP_DecryptFinal_ex(ctx, (unsigned char *)output.data() + first, &last);
    EVP_CIPHER_CTX_free(ctx);
#else
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    int ok = encrypt ? EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), 0,
                    (const unsigned char *)key.constData(), (const unsigned char *)iv.constData())
                     : EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), 0,
                    (const unsigned char *)key.constData(), (const unsigned char *)iv.constData());
    QByteArray output(input.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int first = 0, last = 0;
    if (ok)
        ok = encrypt ? EVP_EncryptUpdate(&ctx, (unsigned char *)output.data(), &first,
                    (const unsigned char *)input.constData(), input.size())
                     : EVP_DecryptUpdate(&ctx, (unsigned char *)output.data(), &first,
                    (const unsigned char *)input.constData(), input.size());
    if (ok)
        ok = encrypt ? EVP_EncryptFinal_ex(&ctx, (unsigned char *)output.data() + first, &last)
                     : EVP_DecryptFinal_ex(&ctx, (unsigned char *)output.data() + first, &last);
    EVP_CIPHER_CTX_cleanup(&ctx);
#endif
    if (!ok)
        return QByteArray();
    output.resize(first + last);
    return output;
}

QByteArray QuickShareSender::signedCoordinate(const void *rawBn) const
{
    const BIGNUM *bn = (const BIGNUM *)rawBn;
    QByteArray value(BN_num_bytes(bn), 0);
    BN_bn2bin(bn, (unsigned char *)value.data());
    if (!value.isEmpty() && ((unsigned char)value.at(0) & 0x80))
        value.prepend('\0');
    return value;
}

QByteArray QuickShareSender::endpointInfo() const
{
    QByteArray info;
    info.append((char)(1 << 1));
    info.append(randomBytes(16));
    QByteArray name = m_localDeviceName.toUtf8();
    if (name.isEmpty()) name = "BBX Share";
    name = name.left(45);
    info.append((char)name.size());
    info.append(name);
    return info;
}

QByteArray QuickShareSender::makeOfflineFrame(int type, int fieldNumber,
                                              const QByteArray &payload) const
{
    QByteArray v1;
    ProtoWire::appendVarint(&v1, 1, type);
    if (fieldNumber > 0)
        ProtoWire::appendBytes(&v1, fieldNumber, payload);
    QByteArray offline;
    ProtoWire::appendVarint(&offline, 1, 1);
    ProtoWire::appendBytes(&offline, 2, v1);
    return offline;
}

bool QuickShareSender::sendConnectionRequest()
{
    // endpoint_id (field 1) e endpoint_name (field 2) sono richiesti dai
    // receiver Nearby moderni anche se il server BBX li ignora.
    QByteArray endpointId;
    endpointId.append(randomBytes(4));
    for (int i = 0; i < endpointId.size(); ++i)
        endpointId[i] = (char)('A' + ((unsigned char)endpointId.at(i) % 26));
    QByteArray fullRequest;
    ProtoWire::appendBytes(&fullRequest, 1, endpointId);
    QByteArray localName = m_localDeviceName.toUtf8();
    if (localName.isEmpty()) localName = "BBX Share";
    ProtoWire::appendBytes(&fullRequest, 2, localName.left(45));
    ProtoWire::appendBytes(&fullRequest, 6, endpointInfo());
    ProtoWire::appendVarint(&fullRequest, 5, 5); // WIFI_LAN
    QByteArray v1;
    ProtoWire::appendVarint(&v1, 1, 1);
    ProtoWire::appendBytes(&v1, 2, fullRequest);
    QByteArray frame;
    ProtoWire::appendVarint(&frame, 1, 1);
    ProtoWire::appendBytes(&frame, 2, v1);
    return sendFrame(frame);
}

bool QuickShareSender::sendClientInit()
{
    m_ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!m_ecKey || EC_KEY_generate_key((EC_KEY *)m_ecKey) != 1)
        return fail(QObject::tr("generazione chiave P-256 fallita"));

    // ClientFinish viene costruito prima e impegnato con SHA-512 nel ClientInit.
    const EC_GROUP *group = EC_KEY_get0_group((EC_KEY *)m_ecKey);
    const EC_POINT *point = EC_KEY_get0_public_key((EC_KEY *)m_ecKey);
    BIGNUM *x = BN_new(); BIGNUM *y = BN_new();
    if (!x || !y || EC_POINT_get_affine_coordinates_GFp(group, point, x, y, 0) != 1)
        return fail(QObject::tr("lettura chiave P-256 fallita"));
    QByteArray ecPublic;
    ProtoWire::appendBytes(&ecPublic, 1, signedCoordinate(x));
    ProtoWire::appendBytes(&ecPublic, 2, signedCoordinate(y));
    BN_free(x); BN_free(y);
    QByteArray generic;
    ProtoWire::appendVarint(&generic, 1, 1);
    ProtoWire::appendBytes(&generic, 2, ecPublic);
    QByteArray finish;
    ProtoWire::appendBytes(&finish, 1, generic);
    m_clientFinishRaw.clear();
    ProtoWire::appendVarint(&m_clientFinishRaw, 1, 4);
    ProtoWire::appendBytes(&m_clientFinishRaw, 2, finish);

    QByteArray init;
    ProtoWire::appendVarint(&init, 1, 1);
    ProtoWire::appendBytes(&init, 2, randomBytes(32));
    QByteArray commitment = sha512(m_clientFinishRaw);
    QByteArray cipher;
    ProtoWire::appendVarint(&cipher, 1, 100);
    ProtoWire::appendBytes(&cipher, 2, commitment);
    ProtoWire::appendBytes(&init, 3, cipher);
    ProtoWire::appendBytes(&init, 4, QByteArray("AES_256_CBC-HMAC_SHA256"));
    m_clientInitRaw.clear();
    ProtoWire::appendVarint(&m_clientInitRaw, 1, 2);
    ProtoWire::appendBytes(&m_clientInitRaw, 2, init);
    return sendFrame(m_clientInitRaw);
}

bool QuickShareSender::processServerInit(const QByteArray &frame)
{
    quint64 type = 0, version = 0, cipher = 0;
    QByteArray data, generic, ecPublic, xBytes, yBytes;
    if (!nestedVarint(frame, 1, &type) || type != 3 ||
        !nestedBytes(frame, 2, &data) || !nestedVarint(data, 1, &version) || version != 1 ||
        !nestedVarint(data, 3, &cipher) || cipher != 100 ||
        !nestedBytes(data, 4, &generic) || !nestedVarint(generic, 1, &version) || version != 1 ||
        !nestedBytes(generic, 2, &ecPublic) || !nestedBytes(ecPublic, 1, &xBytes) ||
        !nestedBytes(ecPublic, 2, &yBytes))
        return fail(QObject::tr("UKEY2 ServerInit non valido"));

    while (xBytes.size() > 32 && xBytes.at(0) == 0) xBytes.remove(0, 1);
    while (yBytes.size() > 32 && yBytes.at(0) == 0) yBytes.remove(0, 1);
    if (xBytes.size() > 32 || yBytes.size() > 32)
        return fail(QObject::tr("coordinate server non valide"));
    xBytes = QByteArray(32 - xBytes.size(), 0) + xBytes;
    yBytes = QByteArray(32 - yBytes.size(), 0) + yBytes;
    const EC_GROUP *group = EC_KEY_get0_group((EC_KEY *)m_ecKey);
    EC_POINT *peer = EC_POINT_new(group);
    BIGNUM *x = BN_bin2bn((const unsigned char *)xBytes.constData(), 32, 0);
    BIGNUM *y = BN_bin2bn((const unsigned char *)yBytes.constData(), 32, 0);
    bool valid = peer && x && y &&
        EC_POINT_set_affine_coordinates_GFp(group, peer, x, y, 0) == 1 &&
        EC_POINT_is_on_curve(group, peer, 0) == 1;
    BN_free(x); BN_free(y);
    if (!valid) { EC_POINT_free(peer); return fail(QObject::tr("punto server non valido")); }
    unsigned char shared[32];
    int sharedSize = ECDH_compute_key(shared, sizeof(shared), peer, (EC_KEY *)m_ecKey, 0);
    EC_POINT_free(peer);
    if (sharedSize <= 0)
        return fail(QObject::tr("ECDH server fallito"));
    QByteArray secret((const char *)shared, sharedSize);
    if (secret.size() < 32) secret.prepend(QByteArray(32 - secret.size(), 0));
    const QByteArray derived = sha256(secret);
    const QByteArray info = m_clientInitRaw + frame;
    const QByteArray auth = hkdf(derived, "UKEY2 v1 auth", info, 32);
    const QByteArray next = hkdf(derived, "UKEY2 v1 next", info, 32);
    m_pin = pinFromAuthKey(auth);
    static const unsigned char d2dSaltBytes[32] = {
        0x82,0xaa,0x55,0xa0,0xd3,0x97,0xf8,0x83,0x46,0xca,0x1c,0xee,0x8d,0x39,0x09,0xb9,
        0x5f,0x13,0xfa,0x7d,0xeb,0x1d,0x4a,0xb3,0x83,0x76,0xb8,0x25,0x6d,0xa8,0x55,0x10};
    static const unsigned char secureSaltBytes[32] = {
        0xbf,0x9d,0x2a,0x53,0xc6,0x36,0x16,0xd7,0x5d,0xb0,0xa7,0x16,0x5b,0x91,0xc1,0xef,
        0x73,0xe5,0x37,0xf2,0x42,0x74,0x05,0xfa,0x23,0x61,0x0a,0x4b,0xe6,0x57,0x64,0x2e};
    const QByteArray d2d((const char *)d2dSaltBytes, 32);
    const QByteArray secure((const char *)secureSaltBytes, 32);
    const QByteArray client = hkdf(next, d2d, "client", 32);
    const QByteArray server = hkdf(next, d2d, "server", 32);
    m_encryptKey = hkdf(client, secure, "ENC:2", 32);
    m_sendHmacKey = hkdf(client, secure, "SIG:1", 32);
    m_decryptKey = hkdf(server, secure, "ENC:2", 32);
    m_receiveHmacKey = hkdf(server, secure, "SIG:1", 32);
    m_serverInitRaw = frame;
    return true;
}

bool QuickShareSender::sendClientFinish()
{
    return sendFrame(m_clientFinishRaw);
}

bool QuickShareSender::sendConnectionResponse()
{
    QByteArray response;
    ProtoWire::appendVarint(&response, 3, 1);
    // Advertise support for the safe-disconnect handshake used by recent
    // Android/Samsung Quick Share receivers.
    ProtoWire::appendVarint(&response, 7, 1);
    QByteArray osInfo;
    ProtoWire::appendVarint(&osInfo, 1, 100); // LINUX/QNX neutro
    ProtoWire::appendBytes(&response, 4, osInfo);
    return sendFrame(makeOfflineFrame(2, 3, response));
}

bool QuickShareSender::processConnectionResponse(const QByteArray &frame)
{
    QByteArray v1, response;
    quint64 version = 0, type = 0, decision = 0, legacyStatus = 1;
    if (!nestedVarint(frame, 1, &version) || version != 1 ||
        !nestedBytes(frame, 2, &v1) ||
        !nestedVarint(v1, 1, &type) || type != 2 ||
        !nestedBytes(v1, 3, &response))
        return fail(QObject::tr("ConnectionResponse del receiver non valida"));

    const bool hasDecision = nestedVarint(response, 3, &decision);
    const bool hasLegacyStatus = nestedVarint(response, 1, &legacyStatus);
    quint64 safeDisconnectVersion = 0;
    m_safeDisconnect = nestedVarint(response, 7, &safeDisconnectVersion) &&
                       safeDisconnectVersion >= 1;
    if ((!hasDecision && !hasLegacyStatus) ||
        (hasDecision ? decision != 1 : legacyStatus != 0))
        return fail(QObject::tr("connessione rifiutata dal receiver"));
    return true;
}

bool QuickShareSender::sendEncryptedOffline(const QByteArray &offline)
{
    QByteArray body;
    ProtoWire::appendBytes(&body, 1, offline);
    ProtoWire::appendVarint(&body, 2, (quint64)++m_sendSequence);
    const QByteArray iv = randomBytes(16);
    const QByteArray encrypted = aesCrypt(body, m_encryptKey, iv, true);
    if (encrypted.isEmpty())
        return fail(QObject::tr("cifratura AES fallita"));
    QByteArray metadata;
    ProtoWire::appendVarint(&metadata, 1, 13);
    ProtoWire::appendVarint(&metadata, 2, 1);
    QByteArray header;
    ProtoWire::appendVarint(&header, 1, 1);
    ProtoWire::appendVarint(&header, 2, 2);
    ProtoWire::appendBytes(&header, 5, iv);
    ProtoWire::appendBytes(&header, 6, metadata);
    QByteArray headerAndBody;
    ProtoWire::appendBytes(&headerAndBody, 1, header);
    ProtoWire::appendBytes(&headerAndBody, 2, encrypted);
    QByteArray secure;
    ProtoWire::appendBytes(&secure, 1, headerAndBody);
    ProtoWire::appendBytes(&secure, 2, hmacSha256(m_sendHmacKey, headerAndBody));
    return sendFrame(secure);
}

bool QuickShareSender::decryptOffline(const QByteArray &secure, QByteArray *offline)
{
    QByteArray headerAndBody, signature, header, body, iv;
    if (!nestedBytes(secure, 1, &headerAndBody) || !nestedBytes(secure, 2, &signature) ||
        !secureEquals(signature, hmacSha256(m_receiveHmacKey, headerAndBody)) ||
        !nestedBytes(headerAndBody, 1, &header) || !nestedBytes(headerAndBody, 2, &body) ||
        !nestedBytes(header, 5, &iv))
        return fail(QObject::tr("SecureMessage server non valido"));
    const QByteArray plain = aesCrypt(body, m_decryptKey, iv, false);
    quint64 seq = 0;
    if (plain.isEmpty() || !nestedBytes(plain, 1, offline) ||
        !nestedVarint(plain, 2, &seq) || seq != (quint64)++m_receiveSequence)
        return fail(QObject::tr("sequenza SecureMessage server non valida"));
    return true;
}

bool QuickShareSender::sendSharingFrame(const QByteArray &sharing)
{
    const QByteArray idBytes = randomBytes(8);
    quint64 id = 0;
    for (int i = 0; i < idBytes.size(); ++i)
        id = (id << 8) | (unsigned char)idBytes.at(i);
    // Keep the sign bit set so the integration path continuously exercises
    // valid negative protobuf int64 payload IDs.
    id |= Q_UINT64_C(0x8000000000000000);
    QByteArray header;
    ProtoWire::appendVarint(&header, 1, id);
    ProtoWire::appendVarint(&header, 2, 1);
    ProtoWire::appendVarint(&header, 3, (quint64)sharing.size());
    ProtoWire::appendVarint(&header, 4, 0);
    QByteArray chunk;
    ProtoWire::appendVarint(&chunk, 1, 0);
    ProtoWire::appendVarint(&chunk, 2, 0);
    ProtoWire::appendBytes(&chunk, 3, sharing);
    QByteArray transfer;
    ProtoWire::appendVarint(&transfer, 1, 1);
    ProtoWire::appendBytes(&transfer, 2, header);
    ProtoWire::appendBytes(&transfer, 3, chunk);
    if (!sendEncryptedOffline(makeOfflineFrame(3, 4, transfer))) return false;
    chunk.clear();
    ProtoWire::appendVarint(&chunk, 1, 1);
    ProtoWire::appendVarint(&chunk, 2, (quint64)sharing.size());
    transfer.clear();
    ProtoWire::appendVarint(&transfer, 1, 1);
    ProtoWire::appendBytes(&transfer, 2, header);
    ProtoWire::appendBytes(&transfer, 3, chunk);
    return sendEncryptedOffline(makeOfflineFrame(3, 4, transfer));
}

bool QuickShareSender::receiveSharingFrame(QByteArray *sharing, int timeoutMs)
{
    QTime timer;
    timer.start();
    for (;;) {
        const int remaining = timeoutMs - timer.elapsed();
        if (remaining <= 0)
            return false;
        QByteArray secure, offline;
        if (!readFrame(&secure, remaining) || !decryptOffline(secure, &offline))
            return false;
        const int result = processReceivedOffline(offline, sharing);
        if (result < 0) return false;
        if (result > 0) return true;
    }
}

int QuickShareSender::processReceivedOffline(const QByteArray &offline,
                                             QByteArray *sharing)
{
    QByteArray v1, transfer, header, chunk, body;
    if (!nestedBytes(offline, 2, &v1)) {
        fail(QObject::tr("frame server non valido"));
        return -1;
    }
    quint64 type = 0;
    if (!nestedVarint(v1, 1, &type)) {
        fail(QObject::tr("frame server senza tipo"));
        return -1;
    }
    if (type == 5) {
        QByteArray keepAlive;
        ProtoWire::appendVarint(&keepAlive, 1, 1);
        return sendEncryptedOffline(makeOfflineFrame(5, 6, keepAlive)) ? 0 : -1;
    }
    if (type == 6) {
        fail(QObject::tr("device Android ha annullato"));
        return -1;
    }
    if (type != 3 || !nestedBytes(v1, 4, &transfer) ||
        !nestedBytes(transfer, 2, &header) || !nestedBytes(transfer, 3, &chunk)) {
        fail(QObject::tr("risposta Share non valida"));
        return -1;
    }
    quint64 packetType = 0, id = 0, totalSize = 0, flags = 0, offset = 0;
    if (!nestedVarint(transfer, 1, &packetType) || packetType != 1 ||
        !nestedVarint(header, 1, &id) || !nestedVarint(header, 3, &totalSize) ||
        !nestedVarint(chunk, 1, &flags) || !nestedVarint(chunk, 2, &offset)) {
        fail(QObject::tr("payload risposta non valido"));
        return -1;
    }
    if (totalSize > (quint64)MAX_CONTROL_PAYLOAD_SIZE || offset > totalSize) {
        fail(QObject::tr("risposta Share troppo grande"));
        return -1;
    }
    nestedBytes(chunk, 3, &body);
    QByteArray &buffer = m_controlBuffers[id];
    if ((quint64)buffer.size() != offset ||
        (quint64)body.size() > totalSize - offset) {
        m_controlBuffers.remove(id);
        fail(QObject::tr("offset risposta non valido"));
        return -1;
    }
    buffer.append(body);
    if (!(flags & 1)) return 0;
    if ((quint64)buffer.size() != totalSize) {
        m_controlBuffers.remove(id);
        fail(QObject::tr("risposta Share incompleta"));
        return -1;
    }
    *sharing = buffer;
    m_controlBuffers.remove(id);
    return 1;
}

bool QuickShareSender::sendPairedKeyEncryption()
{
    QByteArray paired;
    ProtoWire::appendBytes(&paired, 1, randomBytes(72));
    ProtoWire::appendBytes(&paired, 2, randomBytes(6));
    QByteArray v1;
    ProtoWire::appendVarint(&v1, 1, 3);
    ProtoWire::appendBytes(&v1, 4, paired);
    QByteArray frame;
    ProtoWire::appendVarint(&frame, 1, 1);
    ProtoWire::appendBytes(&frame, 2, v1);
    return sendSharingFrame(frame);
}

bool QuickShareSender::sendPairedKeyResult()
{
    QByteArray result;
    ProtoWire::appendVarint(&result, 1, 3);
    QByteArray v1;
    ProtoWire::appendVarint(&v1, 1, 4);
    ProtoWire::appendBytes(&v1, 5, result);
    QByteArray frame;
    ProtoWire::appendVarint(&frame, 1, 1);
    ProtoWire::appendBytes(&frame, 2, v1);
    return sendSharingFrame(frame);
}

QString QuickShareSender::safeName(const QString &name) const
{
    QString value = QFileInfo(name).fileName();
    value.replace(QRegExp(QString::fromUtf8("[\\/\\?%\\*:\\|\"<>=]")), "_");
    return value.isEmpty() ? QString::fromUtf8("file.bin") : value;
}

QByteArray QuickShareSender::fileMimeType(const QString &name) const
{
    const QString suffix = QFileInfo(name).suffix().toLower();
    if (suffix == "jpg" || suffix == "jpeg") return "image/jpeg";
    if (suffix == "png") return "image/png";
    if (suffix == "gif") return "image/gif";
    if (suffix == "mp4" || suffix == "m4v") return "video/mp4";
    if (suffix == "mp3" || suffix == "m4a") return "audio/mpeg";
    if (suffix == "pdf") return "application/pdf";
    if (suffix == "txt" || suffix == "log") return "text/plain";
    return "application/octet-stream";
}

QString QuickShareSender::humanSize(qint64 bytes) const
{
    if (bytes < 1024) return QString::fromUtf8("%1 B").arg(bytes);
    if (bytes < 1024 * 1024) return QString::fromUtf8("%1 KB").arg(bytes / 1024.0, 0, 'f', 1);
    return QString::fromUtf8("%1 MB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 1);
}

QString QuickShareSender::pinFromAuthKey(const QByteArray &key) const
{
    int hash = 0, multiplier = 1;
    for (int i = 0; i < key.size(); ++i) {
        const int byte = (signed char)key.at(i);
        hash = (hash + byte * multiplier) % 9973;
        multiplier = (multiplier * 31) % 9973;
    }
    return QString::fromUtf8("%1").arg(qAbs(hash), 4, 10, QLatin1Char('0'));
}

bool QuickShareSender::sendIntroduction()
{
    QByteArray introduction;
    for (int fileIndex = 0; fileIndex < m_files.size(); ++fileIndex) {
        OutgoingFile &file = m_files[fileIndex];
        QByteArray metadata;
        ProtoWire::appendBytes(&metadata, 1, file.name.toUtf8());
        quint64 metadataType = 0; // UNKNOWN
        if (file.mimeType.startsWith("image/")) metadataType = 1;
        else if (file.mimeType.startsWith("video/")) metadataType = 2;
        else if (QFileInfo(file.path).suffix().compare("apk", Qt::CaseInsensitive) == 0)
            metadataType = 3;
        else if (file.mimeType.startsWith("audio/")) metadataType = 4;
        if (metadataType != 0)
            ProtoWire::appendVarint(&metadata, 2, metadataType);

        bool duplicate = false;
        do {
            quint64 id = 0;
            const QByteArray idBytes = randomBytes(8);
            for (int i = 0; i < idBytes.size(); ++i)
                id = (id << 8) | (unsigned char)idBytes.at(i);
            // FileMetadata.payload_id is signed. Use a negative value for the
            // first item so host/device end-to-end tests cover this case.
            file.payloadId = fileIndex == 0
                ? (id | Q_UINT64_C(0x8000000000000000)) : id;
            for (int i = 0; i < fileIndex && !duplicate; ++i)
                duplicate = m_files.at(i).payloadId == file.payloadId;
        } while (duplicate);

        ProtoWire::appendVarint(&metadata, 3, file.payloadId);
        ProtoWire::appendVarint(&metadata, 4, (quint64)file.size);
        ProtoWire::appendBytes(&metadata, 5, file.mimeType);
        ProtoWire::appendVarint(&metadata, 6, file.payloadId);
        ProtoWire::appendBytes(&introduction, 1, metadata);
    }
    ProtoWire::appendVarint(&introduction, 8, 1); // NEARBY_SHARE use case
    QByteArray v1;
    ProtoWire::appendVarint(&v1, 1, 1);
    ProtoWire::appendBytes(&v1, 2, introduction);
    QByteArray frame;
    ProtoWire::appendVarint(&frame, 1, 1);
    ProtoWire::appendBytes(&frame, 2, v1);
    status(QObject::tr("status_send_request_waiting")
               .arg(m_deviceName, m_pin));
    return sendSharingFrame(frame);
}

bool QuickShareSender::processIntroductionResponse(const QByteArray &frame)
{
    QByteArray v1, response;
    quint64 type = 0, decision = 0;
    if (!nestedBytes(frame, 2, &v1) || !nestedVarint(v1, 1, &type) || type != 2 ||
        !nestedBytes(v1, 3, &response) || !nestedVarint(response, 1, &decision))
        return fail(QObject::tr("risposta di consenso non valida"));
    if (decision != 1)
        return fail(QObject::tr("invio rifiutato o scaduto dal device"));
    return true;
}

bool QuickShareSender::checkPeerControl()
{
    for (;;) {
        struct pollfd pfd;
        pfd.fd = m_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int ready = poll(&pfd, 1, 0);
        if (ready < 0)
            return errno == EINTR ? true : fail(QObject::tr("lettura stato receiver fallita"));
        if (ready == 0) return true;
        if (!(pfd.revents & POLLIN))
            return fail(QObject::tr("connessione chiusa dal receiver"));
        QByteArray secure, offline, sharing, v1;
        if (!readFrame(&secure, 2000) || !decryptOffline(secure, &offline))
            return false;
        const int result = processReceivedOffline(offline, &sharing);
        if (result < 0) return false;
        if (result == 0) continue;
        quint64 type = 0;
        if (!nestedBytes(sharing, 2, &v1) || !nestedVarint(v1, 1, &type))
            return fail(QObject::tr("frame di controllo non valido"));
        if (type == 6)
            return fail(QObject::tr("trasferimento annullato dal receiver"));
    }
}

bool QuickShareSender::sendFilePayload(const QString &path, quint64 payloadId,
                                       qint64 size)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() != size)
        return fail(QObject::tr("impossibile aprire il file o dimensione modificata"));
    const QString name = safeName(QFileInfo(path).fileName());
    qint64 offset = 0;
    const qint64 chunkSize = 64 * 1024;
    while (!file.atEnd()) {
        if (!checkPeerControl()) return false;
        const QByteArray body = file.read(chunkSize);
        if (body.isEmpty() && !file.atEnd())
            return fail(QObject::tr("lettura del file fallita"));
        QByteArray header;
        ProtoWire::appendVarint(&header, 1, payloadId);
        ProtoWire::appendVarint(&header, 2, 2);
        ProtoWire::appendVarint(&header, 3, (quint64)size);
        ProtoWire::appendVarint(&header, 4, 0);
        ProtoWire::appendBytes(&header, 5, name.toUtf8());
        QByteArray chunk;
        ProtoWire::appendVarint(&chunk, 1, 0);
        ProtoWire::appendVarint(&chunk, 2, (quint64)offset);
        ProtoWire::appendBytes(&chunk, 3, body);
        QByteArray transfer;
        ProtoWire::appendVarint(&transfer, 1, 1);
        ProtoWire::appendBytes(&transfer, 2, header);
        ProtoWire::appendBytes(&transfer, 3, chunk);
        if (!sendEncryptedOffline(makeOfflineFrame(3, 4, transfer)))
            return fail(QObject::tr("connessione persa durante l'invio"));
        offset += body.size();
        m_sentBytes += body.size();
        const float progress = m_totalSize > 0
            ? (float)((double)m_sentBytes / (double)m_totalSize) : 1.0f;
        QMetaObject::invokeMethod(m_service, "setTransferProgress", Qt::QueuedConnection,
                                  Q_ARG(float, progress),
                                  Q_ARG(QString, QObject::tr("%1 di %2")
                                      .arg(humanSize(m_sentBytes), humanSize(m_totalSize))));
        if (!checkPeerControl()) return false;
    }
    QByteArray header;
    ProtoWire::appendVarint(&header, 1, payloadId);
    ProtoWire::appendVarint(&header, 2, 2);
    ProtoWire::appendVarint(&header, 3, (quint64)size);
    ProtoWire::appendVarint(&header, 4, 0);
    ProtoWire::appendBytes(&header, 5, name.toUtf8());
    QByteArray chunk;
    ProtoWire::appendVarint(&chunk, 1, 1);
    ProtoWire::appendVarint(&chunk, 2, (quint64)offset);
    QByteArray transfer;
    ProtoWire::appendVarint(&transfer, 1, 1);
    ProtoWire::appendBytes(&transfer, 2, header);
    ProtoWire::appendBytes(&transfer, 3, chunk);
    if (!sendEncryptedOffline(makeOfflineFrame(3, 4, transfer)))
        return fail(QObject::tr("connessione persa a fine invio"));
    return checkPeerControl();
}

bool QuickShareSender::sendFiles()
{
    m_sentBytes = 0;
    const qint64 estimateBaseMs = 120000;
    const qint64 estimatedBytesPerSecond = 16 * 1024;
    const qint64 maxEstimatedBytes =
        ((MAX_TRANSFER_DEADLINE_MS - estimateBaseMs) / 1000) *
        estimatedBytesPerSecond;
    const qint64 estimated = m_totalSize >= maxEstimatedBytes
        ? MAX_TRANSFER_DEADLINE_MS
        : estimateBaseMs + (m_totalSize / estimatedBytesPerSecond) * 1000;
    m_transferDeadlineMs = qBound(MIN_TRANSFER_DEADLINE_MS, estimated,
                                  MAX_TRANSFER_DEADLINE_MS);
    m_transferTimer.start();
    for (int i = 0; i < m_files.size(); ++i) {
        const OutgoingFile &file = m_files.at(i);
        if (!sendFilePayload(file.path, file.payloadId, file.size))
            return false;
    }
    if (!sendDisconnection())
        return fail(QObject::tr("chiusura del trasferimento fallita"));
    status(QObject::tr("status_waiting_receive_confirmation").arg(m_deviceName));
    if (!waitForSafeDisconnect())
        return fail(QObject::tr("conferma ricezione non valida"));
    status(QObject::tr("Invio completato a %1").arg(m_deviceName));
    for (int i = 0; i < m_files.size(); ++i) {
        const OutgoingFile &file = m_files.at(i);
        QMetaObject::invokeMethod(m_service, "appendEvent", Qt::QueuedConnection,
                                  Q_ARG(QString, file.name),
                                  Q_ARG(QString, QObject::tr("history_sent_to")
                                      .arg(m_deviceName, humanSize(file.size))),
                                  Q_ARG(QString, QString()));
    }
    QMetaObject::invokeMethod(m_service, "clearTransferProgress", Qt::QueuedConnection);
    return true;
}

bool QuickShareSender::sendDisconnection()
{
    QByteArray disconnection;
    if (m_safeDisconnect)
        ProtoWire::appendVarint(&disconnection, 1, 1); // request_safe_to_disconnect
    return sendEncryptedOffline(makeOfflineFrame(6, 7, disconnection));
}

bool QuickShareSender::waitForSafeDisconnect()
{
    if (!m_safeDisconnect)
        return true;

    // The peer may either acknowledge the request or simply close the TCP
    // stream (older Quick Share builds). EOF is therefore a successful drain,
    // while a malformed encrypted frame remains a real protocol failure.
    QTime timer;
    timer.start();
    while (timer.elapsed() < 1500) {
        QByteArray secure, offline, v1, disconnection;
        if (!readFrame(&secure, 1500 - timer.elapsed()))
            return true;
        if (!decryptOffline(secure, &offline) ||
            !nestedBytes(offline, 2, &v1))
            return false;
        quint64 type = 0;
        if (!nestedVarint(v1, 1, &type))
            return false;
        if (type != 6)
            continue;
        if (!nestedBytes(v1, 7, &disconnection))
            return true;
        quint64 ack = 0;
        if (nestedVarint(disconnection, 2, &ack) && ack == 1)
            return true;
    }
    return true;
}

bool QuickShareSender::run()
{
    m_files.clear();
    m_totalSize = 0;
    for (int i = 0; i < m_paths.size(); ++i) {
        const QFileInfo info(m_paths.at(i));
        if (!info.exists() || !info.isFile() || info.size() < 0)
            return fail(QObject::tr("file di origine non valido: %1")
                        .arg(info.fileName()));
        if (m_totalSize > Q_INT64_C(0x7fffffffffffffff) - info.size())
            return fail(QObject::tr("dimensione totale dei file non valida"));
        OutgoingFile file;
        file.path = info.absoluteFilePath();
        file.name = safeName(info.fileName());
        file.mimeType = fileMimeType(info.fileName());
        file.size = info.size();
        file.payloadId = 0;
        m_files.append(file);
        m_totalSize += file.size;
    }
    if (m_files.isEmpty())
        return fail(QObject::tr("nessun file da inviare"));
    status(QObject::tr("Connessione a %1").arg(m_deviceName));
    if (!connectPeer()) return false;
    status(QObject::tr("Negoziazione sicura con %1").arg(m_deviceName));
    if (!sendConnectionRequest())
        return fail(QObject::tr("invio ConnectionRequest fallito"));
    if (!sendClientInit())
        return false;

    QByteArray frame;
    if (!readFrame(&frame, 30000))
        return fail(QObject::tr("nessuna risposta UKEY2 dal receiver"));
    if (!processServerInit(frame)) return false;
    if (!sendClientFinish())
        return fail(QObject::tr("invio UKEY2 ClientFinish fallito"));
    if (!sendConnectionResponse())
        return fail(QObject::tr("invio ConnectionResponse fallito"));

    // Il receiver risponde ancora in chiaro prima che inizi il canale cifrato.
    // Saltare questo frame faceva interpretare la risposta come SecureMessage
    // e interrompeva ogni invio prima della richiesta di consenso.
    if (!readFrame(&frame, 30000))
        return fail(QObject::tr("nessuna conferma di connessione dal receiver"));
    if (!processConnectionResponse(frame)) return false;

    status(QObject::tr("Verifica del canale cifrato"));
    if (!sendPairedKeyEncryption())
        return fail(QObject::tr("invio verifica chiave fallito"));
    if (!receiveSharingFrame(&frame, 30000))
        return fail(QObject::tr("nessuna verifica chiave dal receiver"));
    if (!sendPairedKeyResult())
        return fail(QObject::tr("invio risultato chiave fallito"));
    if (!receiveSharingFrame(&frame, 30000))
        return fail(QObject::tr("nessun risultato chiave dal receiver"));
    if (!sendIntroduction())
        return fail(QObject::tr("invio metadati file fallito"));

    status(QObject::tr("status_wait_confirmation_pin")
               .arg(m_deviceName, m_pin));
    if (!receiveSharingFrame(&frame, 60000))
        return fail(QObject::tr("conferma di ricezione scaduta"));
    if (!processIntroductionResponse(frame)) return false;
    status(m_files.size() == 1
        ? QObject::tr("Invio di %1").arg(m_files.first().name)
        : QObject::tr("Invio di %1 file").arg(m_files.size()));
    return sendFiles();
}
