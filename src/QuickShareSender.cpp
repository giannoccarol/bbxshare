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
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace {

const int MAX_FRAME_SIZE = 5 * 1024 * 1024;

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

QuickShareSender::QuickShareSender(const QString &path, const QString &address,
                                   int port, const QString &deviceName,
                                   ShareService *service)
    : m_fd(-1), m_path(path), m_address(address), m_port(port),
      m_deviceName(deviceName), m_service(service), m_sendSequence(0),
      m_receiveSequence(0), m_fileSize(0), m_sentBytes(0), m_payloadId(0), m_ecKey(0)
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

void QuickShareSender::event(const QString &title, const QString &detail) const
{
    QMetaObject::invokeMethod(m_service, "appendEvent", Qt::QueuedConnection,
                              Q_ARG(QString, title), Q_ARG(QString, detail));
}

bool QuickShareSender::fail(const QString &message)
{
    status(QString::fromUtf8("Errore invio: %1").arg(message));
    event(QString::fromUtf8("Invio non riuscito"), message);
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
        return fail(QString::fromUtf8("socket TCP: %1").arg(strerror(errno)));

    const int flags = fcntl(m_fd, F_GETFL, 0);
    fcntl(m_fd, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons((quint16)m_port);
    if (inet_pton(AF_INET, m_address.toUtf8().constData(), &peer.sin_addr) != 1)
        return fail(QString::fromUtf8("indirizzo device non valido"));
    int rc = connect(m_fd, (struct sockaddr *)&peer, sizeof(peer));
    if (rc != 0 && errno != EINPROGRESS)
        return fail(QString::fromUtf8("connessione a %1:%2: %3")
                    .arg(m_address).arg(m_port).arg(strerror(errno)));
    if (rc != 0) {
        struct pollfd pfd;
        pfd.fd = m_fd; pfd.events = POLLOUT; pfd.revents = 0;
        if (poll(&pfd, 1, 10000) <= 0)
            return fail(QString::fromUtf8("timeout connessione al device"));
        int error = 0; socklen_t len = sizeof(error);
        getsockopt(m_fd, SOL_SOCKET, SO_ERROR, &error, &len);
        if (error != 0)
            return fail(QString::fromUtf8("connessione rifiutata: %1").arg(strerror(error)));
    }
    fcntl(m_fd, F_SETFL, flags);
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
        struct pollfd pfd;
        pfd.fd = m_fd; pfd.events = POLLOUT; pfd.revents = 0;
        if (poll(&pfd, 1, 10000) <= 0)
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
        return fail(QString::fromUtf8("frame ricevuto non valido"));
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
    const QByteArray name = QByteArray("BBX Share");
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
    ProtoWire::appendBytes(&fullRequest, 2, QByteArray("BBX Share"));
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
        return fail(QString::fromUtf8("generazione chiave P-256 fallita"));

    // ClientFinish viene costruito prima e impegnato con SHA-512 nel ClientInit.
    const EC_GROUP *group = EC_KEY_get0_group((EC_KEY *)m_ecKey);
    const EC_POINT *point = EC_KEY_get0_public_key((EC_KEY *)m_ecKey);
    BIGNUM *x = BN_new(); BIGNUM *y = BN_new();
    if (!x || !y || EC_POINT_get_affine_coordinates_GFp(group, point, x, y, 0) != 1)
        return fail(QString::fromUtf8("lettura chiave P-256 fallita"));
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
        return fail(QString::fromUtf8("UKEY2 ServerInit non valido"));

    while (xBytes.size() > 32 && xBytes.at(0) == 0) xBytes.remove(0, 1);
    while (yBytes.size() > 32 && yBytes.at(0) == 0) yBytes.remove(0, 1);
    if (xBytes.size() > 32 || yBytes.size() > 32)
        return fail(QString::fromUtf8("coordinate server non valide"));
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
    if (!valid) { EC_POINT_free(peer); return fail(QString::fromUtf8("punto server non valido")); }
    unsigned char shared[32];
    int sharedSize = ECDH_compute_key(shared, sizeof(shared), peer, (EC_KEY *)m_ecKey, 0);
    EC_POINT_free(peer);
    if (sharedSize <= 0)
        return fail(QString::fromUtf8("ECDH server fallito"));
    QByteArray secret((const char *)shared, sharedSize);
    if (secret.size() < 32) secret.prepend(QByteArray(32 - secret.size(), 0));
    const QByteArray derived = sha256(secret);
    const QByteArray info = m_clientInitRaw + frame;
    const QByteArray next = hkdf(derived, "UKEY2 v1 next", info, 32);
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
        return fail(QString::fromUtf8("ConnectionResponse del receiver non valida"));

    const bool hasDecision = nestedVarint(response, 3, &decision);
    const bool hasLegacyStatus = nestedVarint(response, 1, &legacyStatus);
    if ((!hasDecision && !hasLegacyStatus) ||
        (hasDecision ? decision != 1 : legacyStatus != 0))
        return fail(QString::fromUtf8("connessione rifiutata dal receiver"));
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
        return fail(QString::fromUtf8("cifratura AES fallita"));
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
        signature != hmacSha256(m_receiveHmacKey, headerAndBody) ||
        !nestedBytes(headerAndBody, 1, &header) || !nestedBytes(headerAndBody, 2, &body) ||
        !nestedBytes(header, 5, &iv))
        return fail(QString::fromUtf8("SecureMessage server non valido"));
    const QByteArray plain = aesCrypt(body, m_decryptKey, iv, false);
    quint64 seq = 0;
    if (plain.isEmpty() || !nestedBytes(plain, 1, offline) ||
        !nestedVarint(plain, 2, &seq) || seq != (quint64)++m_receiveSequence)
        return fail(QString::fromUtf8("sequenza SecureMessage server non valida"));
    return true;
}

bool QuickShareSender::sendSharingFrame(const QByteArray &sharing)
{
    QByteArray idBytes = randomBytes(8);
    quint64 id = 0;
    for (int i = 0; i < idBytes.size(); ++i) id = (id << 8) | (unsigned char)idBytes.at(i);
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
    QHash<quint64, QByteArray> buffers;
    for (;;) {
        QByteArray secure, offline, v1, transfer, header, chunk, body;
        if (!readFrame(&secure, timeoutMs) || !decryptOffline(secure, &offline) ||
            !nestedBytes(offline, 2, &v1))
            return false;
        quint64 type = 0;
        if (!nestedVarint(v1, 1, &type))
            return fail(QString::fromUtf8("frame server senza tipo"));
        if (type == 5) {
            QByteArray keepAlive;
            ProtoWire::appendVarint(&keepAlive, 1, 1);
            if (!sendEncryptedOffline(makeOfflineFrame(5, 6, keepAlive))) return false;
            continue;
        }
        if (type == 6)
            return fail(QString::fromUtf8("device Android ha annullato"));
        if (type != 3 || !nestedBytes(v1, 4, &transfer) ||
            !nestedBytes(transfer, 2, &header) || !nestedBytes(transfer, 3, &chunk))
            return fail(QString::fromUtf8("risposta Share non valida"));
        quint64 packetType = 0, id = 0, flags = 0, offset = 0;
        if (!nestedVarint(transfer, 1, &packetType) || packetType != 1 ||
            !nestedVarint(header, 1, &id) || !nestedVarint(chunk, 1, &flags) ||
            !nestedVarint(chunk, 2, &offset))
            return fail(QString::fromUtf8("payload risposta non valido"));
        nestedBytes(chunk, 3, &body);
        QByteArray &buffer = buffers[id];
        if ((quint64)buffer.size() != offset)
            return fail(QString::fromUtf8("offset risposta non valido"));
        buffer.append(body);
        if (flags & 1) {
            *sharing = buffer;
            buffers.remove(id);
            return true;
        }
    }
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

bool QuickShareSender::sendIntroduction()
{
    QFileInfo file(m_path);
    m_fileSize = file.size();
    QByteArray metadata;
    ProtoWire::appendBytes(&metadata, 1, safeName(file.fileName()).toUtf8());
    quint64 id = 0;
    const QByteArray idBytes = randomBytes(8);
    for (int i = 0; i < idBytes.size(); ++i) id = (id << 8) | (unsigned char)idBytes.at(i);
    id &= 0x7fffffffffffffffULL;
    m_payloadId = id;
    ProtoWire::appendVarint(&metadata, 3, id);
    ProtoWire::appendVarint(&metadata, 4, (quint64)m_fileSize);
    ProtoWire::appendBytes(&metadata, 5, fileMimeType(file.fileName()));
    QByteArray introduction;
    ProtoWire::appendBytes(&introduction, 1, metadata);
    QByteArray v1;
    ProtoWire::appendVarint(&v1, 1, 1);
    ProtoWire::appendBytes(&v1, 2, introduction);
    QByteArray frame;
    ProtoWire::appendVarint(&frame, 1, 1);
    ProtoWire::appendBytes(&frame, 2, v1);
    status(QString::fromUtf8("Richiesta di invio a %1 — attendo conferma").arg(m_deviceName));
    return sendSharingFrame(frame);
}

bool QuickShareSender::processIntroductionResponse(const QByteArray &frame)
{
    QByteArray v1, response;
    quint64 type = 0, decision = 0;
    if (!nestedBytes(frame, 2, &v1) || !nestedVarint(v1, 1, &type) || type != 2 ||
        !nestedBytes(v1, 3, &response) || !nestedVarint(response, 1, &decision))
        return fail(QString::fromUtf8("risposta di consenso non valida"));
    if (decision != 1)
        return fail(QString::fromUtf8("invio rifiutato o scaduto dal device"));
    return true;
}

bool QuickShareSender::sendFile()
{
    QFile file(m_path);
    if (!file.open(QIODevice::ReadOnly))
        return fail(QString::fromUtf8("impossibile aprire il file"));
    const qint64 chunkSize = 256 * 1024;
    while (!file.atEnd()) {
        const QByteArray body = file.read(chunkSize);
        if (body.isEmpty() && !file.atEnd())
            return fail(QString::fromUtf8("lettura del file fallita"));
        QByteArray header;
        ProtoWire::appendVarint(&header, 1, m_payloadId);
        ProtoWire::appendVarint(&header, 2, 2);
        ProtoWire::appendVarint(&header, 3, (quint64)m_fileSize);
        ProtoWire::appendVarint(&header, 4, 0);
        ProtoWire::appendBytes(&header, 5,
                               safeName(QFileInfo(m_path).fileName()).toUtf8());
        QByteArray chunk;
        ProtoWire::appendVarint(&chunk, 1, 0);
        ProtoWire::appendVarint(&chunk, 2, (quint64)m_sentBytes);
        ProtoWire::appendBytes(&chunk, 3, body);
        QByteArray transfer;
        ProtoWire::appendVarint(&transfer, 1, 1);
        ProtoWire::appendBytes(&transfer, 2, header);
        ProtoWire::appendBytes(&transfer, 3, chunk);
        if (!sendEncryptedOffline(makeOfflineFrame(3, 4, transfer)))
            return false;
        m_sentBytes += body.size();
        const float progress = m_fileSize > 0
            ? (float)((double)m_sentBytes / (double)m_fileSize) : 1.0f;
        QMetaObject::invokeMethod(m_service, "setTransferProgress", Qt::QueuedConnection,
                                  Q_ARG(float, progress),
                                  Q_ARG(QString, QString::fromUtf8("%1 di %2")
                                      .arg(humanSize(m_sentBytes), humanSize(m_fileSize))));
    }
    QByteArray header;
    ProtoWire::appendVarint(&header, 1, m_payloadId);
    ProtoWire::appendVarint(&header, 2, 2);
    ProtoWire::appendVarint(&header, 3, (quint64)m_fileSize);
    ProtoWire::appendVarint(&header, 4, 0);
    ProtoWire::appendBytes(&header, 5,
                           safeName(QFileInfo(m_path).fileName()).toUtf8());
    QByteArray chunk;
    ProtoWire::appendVarint(&chunk, 1, 1);
    ProtoWire::appendVarint(&chunk, 2, (quint64)m_sentBytes);
    QByteArray transfer;
    ProtoWire::appendVarint(&transfer, 1, 1);
    ProtoWire::appendBytes(&transfer, 2, header);
    ProtoWire::appendBytes(&transfer, 3, chunk);
    if (!sendEncryptedOffline(makeOfflineFrame(3, 4, transfer)))
        return false;
    if (!sendDisconnection())
        return fail(QString::fromUtf8("chiusura del trasferimento fallita"));
    status(QString::fromUtf8("Invio completato a %1").arg(m_deviceName));
    event(QString::fromUtf8("File inviato"), QFileInfo(m_path).fileName());
    QMetaObject::invokeMethod(m_service, "clearTransferProgress", Qt::QueuedConnection);
    return true;
}

bool QuickShareSender::sendDisconnection()
{
    return sendEncryptedOffline(makeOfflineFrame(6, 7, QByteArray()));
}

bool QuickShareSender::run()
{
    QFileInfo info(m_path);
    if (!info.exists() || !info.isFile())
        return fail(QString::fromUtf8("file di origine non valido"));
    status(QString::fromUtf8("Connessione a %1").arg(m_deviceName));
    if (!connectPeer()) return false;
    status(QString::fromUtf8("Negoziazione sicura con %1").arg(m_deviceName));
    if (!sendConnectionRequest())
        return fail(QString::fromUtf8("invio ConnectionRequest fallito"));
    if (!sendClientInit())
        return false;

    QByteArray frame;
    if (!readFrame(&frame, 30000))
        return fail(QString::fromUtf8("nessuna risposta UKEY2 dal receiver"));
    if (!processServerInit(frame)) return false;
    if (!sendClientFinish())
        return fail(QString::fromUtf8("invio UKEY2 ClientFinish fallito"));
    if (!sendConnectionResponse())
        return fail(QString::fromUtf8("invio ConnectionResponse fallito"));

    // Il receiver risponde ancora in chiaro prima che inizi il canale cifrato.
    // Saltare questo frame faceva interpretare la risposta come SecureMessage
    // e interrompeva ogni invio prima della richiesta di consenso.
    if (!readFrame(&frame, 30000))
        return fail(QString::fromUtf8("nessuna conferma di connessione dal receiver"));
    if (!processConnectionResponse(frame)) return false;

    status(QString::fromUtf8("Verifica del canale cifrato"));
    if (!sendPairedKeyEncryption())
        return fail(QString::fromUtf8("invio verifica chiave fallito"));
    if (!receiveSharingFrame(&frame, 30000))
        return fail(QString::fromUtf8("nessuna verifica chiave dal receiver"));
    if (!sendPairedKeyResult())
        return fail(QString::fromUtf8("invio risultato chiave fallito"));
    if (!receiveSharingFrame(&frame, 30000))
        return fail(QString::fromUtf8("nessun risultato chiave dal receiver"));
    if (!sendIntroduction())
        return fail(QString::fromUtf8("invio metadati file fallito"));

    status(QString::fromUtf8("Attendi la conferma su %1").arg(m_deviceName));
    if (!receiveSharingFrame(&frame, 60000))
        return fail(QString::fromUtf8("conferma di ricezione scaduta"));
    if (!processIntroductionResponse(frame)) return false;
    status(QString::fromUtf8("Invio di %1").arg(info.fileName()));
    return sendFile();
}
