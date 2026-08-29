#include "QuickShareSession.hpp"

#include "ProtoWire.hpp"
#include "ShareService.hpp"

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QMetaObject>
#include <QtCore/QStringList>

#include <arpa/inet.h>
#include <errno.h>
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
const int CONSENT_TIMEOUT_MS = 60000;

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

} // namespace

QuickShareSession::QuickShareSession(int socketFd, const QString &peerAddress,
                                     ShareService *service)
    : m_fd(socketFd), m_peerAddress(peerAddress), m_service(service),
      m_state(PlainHandshake), m_ecKey(0), m_clientSequence(0),
      m_serverSequence(0), m_totalBytes(0), m_receivedBytes(0)
{
}

QuickShareSession::~QuickShareSession()
{
    if (m_state == AwaitConsent)
        m_service->finishConsent();
    if (m_state == Receiving)
        QMetaObject::invokeMethod(m_service, "clearTransferProgress",
                                  Qt::QueuedConnection);
    closeFiles();
    if (m_ecKey)
        EC_KEY_free(m_ecKey);
    if (m_fd >= 0)
        close(m_fd);
}

void QuickShareSession::status(const QString &message) const
{
    QMetaObject::invokeMethod(m_service, "setStatus", Qt::QueuedConnection,
                              Q_ARG(QString, message));
}

void QuickShareSession::event(const QString &title, const QString &detail) const
{
    QMetaObject::invokeMethod(m_service, "appendEvent", Qt::QueuedConnection,
                              Q_ARG(QString, title), Q_ARG(QString, detail));
}

bool QuickShareSession::fail(const QString &message)
{
    m_error = message;
    QMetaObject::invokeMethod(m_service, "clearTransferProgress", Qt::QueuedConnection);
    status(QString::fromUtf8("Errore ricezione: %1").arg(message));
    event(QString::fromUtf8("Trasferimento non riuscito"), message);
    return false;
}

bool QuickShareSession::receiveExact(char *data, int size, int timeoutMs)
{
    int done = 0;
    while (done < size) {
        struct pollfd pfd;
        pfd.fd = m_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int ready = poll(&pfd, 1, timeoutMs);
        if (ready <= 0)
            return false;
        int count = recv(m_fd, data + done, size - done, 0);
        if (count <= 0)
            return false;
        done += count;
    }
    return true;
}

bool QuickShareSession::sendAll(const char *data, int size)
{
    int done = 0;
    while (done < size) {
        int count = send(m_fd, data + done, size - done, 0);
        if (count <= 0)
            return false;
        done += count;
    }
    return true;
}

bool QuickShareSession::readFrame(QByteArray *frame, int timeoutMs)
{
    unsigned char lengthBytes[4];
    if (!receiveExact((char *)lengthBytes, 4, timeoutMs))
        return false;
    quint32 length = ((quint32)lengthBytes[0] << 24) |
                     ((quint32)lengthBytes[1] << 16) |
                     ((quint32)lengthBytes[2] << 8) | lengthBytes[3];
    if (length == 0 || length > (quint32)MAX_FRAME_SIZE)
        return fail(QString::fromUtf8("dimensione frame non valida: %1").arg(length));
    frame->resize((int)length);
    return receiveExact(frame->data(), (int)length, timeoutMs);
}

bool QuickShareSession::sendFrame(const QByteArray &frame)
{
    quint32 length = (quint32)frame.size();
    unsigned char prefix[4] = {
        (unsigned char)(length >> 24), (unsigned char)(length >> 16),
        (unsigned char)(length >> 8), (unsigned char)length
    };
    return sendAll((const char *)prefix, 4) &&
           sendAll(frame.constData(), frame.size());
}

QByteArray QuickShareSession::randomBytes(int size) const
{
    QByteArray result(size, 0);
    if (RAND_bytes((unsigned char *)result.data(), size) != 1) {
        for (int i = 0; i < size; ++i)
            result[i] = (char)(qrand() & 0xff);
    }
    return result;
}

QByteArray QuickShareSession::hkdf(const QByteArray &ikm, const QByteArray &salt,
                                   const QByteArray &info, int size) const
{
    const QByteArray prk = hmacSha256(salt, ikm);
    QByteArray output;
    QByteArray previous;
    unsigned char counter = 1;
    while (output.size() < size) {
        QByteArray input = previous + info;
        input.append((char)counter++);
        previous = hmacSha256(prk, input);
        output.append(previous);
    }
    return output.left(size);
}

QByteArray QuickShareSession::aesCrypt(const QByteArray &input,
                                       const QByteArray &key,
                                       const QByteArray &iv,
                                       bool encrypt) const
{
    if (key.size() != 32 || iv.size() != 16)
        return QByteArray();

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return QByteArray();
    int ok = encrypt
        ? EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), 0,
                            (const unsigned char *)key.constData(),
                            (const unsigned char *)iv.constData())
        : EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), 0,
                            (const unsigned char *)key.constData(),
                            (const unsigned char *)iv.constData());
    QByteArray output(input.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int first = 0, last = 0;
    if (ok) {
        ok = encrypt
            ? EVP_EncryptUpdate(ctx, (unsigned char *)output.data(), &first,
                                (const unsigned char *)input.constData(), input.size())
            : EVP_DecryptUpdate(ctx, (unsigned char *)output.data(), &first,
                                (const unsigned char *)input.constData(), input.size());
    }
    if (ok) {
        ok = encrypt
            ? EVP_EncryptFinal_ex(ctx, (unsigned char *)output.data() + first, &last)
            : EVP_DecryptFinal_ex(ctx, (unsigned char *)output.data() + first, &last);
    }
    EVP_CIPHER_CTX_free(ctx);
#else
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    int ok = encrypt
        ? EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), 0,
                            (const unsigned char *)key.constData(),
                            (const unsigned char *)iv.constData())
        : EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), 0,
                            (const unsigned char *)key.constData(),
                            (const unsigned char *)iv.constData());
    QByteArray output(input.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int first = 0, last = 0;
    if (ok) {
        ok = encrypt
            ? EVP_EncryptUpdate(&ctx, (unsigned char *)output.data(), &first,
                                (const unsigned char *)input.constData(), input.size())
            : EVP_DecryptUpdate(&ctx, (unsigned char *)output.data(), &first,
                                (const unsigned char *)input.constData(), input.size());
    }
    if (ok) {
        ok = encrypt
            ? EVP_EncryptFinal_ex(&ctx, (unsigned char *)output.data() + first, &last)
            : EVP_DecryptFinal_ex(&ctx, (unsigned char *)output.data() + first, &last);
    }
    EVP_CIPHER_CTX_cleanup(&ctx);
#endif
    if (!ok)
        return QByteArray();
    output.resize(first + last);
    return output;
}

QByteArray QuickShareSession::signedCoordinate(const void *rawBn) const
{
    const BIGNUM *bn = (const BIGNUM *)rawBn;
    QByteArray result(BN_num_bytes(bn), 0);
    BN_bn2bin(bn, (unsigned char *)result.data());
    if (!result.isEmpty() && ((unsigned char)result.at(0) & 0x80))
        result.prepend('\0');
    return result;
}

bool QuickShareSession::processConnectionRequest(const QByteArray &frame)
{
    QByteArray v1, request, endpoint;
    quint64 version = 0, type = 0;
    if (!nestedVarint(frame, 1, &version) || version != 1 ||
        !nestedBytes(frame, 2, &v1) ||
        !nestedVarint(v1, 1, &type) || type != 1 ||
        !nestedBytes(v1, 2, &request) ||
        !nestedBytes(request, 6, &endpoint))
        return fail(QString::fromUtf8("ConnectionRequest protobuf non valido"));

    if (endpoint.size() < 18)
        return fail(QString::fromUtf8("endpoint info troppo corto"));
    int nameLength = (unsigned char)endpoint.at(17);
    if (endpoint.size() < 18 + nameLength)
        return fail(QString::fromUtf8("nome endpoint troncato"));
    m_peerName = QString::fromUtf8(endpoint.constData() + 18, nameLength);
    status(QString::fromUtf8("Connessione da %1 (%2) — negoziazione sicura")
               .arg(m_peerName, m_peerAddress));
    return true;
}

bool QuickShareSession::processClientInit(const QByteArray &frame)
{
    quint64 type = 0, version = 0;
    QByteArray data, random, protocol;
    if (!nestedVarint(frame, 1, &type) || type != 2 ||
        !nestedBytes(frame, 2, &data) ||
        !nestedVarint(data, 1, &version) || version != 1 ||
        !nestedBytes(data, 2, &random) || random.size() != 32 ||
        !nestedBytes(data, 4, &protocol) ||
        protocol != "AES_256_CBC-HMAC_SHA256")
        return fail(QString::fromUtf8("UKEY2 ClientInit non supportato"));

    const QList<QByteArray> commitments = ProtoWire::repeatedBytes(data, 3);
    for (int i = 0; i < commitments.size(); ++i) {
        quint64 cipher = 0;
        QByteArray commitment;
        if (nestedVarint(commitments.at(i), 1, &cipher) && cipher == 100 &&
            nestedBytes(commitments.at(i), 2, &commitment)) {
            m_commitment = commitment;
            break;
        }
    }
    if (m_commitment.size() != SHA512_DIGEST_LENGTH)
        return fail(QString::fromUtf8("cipher P-256/SHA-512 assente"));

    m_ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!m_ecKey || EC_KEY_generate_key(m_ecKey) != 1)
        return fail(QString::fromUtf8("generazione chiave P-256 fallita"));

    const EC_GROUP *group = EC_KEY_get0_group(m_ecKey);
    const EC_POINT *point = EC_KEY_get0_public_key(m_ecKey);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (!x || !y || EC_POINT_get_affine_coordinates_GFp(group, point, x, y, 0) != 1) {
        BN_free(x); BN_free(y);
        return fail(QString::fromUtf8("lettura chiave pubblica fallita"));
    }

    QByteArray ecPublic;
    ProtoWire::appendBytes(&ecPublic, 1, signedCoordinate(x));
    ProtoWire::appendBytes(&ecPublic, 2, signedCoordinate(y));
    BN_free(x); BN_free(y);

    QByteArray genericPublic;
    ProtoWire::appendVarint(&genericPublic, 1, 1); // EC_P256
    ProtoWire::appendBytes(&genericPublic, 2, ecPublic);

    QByteArray serverInit;
    ProtoWire::appendVarint(&serverInit, 1, 1);
    ProtoWire::appendBytes(&serverInit, 2, randomBytes(32));
    ProtoWire::appendVarint(&serverInit, 3, 100);
    ProtoWire::appendBytes(&serverInit, 4, genericPublic);

    QByteArray message;
    ProtoWire::appendVarint(&message, 1, 3); // SERVER_INIT
    ProtoWire::appendBytes(&message, 2, serverInit);

    m_clientInitRaw = frame;
    m_serverInitRaw = message;
    if (!sendFrame(message))
        return fail(QString::fromUtf8("invio UKEY2 ServerInit fallito"));
    return true;
}

bool QuickShareSession::deriveKeys(const QByteArray &genericPublicKey)
{
    quint64 keyType = 0;
    QByteArray ecPublic, xBytes, yBytes;
    if (!nestedVarint(genericPublicKey, 1, &keyType) || keyType != 1 ||
        !nestedBytes(genericPublicKey, 2, &ecPublic) ||
        !nestedBytes(ecPublic, 1, &xBytes) || !nestedBytes(ecPublic, 2, &yBytes))
        return fail(QString::fromUtf8("chiave pubblica client non valida"));

    while (xBytes.size() > 32 && xBytes.at(0) == 0) xBytes.remove(0, 1);
    while (yBytes.size() > 32 && yBytes.at(0) == 0) yBytes.remove(0, 1);
    if (xBytes.size() > 32 || yBytes.size() > 32)
        return fail(QString::fromUtf8("coordinate P-256 fuori formato"));
    xBytes = QByteArray(32 - xBytes.size(), 0) + xBytes;
    yBytes = QByteArray(32 - yBytes.size(), 0) + yBytes;

    const EC_GROUP *group = EC_KEY_get0_group(m_ecKey);
    EC_POINT *peer = EC_POINT_new(group);
    BIGNUM *x = BN_bin2bn((const unsigned char *)xBytes.constData(), 32, 0);
    BIGNUM *y = BN_bin2bn((const unsigned char *)yBytes.constData(), 32, 0);
    bool valid = peer && x && y &&
        EC_POINT_set_affine_coordinates_GFp(group, peer, x, y, 0) == 1 &&
        EC_POINT_is_on_curve(group, peer, 0) == 1;
    BN_free(x); BN_free(y);
    if (!valid) {
        EC_POINT_free(peer);
        return fail(QString::fromUtf8("punto P-256 client non valido"));
    }

    unsigned char shared[32];
    int sharedSize = ECDH_compute_key(shared, sizeof(shared), peer, m_ecKey, 0);
    EC_POINT_free(peer);
    if (sharedSize <= 0)
        return fail(QString::fromUtf8("ECDH fallito"));
    QByteArray sharedSecret((const char *)shared, sharedSize);
    if (sharedSecret.size() < 32)
        sharedSecret.prepend(QByteArray(32 - sharedSecret.size(), 0));

    const QByteArray derived = sha256(sharedSecret);
    const QByteArray info = m_clientInitRaw + m_serverInitRaw;
    const QByteArray auth = hkdf(derived, "UKEY2 v1 auth", info, 32);
    const QByteArray next = hkdf(derived, "UKEY2 v1 next", info, 32);
    m_pin = pinFromAuthKey(auth);

    static const unsigned char d2dSaltBytes[32] = {
        0x82,0xaa,0x55,0xa0,0xd3,0x97,0xf8,0x83,0x46,0xca,0x1c,0xee,0x8d,0x39,0x09,0xb9,
        0x5f,0x13,0xfa,0x7d,0xeb,0x1d,0x4a,0xb3,0x83,0x76,0xb8,0x25,0x6d,0xa8,0x55,0x10
    };
    static const unsigned char secureSaltBytes[32] = {
        0xbf,0x9d,0x2a,0x53,0xc6,0x36,0x16,0xd7,0x5d,0xb0,0xa7,0x16,0x5b,0x91,0xc1,0xef,
        0x73,0xe5,0x37,0xf2,0x42,0x74,0x05,0xfa,0x23,0x61,0x0a,0x4b,0xe6,0x57,0x64,0x2e
    };
    const QByteArray d2dSalt((const char *)d2dSaltBytes, 32);
    const QByteArray secureSalt((const char *)secureSaltBytes, 32);
    const QByteArray client = hkdf(next, d2dSalt, "client", 32);
    const QByteArray server = hkdf(next, d2dSalt, "server", 32);
    m_decryptKey = hkdf(client, secureSalt, "ENC:2", 32);
    m_receiveHmacKey = hkdf(client, secureSalt, "SIG:1", 32);
    m_encryptKey = hkdf(server, secureSalt, "ENC:2", 32);
    m_sendHmacKey = hkdf(server, secureSalt, "SIG:1", 32);
    return true;
}

bool QuickShareSession::processClientFinish(const QByteArray &frame)
{
    quint64 type = 0;
    QByteArray data, genericPublic;
    if (!nestedVarint(frame, 1, &type) || type != 4 ||
        !nestedBytes(frame, 2, &data) ||
        !nestedBytes(data, 1, &genericPublic))
        return fail(QString::fromUtf8("UKEY2 ClientFinish non valido"));
    if (sha512(frame) != m_commitment)
        return fail(QString::fromUtf8("commitment UKEY2 non corrispondente"));
    return deriveKeys(genericPublic);
}

QByteArray QuickShareSession::makeOfflineFrame(int type, int fieldNumber,
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

bool QuickShareSession::processClientConnectionResponse(const QByteArray &frame)
{
    QByteArray v1;
    quint64 type = 0;
    if (!nestedBytes(frame, 2, &v1) || !nestedVarint(v1, 1, &type) || type != 2)
        return fail(QString::fromUtf8("ConnectionResponse client mancante"));

    QByteArray osInfo;
    ProtoWire::appendVarint(&osInfo, 1, 100); // Linux: valore non-Android neutro
    QByteArray response;
    ProtoWire::appendVarint(&response, 1, 0); // status legacy OK
    ProtoWire::appendVarint(&response, 3, 1); // ACCEPT
    ProtoWire::appendBytes(&response, 4, osInfo);
    if (!sendFrame(makeOfflineFrame(2, 3, response)))
        return fail(QString::fromUtf8("invio ConnectionResponse fallito"));
    m_state = AwaitPairedEncryption;
    return sendPairedKeyEncryption();
}

bool QuickShareSession::sendEncryptedOffline(const QByteArray &offline)
{
    QByteArray d2d;
    ProtoWire::appendBytes(&d2d, 1, offline);
    ProtoWire::appendVarint(&d2d, 2, (quint64)++m_serverSequence);

    const QByteArray iv = randomBytes(16);
    const QByteArray encrypted = aesCrypt(d2d, m_encryptKey, iv, true);
    if (encrypted.isEmpty())
        return fail(QString::fromUtf8("cifratura AES fallita"));

    QByteArray metadata;
    ProtoWire::appendVarint(&metadata, 1, 13); // DEVICE_TO_DEVICE_MESSAGE
    ProtoWire::appendVarint(&metadata, 2, 1);
    QByteArray header;
    ProtoWire::appendVarint(&header, 1, 1); // HMAC_SHA256
    ProtoWire::appendVarint(&header, 2, 2); // AES_256_CBC
    ProtoWire::appendBytes(&header, 5, iv);
    ProtoWire::appendBytes(&header, 6, metadata);
    QByteArray headerAndBody;
    ProtoWire::appendBytes(&headerAndBody, 1, header);
    ProtoWire::appendBytes(&headerAndBody, 2, encrypted);
    QByteArray secureMessage;
    ProtoWire::appendBytes(&secureMessage, 1, headerAndBody);
    ProtoWire::appendBytes(&secureMessage, 2,
                           hmacSha256(m_sendHmacKey, headerAndBody));
    return sendFrame(secureMessage);
}

bool QuickShareSession::decryptOffline(const QByteArray &secureMessage,
                                       QByteArray *offline)
{
    QByteArray headerAndBody, signature, header, body, iv;
    if (!nestedBytes(secureMessage, 1, &headerAndBody) ||
        !nestedBytes(secureMessage, 2, &signature) ||
        signature != hmacSha256(m_receiveHmacKey, headerAndBody) ||
        !nestedBytes(headerAndBody, 1, &header) ||
        !nestedBytes(headerAndBody, 2, &body) ||
        !nestedBytes(header, 5, &iv))
        return fail(QString::fromUtf8("SecureMessage/HMAC non valido"));

    const QByteArray plain = aesCrypt(body, m_decryptKey, iv, false);
    QByteArray message;
    quint64 sequence = 0;
    if (plain.isEmpty() || !nestedBytes(plain, 1, &message) ||
        !nestedVarint(plain, 2, &sequence) || sequence != (quint64)++m_clientSequence)
        return fail(QString::fromUtf8("sequenza SecureMessage non valida"));
    *offline = message;
    return true;
}

bool QuickShareSession::sendSharingFrame(const QByteArray &sharingFrame)
{
    QByteArray idBytes = randomBytes(8);
    quint64 id = 0;
    for (int i = 0; i < idBytes.size(); ++i)
        id = (id << 8) | (unsigned char)idBytes.at(i);

    QByteArray header;
    ProtoWire::appendVarint(&header, 1, id);
    ProtoWire::appendVarint(&header, 2, 1); // BYTES
    ProtoWire::appendVarint(&header, 3, (quint64)sharingFrame.size());
    ProtoWire::appendVarint(&header, 4, 0);

    QByteArray chunk;
    ProtoWire::appendVarint(&chunk, 1, 0);
    ProtoWire::appendVarint(&chunk, 2, 0);
    ProtoWire::appendBytes(&chunk, 3, sharingFrame);
    QByteArray transfer;
    ProtoWire::appendVarint(&transfer, 1, 1);
    ProtoWire::appendBytes(&transfer, 2, header);
    ProtoWire::appendBytes(&transfer, 3, chunk);
    if (!sendEncryptedOffline(makeOfflineFrame(3, 4, transfer)))
        return false;

    chunk.clear();
    ProtoWire::appendVarint(&chunk, 1, 1);
    ProtoWire::appendVarint(&chunk, 2, (quint64)sharingFrame.size());
    transfer.clear();
    ProtoWire::appendVarint(&transfer, 1, 1);
    ProtoWire::appendBytes(&transfer, 2, header);
    ProtoWire::appendBytes(&transfer, 3, chunk);
    return sendEncryptedOffline(makeOfflineFrame(3, 4, transfer));
}

bool QuickShareSession::sendPairedKeyEncryption()
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

bool QuickShareSession::sendPairedKeyResult()
{
    QByteArray result;
    ProtoWire::appendVarint(&result, 1, 3); // UNABLE
    QByteArray v1;
    ProtoWire::appendVarint(&v1, 1, 4);
    ProtoWire::appendBytes(&v1, 5, result);
    QByteArray frame;
    ProtoWire::appendVarint(&frame, 1, 1);
    ProtoWire::appendBytes(&frame, 2, v1);
    return sendSharingFrame(frame);
}

bool QuickShareSession::sendIntroductionResponse(bool accepted)
{
    QByteArray response;
    ProtoWire::appendVarint(&response, 1, accepted ? 1 : 2);
    QByteArray v1;
    ProtoWire::appendVarint(&v1, 1, 2);
    ProtoWire::appendBytes(&v1, 3, response);
    QByteArray frame;
    ProtoWire::appendVarint(&frame, 1, 1);
    ProtoWire::appendBytes(&frame, 2, v1);
    return sendSharingFrame(frame);
}

bool QuickShareSession::sendKeepAliveAck()
{
    QByteArray keepAlive;
    ProtoWire::appendVarint(&keepAlive, 1, 1);
    return sendEncryptedOffline(makeOfflineFrame(5, 6, keepAlive));
}

QString QuickShareSession::safeDestination(const QString &name) const
{
    QString directory = QString::fromLocal8Bit(qgetenv("BBXSHARE_DOWNLOAD_DIR"));
    if (directory.isEmpty())
        directory = QString::fromUtf8("/accounts/1000/shared/downloads/BBXShare");
    QDir().mkpath(directory);
    QString safe = QFileInfo(name).fileName();
    if (safe.isEmpty() || safe == "." || safe == "..")
        safe = QString::fromUtf8("ricevuto.bin");
    QString path = directory + "/" + safe;
    if (!QFile::exists(path))
        return path;
    const QFileInfo info(path);
    const QString base = info.completeBaseName();
    const QString suffix = info.suffix();
    for (int i = 1; ; ++i) {
        QString candidate = directory + "/" + base +
                            QString::fromUtf8(" (%1)").arg(i);
        if (!suffix.isEmpty())
            candidate += "." + suffix;
        if (!QFile::exists(candidate))
            return candidate;
    }
}

QString QuickShareSession::humanSize(qint64 bytes) const
{
    if (bytes < 1024)
        return QString::fromUtf8("%1 B").arg(bytes);
    if (bytes < 1024 * 1024)
        return QString::fromUtf8("%1 KB").arg(bytes / 1024.0, 0, 'f', 1);
    return QString::fromUtf8("%1 MB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 1);
}

QString QuickShareSession::pinFromAuthKey(const QByteArray &key) const
{
    int hash = 0, multiplier = 1;
    for (int i = 0; i < key.size(); ++i) {
        int byte = (signed char)key.at(i);
        hash = (hash + byte * multiplier) % 9973;
        multiplier = (multiplier * 31) % 9973;
    }
    return QString::fromUtf8("%1").arg(qAbs(hash), 4, 10, QLatin1Char('0'));
}

bool QuickShareSession::processIntroduction(const QByteArray &introduction)
{
    const QList<QByteArray> fileMetadata = ProtoWire::repeatedBytes(introduction, 1);
    const QList<QByteArray> textMetadata = ProtoWire::repeatedBytes(introduction, 2);
    QStringList names;
    qint64 total = 0;

    for (int i = 0; i < fileMetadata.size(); ++i) {
        QByteArray nameBytes, mimeBytes;
        quint64 id = 0, size = 0;
        if (!nestedBytes(fileMetadata.at(i), 1, &nameBytes) ||
            !nestedVarint(fileMetadata.at(i), 3, &id) ||
            !nestedVarint(fileMetadata.at(i), 4, &size))
            return fail(QString::fromUtf8("metadata file incompleti"));
        nestedBytes(fileMetadata.at(i), 5, &mimeBytes);
        IncomingFile *file = new IncomingFile;
        file->name = QString::fromUtf8(nameBytes);
        file->mimeType = QString::fromUtf8(mimeBytes);
        file->path = safeDestination(file->name);
        file->payloadId = (qint64)id;
        file->size = (qint64)size;
        file->received = 0;
        file->bytePayload = false;
        file->file = 0;
        m_files.insert(file->payloadId, file);
        names.append(file->name);
        total += file->size;
    }

    for (int i = 0; i < textMetadata.size(); ++i) {
        quint64 id = 0, size = 0;
        if (!nestedVarint(textMetadata.at(i), 4, &id) ||
            !nestedVarint(textMetadata.at(i), 5, &size))
            return fail(QString::fromUtf8("metadata testo incompleti"));
        IncomingFile *file = new IncomingFile;
        file->name = QString::fromUtf8("Testo ricevuto %1.txt")
            .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd HH.mm.ss"));
        file->mimeType = QString::fromUtf8("text/plain");
        file->path = safeDestination(file->name);
        file->payloadId = (qint64)id;
        file->size = (qint64)size;
        file->received = 0;
        file->bytePayload = true;
        file->file = 0;
        m_files.insert(file->payloadId, file);
        names.append(file->name);
        total += file->size;
    }

    if (m_files.isEmpty())
        return fail(QString::fromUtf8("tipo di allegato non supportato"));

    m_totalBytes = total;
    m_receivedBytes = 0;

    const QString title = QString::fromUtf8("%1 vuole condividere %2 elemento/i")
        .arg(m_peerName).arg(m_files.size());
    const QString detail = QString::fromUtf8("%1\nTotale: %2 · PIN %3")
        .arg(names.join(QString::fromUtf8(", "))).arg(humanSize(total)).arg(m_pin);
    if (!m_service->beginConsent(title, detail))
        return fail(QString::fromUtf8("un altro trasferimento è già in attesa"));
    m_state = AwaitConsent;
    m_consentTimer.start();
    status(QString::fromUtf8("Conferma il trasferimento da %1 — PIN %2")
               .arg(m_peerName, m_pin));
    return true;
}

bool QuickShareSession::processSharingFrame(const QByteArray &frame)
{
    QByteArray v1;
    quint64 type = 0;
    if (!nestedBytes(frame, 2, &v1) || !nestedVarint(v1, 1, &type))
        return fail(QString::fromUtf8("frame Share non valido"));
    if (type == 6)
        return fail(QString::fromUtf8("trasferimento annullato dal telefono"));

    if (m_state == AwaitPairedEncryption && type == 3) {
        QByteArray paired;
        if (!nestedBytes(v1, 4, &paired))
            return fail(QString::fromUtf8("PairedKeyEncryption mancante"));
        if (!sendPairedKeyResult())
            return false;
        m_state = AwaitPairedResult;
        return true;
    }
    if (m_state == AwaitPairedResult && type == 4) {
        QByteArray result;
        if (!nestedBytes(v1, 5, &result))
            return fail(QString::fromUtf8("PairedKeyResult mancante"));
        m_state = AwaitIntroduction;
        return true;
    }
    if (m_state == AwaitIntroduction && type == 1) {
        QByteArray introduction;
        if (!nestedBytes(v1, 2, &introduction))
            return fail(QString::fromUtf8("Introduction mancante"));
        return processIntroduction(introduction);
    }
    return true;
}

bool QuickShareSession::processIncomingFile(qint64 id, qint64 offset, int flags,
                                            const QByteArray &body)
{
    IncomingFile *file = m_files.value(id, 0);
    if (!file)
        return fail(QString::fromUtf8("payload file sconosciuto: %1").arg(id));
    if (offset != file->received || file->received + body.size() > file->size)
        return fail(QString::fromUtf8("offset/dimensione non valida per %1").arg(file->name));
    if (!file->file)
        return fail(QString::fromUtf8("file di destinazione non aperto: %1").arg(file->name));
    if (!body.isEmpty() && file->file->write(body) != body.size())
        return fail(QString::fromUtf8("scrittura fallita: %1").arg(file->path));
    file->received += body.size();
    m_receivedBytes += body.size();
    status(QString::fromUtf8("Ricezione %1 — %2 / %3")
               .arg(file->name, humanSize(file->received), humanSize(file->size)));
    const float progress = m_totalBytes > 0
        ? (float)((double)m_receivedBytes / (double)m_totalBytes) : 0.0f;
    QMetaObject::invokeMethod(m_service, "setTransferProgress", Qt::QueuedConnection,
                              Q_ARG(float, progress),
                              Q_ARG(QString, QString::fromUtf8("%1 di %2")
                                  .arg(humanSize(m_receivedBytes), humanSize(m_totalBytes))));

    if (flags & 1) {
        file->file->flush();
        file->file->close();
        if (file->received != file->size)
            return fail(QString::fromUtf8("file incompleto: %1").arg(file->name));
        event(QString::fromUtf8("File ricevuto"), file->path);
        delete file->file;
        file->file = 0;
        m_files.remove(id);
        delete file;
        if (m_files.isEmpty()) {
            QMetaObject::invokeMethod(m_service, "clearTransferProgress",
                                      Qt::QueuedConnection);
            status(QString::fromUtf8("Trasferimento completato"));
            event(QString::fromUtf8("Trasferimento completato"),
                  QString::fromUtf8("Ricezione da %1 terminata").arg(m_peerName));
        }
    }
    return true;
}

bool QuickShareSession::processPayloadTransfer(const QByteArray &payloadTransfer)
{
    QByteArray header, chunk, body;
    quint64 packetType = 0, rawId = 0, payloadType = 0, offset = 0, flags = 0;
    if (!nestedVarint(payloadTransfer, 1, &packetType) || packetType != 1 ||
        !nestedBytes(payloadTransfer, 2, &header) ||
        !nestedBytes(payloadTransfer, 3, &chunk) ||
        !nestedVarint(header, 1, &rawId) ||
        !nestedVarint(header, 2, &payloadType) ||
        !nestedVarint(chunk, 1, &flags) || !nestedVarint(chunk, 2, &offset))
        return fail(QString::fromUtf8("PayloadTransfer non valido"));
    nestedBytes(chunk, 3, &body);
    const qint64 id = (qint64)rawId;

    if (payloadType == 2)
        return processIncomingFile(id, (qint64)offset, (int)flags, body);
    if (payloadType != 1)
        return fail(QString::fromUtf8("tipo payload non supportato: %1").arg(payloadType));

    QByteArray &buffer = m_byteBuffers[id];
    if ((qint64)offset != buffer.size()) {
        m_byteBuffers.remove(id);
        return fail(QString::fromUtf8("offset payload bytes non valido"));
    }
    buffer.append(body);
    if (!(flags & 1))
        return true;
    const QByteArray complete = buffer;
    m_byteBuffers.remove(id);

    if (m_state == Receiving && m_files.contains(id) && m_files.value(id)->bytePayload)
        return processIncomingFile(id, 0, 1, complete);
    return processSharingFrame(complete);
}

bool QuickShareSession::processEncryptedFrame(const QByteArray &secureMessage)
{
    QByteArray offline, v1;
    quint64 type = 0;
    if (!decryptOffline(secureMessage, &offline) ||
        !nestedBytes(offline, 2, &v1) || !nestedVarint(v1, 1, &type))
        return false;
    if (type == 3) {
        QByteArray transfer;
        if (!nestedBytes(v1, 4, &transfer))
            return fail(QString::fromUtf8("payload transfer mancante"));
        return processPayloadTransfer(transfer);
    }
    if (type == 5)
        return sendKeepAliveAck();
    if (type == 6)
        return fail(QString::fromUtf8("connessione chiusa dal telefono"));
    return true;
}

void QuickShareSession::closeFiles()
{
    QHash<qint64, IncomingFile *>::iterator it = m_files.begin();
    while (it != m_files.end()) {
        IncomingFile *file = it.value();
        if (file->file) {
            file->file->close();
            delete file->file;
            QFile::remove(file->path);
        }
        delete file;
        ++it;
    }
    m_files.clear();
}

bool QuickShareSession::run()
{
    QByteArray frame;
    if (!readFrame(&frame, 30000) || !processConnectionRequest(frame)) return false;
    if (!readFrame(&frame, 30000) || !processClientInit(frame)) return false;
    if (!readFrame(&frame, 30000) || !processClientFinish(frame)) return false;
    if (!readFrame(&frame, 30000) || !processClientConnectionResponse(frame)) return false;

    for (;;) {
        if (m_state == AwaitConsent) {
            int decision = m_service->consentDecision();
            if (decision == 1) {
                QHash<qint64, IncomingFile *>::iterator it = m_files.begin();
                for (; it != m_files.end(); ++it) {
                    it.value()->file = new QFile(it.value()->path);
                    if (!it.value()->file->open(QIODevice::WriteOnly)) {
                        m_service->finishConsent();
                        return fail(QString::fromUtf8("impossibile creare %1")
                                    .arg(it.value()->path));
                    }
                }
                if (!sendIntroductionResponse(true)) {
                    m_service->finishConsent();
                    return false;
                }
                m_service->finishConsent();
                m_state = Receiving;
                QMetaObject::invokeMethod(m_service, "setTransferProgress",
                                          Qt::QueuedConnection, Q_ARG(float, 0.0f),
                                          Q_ARG(QString, QString::fromUtf8("In attesa dei dati...")));
                event(QString::fromUtf8("Trasferimento accettato"),
                      QString::fromUtf8("Da %1 · PIN %2").arg(m_peerName, m_pin));
            } else if (decision < 0 || m_consentTimer.elapsed() > CONSENT_TIMEOUT_MS) {
                sendIntroductionResponse(false);
                m_service->finishConsent();
                event(QString::fromUtf8("Trasferimento rifiutato"), m_peerName);
                return true;
            }
        }

        struct pollfd pfd;
        pfd.fd = m_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int ready = poll(&pfd, 1, 250);
        if (ready < 0) {
            if (errno == EINTR) continue;
            return fail(QString::fromUtf8("poll TCP: %1").arg(strerror(errno)));
        }
        if (ready == 0)
            continue;
        if (!(pfd.revents & POLLIN))
            return m_files.isEmpty() && m_state == Receiving;
        if (!readFrame(&frame, 30000))
            return m_files.isEmpty() && m_state == Receiving;
        if (!processEncryptedFrame(frame))
            return false;
        if (m_state == Receiving && m_files.isEmpty())
            return true;
    }
}
