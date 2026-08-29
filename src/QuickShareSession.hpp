#ifndef QUICKSHARESESSION_HPP_
#define QUICKSHARESESSION_HPP_

#include <QtCore/QByteArray>
#include <QtCore/QHash>
#include <QtCore/QString>
#include <QtCore/QTime>

typedef struct ec_key_st EC_KEY;

class QFile;
class ShareService;

class QuickShareSession {
public:
    QuickShareSession(int socketFd, const QString &peerAddress, ShareService *service);
    ~QuickShareSession();

    bool run();

private:
    enum State {
        PlainHandshake,
        AwaitPairedEncryption,
        AwaitPairedResult,
        AwaitIntroduction,
        AwaitConsent,
        Receiving
    };

    struct IncomingFile {
        QString name;
        QString mimeType;
        QString path;
        qint64 payloadId;
        qint64 size;
        qint64 received;
        bool bytePayload;
        QFile *file;
    };

    bool readFrame(QByteArray *frame, int timeoutMs);
    bool sendFrame(const QByteArray &frame);
    bool receiveExact(char *data, int size, int timeoutMs);
    bool sendAll(const char *data, int size);

    bool processConnectionRequest(const QByteArray &frame);
    bool processClientInit(const QByteArray &frame);
    bool processClientFinish(const QByteArray &frame);
    bool processClientConnectionResponse(const QByteArray &frame);
    bool deriveKeys(const QByteArray &genericPublicKey);

    bool decryptOffline(const QByteArray &secureMessage, QByteArray *offline);
    bool sendEncryptedOffline(const QByteArray &offline);
    bool processEncryptedFrame(const QByteArray &secureMessage);
    bool processPayloadTransfer(const QByteArray &payloadTransfer);
    bool processSharingFrame(const QByteArray &frame);
    bool processIntroduction(const QByteArray &introduction);
    bool processIncomingFile(qint64 id, qint64 offset, int flags,
                             const QByteArray &body);

    bool sendSharingFrame(const QByteArray &sharingFrame);
    bool sendPairedKeyEncryption();
    bool sendPairedKeyResult();
    bool sendIntroductionResponse(bool accepted);
    bool sendKeepAliveAck();

    QByteArray makeOfflineFrame(int type, int fieldNumber,
                                const QByteArray &payload) const;
    QByteArray randomBytes(int size) const;
    QByteArray hkdf(const QByteArray &ikm, const QByteArray &salt,
                    const QByteArray &info, int size) const;
    QByteArray aesCrypt(const QByteArray &input, const QByteArray &key,
                        const QByteArray &iv, bool encrypt) const;
    QByteArray signedCoordinate(const void *bn) const;
    QString safeDestination(const QString &name) const;
    QString humanSize(qint64 bytes) const;
    QString pinFromAuthKey(const QByteArray &key) const;

    void status(const QString &message) const;
    void event(const QString &title, const QString &detail) const;
    bool fail(const QString &message);
    void closeFiles();

    int m_fd;
    QString m_peerAddress;
    QString m_peerName;
    QString m_pin;
    QString m_error;
    ShareService *m_service;
    State m_state;
    EC_KEY *m_ecKey;
    QByteArray m_clientInitRaw;
    QByteArray m_serverInitRaw;
    QByteArray m_commitment;
    QByteArray m_decryptKey;
    QByteArray m_receiveHmacKey;
    QByteArray m_encryptKey;
    QByteArray m_sendHmacKey;
    int m_clientSequence;
    int m_serverSequence;
    qint64 m_totalBytes;
    qint64 m_receivedBytes;
    QHash<qint64, QByteArray> m_byteBuffers;
    QHash<qint64, IncomingFile *> m_files;
    QTime m_consentTimer;
};

#endif
