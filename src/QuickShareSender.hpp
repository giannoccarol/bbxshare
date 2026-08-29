#ifndef QUICKSHARESENDER_HPP_
#define QUICKSHARESENDER_HPP_

#include <QtCore/QByteArray>
#include <QtCore/QString>

class ShareService;

class QuickShareSender {
public:
    QuickShareSender(const QString &path, const QString &address, int port,
                     const QString &deviceName, ShareService *service);
    ~QuickShareSender();
    bool run();

private:
    bool connectPeer();
    bool readFrame(QByteArray *frame, int timeoutMs);
    bool receiveExact(char *data, int size, int timeoutMs);
    bool sendFrame(const QByteArray &frame);
    bool sendAll(const char *data, int size);
    bool sendEncryptedOffline(const QByteArray &offline);
    bool decryptOffline(const QByteArray &secure, QByteArray *offline);
    bool receiveSharingFrame(QByteArray *sharing, int timeoutMs);
    bool sendSharingFrame(const QByteArray &sharing);

    bool sendConnectionRequest();
    bool sendClientInit();
    bool processServerInit(const QByteArray &frame);
    bool sendClientFinish();
    bool sendConnectionResponse();
    bool processConnectionResponse(const QByteArray &frame);
    bool sendPairedKeyEncryption();
    bool sendPairedKeyResult();
    bool sendIntroduction();
    bool processIntroductionResponse(const QByteArray &frame);
    bool sendFile();
    bool sendDisconnection();

    QByteArray makeOfflineFrame(int type, int fieldNumber,
                                const QByteArray &payload) const;
    QByteArray randomBytes(int size) const;
    QByteArray hkdf(const QByteArray &ikm, const QByteArray &salt,
                    const QByteArray &info, int size) const;
    QByteArray aesCrypt(const QByteArray &input, const QByteArray &key,
                        const QByteArray &iv, bool encrypt) const;
    QByteArray signedCoordinate(const void *bn) const;
    QByteArray endpointInfo() const;
    QByteArray fileMimeType(const QString &name) const;
    QString safeName(const QString &name) const;
    QString humanSize(qint64 bytes) const;
    bool fail(const QString &message);
    void status(const QString &message) const;
    void event(const QString &title, const QString &detail) const;

    int m_fd;
    QString m_path;
    QString m_address;
    int m_port;
    QString m_deviceName;
    ShareService *m_service;
    QByteArray m_clientInitRaw;
    QByteArray m_serverInitRaw;
    QByteArray m_clientFinishRaw;
    QByteArray m_encryptKey;
    QByteArray m_sendHmacKey;
    QByteArray m_decryptKey;
    QByteArray m_receiveHmacKey;
    int m_sendSequence;
    int m_receiveSequence;
    qint64 m_fileSize;
    qint64 m_sentBytes;
    quint64 m_payloadId;
    void *m_ecKey;
};

#endif
