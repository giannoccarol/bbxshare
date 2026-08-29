#ifndef QUICKSHARESENDER_HPP_
#define QUICKSHARESENDER_HPP_

#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QHash>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QTime>

class ShareService;

class QuickShareSender {
public:
    QuickShareSender(const QStringList &paths, const QString &address, int port,
                     const QString &deviceName, const QString &localDeviceName,
                     ShareService *service);
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
    int processReceivedOffline(const QByteArray &offline, QByteArray *sharing);
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
    bool sendFiles();
    bool sendFilePayload(const QString &path, quint64 payloadId, qint64 size);
    bool checkPeerControl();
    bool sendDisconnection();
    bool waitForSafeDisconnect();

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
    QString pinFromAuthKey(const QByteArray &key) const;
    bool fail(const QString &message);
    void status(const QString &message) const;

    int m_fd;
    struct OutgoingFile {
        QString path;
        QString name;
        QByteArray mimeType;
        qint64 size;
        quint64 payloadId;
    };

    QStringList m_paths;
    QString m_address;
    int m_port;
    QString m_deviceName;
    QString m_localDeviceName;
    QString m_pin;
    ShareService *m_service;
    QByteArray m_clientInitRaw;
    QByteArray m_serverInitRaw;
    QByteArray m_clientFinishRaw;
    QByteArray m_encryptKey;
    QByteArray m_sendHmacKey;
    QByteArray m_decryptKey;
    QByteArray m_receiveHmacKey;
    QHash<quint64, QByteArray> m_controlBuffers;
    int m_sendSequence;
    int m_receiveSequence;
    QList<OutgoingFile> m_files;
    qint64 m_totalSize;
    qint64 m_sentBytes;
    qint64 m_transferDeadlineMs;
    QTime m_transferTimer;
    bool m_safeDisconnect;
    void *m_ecKey;
};

#endif
