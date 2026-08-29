#ifndef SHARESVC_HPP_
#define SHARESVC_HPP_

#include <QtCore/QAtomicInt>
#include <QtCore/QObject>
#include <QtCore/QMutex>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QVariantList>
#include <bb/cascades/ArrayDataModel>

#include <pthread.h>

namespace bb {
namespace system {
class InvokeManager;
class InvokeRequest;
}
}

/*
 * BBX Share — fase 1.
 * Adverte un servizio mDNS "_FC9F5ED42C8A._tcp.local" (protocollo Quick Share /
 * Nearby Share) cosi' che il telefono Android lo veda nel menu Quick Share,
 * e accetta connessioni TCP sulla porta advertised (handshake: fase 2).
 */
class ShareService : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString status READ status NOTIFY statusChanged)
    Q_PROPERTY(bb::cascades::ArrayDataModel* events READ events CONSTANT)
    Q_PROPERTY(bool eventsEmpty READ eventsEmpty NOTIFY eventsChanged)
    Q_PROPERTY(bool transferPending READ transferPending NOTIFY pendingTransferChanged)
    Q_PROPERTY(QString pendingTitle READ pendingTitle NOTIFY pendingTransferChanged)
    Q_PROPERTY(QString pendingDetail READ pendingDetail NOTIFY pendingTransferChanged)
    Q_PROPERTY(bool transferActive READ transferActive NOTIFY transferProgressChanged)
    Q_PROPERTY(float transferProgress READ transferProgress NOTIFY transferProgressChanged)
    Q_PROPERTY(QString transferProgressText READ transferProgressText NOTIFY transferProgressChanged)
    Q_PROPERTY(int eventCount READ eventCount NOTIFY eventsChanged)
    Q_PROPERTY(bool outgoingReady READ outgoingReady NOTIFY outgoingChanged)
    Q_PROPERTY(QString outgoingPath READ outgoingPath NOTIFY outgoingChanged)
    Q_PROPERTY(QString outgoingName READ outgoingName NOTIFY outgoingChanged)
    Q_PROPERTY(QString outgoingDetail READ outgoingDetail NOTIFY outgoingChanged)
    Q_PROPERTY(bb::cascades::ArrayDataModel* devices READ devices CONSTANT)
    Q_PROPERTY(bool devicesEmpty READ devicesEmpty NOTIFY devicesChanged)
    Q_PROPERTY(bool scanning READ scanning NOTIFY scanningChanged)
    Q_PROPERTY(bool deviceReady READ deviceReady NOTIFY deviceSelectionChanged)
    Q_PROPERTY(QString selectedDeviceName READ selectedDeviceName NOTIFY deviceSelectionChanged)
    Q_PROPERTY(QString selectedDeviceAddress READ selectedDeviceAddress NOTIFY deviceSelectionChanged)
    Q_PROPERTY(int selectedDevicePort READ selectedDevicePort NOTIFY deviceSelectionChanged)
    Q_PROPERTY(bool sendActive READ sendActive NOTIFY sendStateChanged)
    Q_PROPERTY(bool sendFailed READ sendFailed NOTIFY sendStateChanged)
    Q_PROPERTY(QString sendStatus READ sendStatus NOTIFY sendStateChanged)

public:
    explicit ShareService(QObject *parent = 0);
    ~ShareService();
    QString status() const { return m_status; }
    bb::cascades::ArrayDataModel* events() const { return m_events; }
    bool eventsEmpty() const { return m_events->isEmpty(); }
    bool transferPending() const { return m_transferPending; }
    QString pendingTitle() const { return m_pendingTitle; }
    QString pendingDetail() const { return m_pendingDetail; }
    bool transferActive() const { return m_transferActive; }
    float transferProgress() const { return m_transferProgress; }
    QString transferProgressText() const { return m_transferProgressText; }
    int eventCount() const { return m_events->size(); }
    bool outgoingReady() const { return !m_outgoingPaths.isEmpty(); }
    QString outgoingPath() const { return m_outgoingPath; }
    QString outgoingName() const { return m_outgoingName; }
    QString outgoingDetail() const { return m_outgoingDetail; }
    bb::cascades::ArrayDataModel* devices() const { return m_devices; }
    bool devicesEmpty() const { return m_devices->isEmpty(); }
    bool scanning() const { return m_scanning; }
    bool deviceReady() const { return !m_selectedDeviceAddress.isEmpty() && m_selectedDevicePort > 0; }
    QString selectedDeviceName() const { return m_selectedDeviceName; }
    QString selectedDeviceAddress() const { return m_selectedDeviceAddress; }
    int selectedDevicePort() const { return m_selectedDevicePort; }
    bool sendActive() const { return m_sendActive; }
    bool sendFailed() const { return m_sendFailed; }
    QString sendStatus() const { return m_sendStatus; }

    Q_INVOKABLE void start(int mdnsPort = 5353);
    Q_INVOKABLE void acceptTransfer();
    Q_INVOKABLE void rejectTransfer();
    Q_INVOKABLE void clearHistory();
    Q_INVOKABLE void openReceivedFile(const QString &path);
    Q_INVOKABLE void selectOutgoingFile(const QString &path);
    Q_INVOKABLE void selectOutgoingFiles(const QStringList &paths);
    Q_INVOKABLE void clearOutgoingFile();
    Q_INVOKABLE void scanDevices();
    Q_INVOKABLE void selectDevice(const QString &address, int port,
                                  const QString &name, const QString &instance);
    Q_INVOKABLE void clearDeviceSelection();
    Q_INVOKABLE void sendOutgoing();

    // API thread-safe usata dalla sessione Quick Share in background.
    bool beginConsent(const QString &title, const QString &detail);
    int consentDecision(); // -1=rifiuta, 0=attesa, 1=accetta
    void finishConsent();
    // Internal hand-off consumed by the mDNS worker.
    bool takeScanRequest();
    bool takeResolveRequest(QString *instance);
    bool stopRequested() const { return m_stopRequested != 0; }

signals:
    void statusChanged(const QString &status);
    void eventsChanged();
    void pendingTransferChanged();
    void transferProgressChanged();
    void outgoingChanged();
    void devicesChanged();
    void scanningChanged();
    void deviceSelectionChanged();
    void sendStateChanged();

public slots:
    void setStatus(const QString &status);
    void appendEvent(const QString &name, const QString &detail, const QString &path);
    void showPendingTransfer(const QString &title, const QString &detail);
    void clearPendingTransfer();
    void setTransferProgress(float progress, const QString &text);
    void clearTransferProgress();
    void clearDevices();
    void setScanning(bool scanning);
    void syncDevices(const QVariantList &devices);
    void setSendStatus(const QString &status);
    void sendFinished(bool success);

private slots:
    void handleInvoke(const bb::system::InvokeRequest &request);
    void handleOpenFolderReply();
    void sendOutgoingResolved();

private:
    void saveHistory();
    void loadHistory();
    QString m_status;
    bb::cascades::ArrayDataModel *m_events;
    bool m_started;
    bool m_transferPending;
    QString m_pendingTitle;
    QString m_pendingDetail;
    QMutex m_consentMutex;
    int m_consentDecision;
    bool m_transferActive;
    float m_transferProgress;
    QString m_transferProgressText;
    bb::system::InvokeManager *m_invokeManager;
    QStringList m_outgoingPaths;
    QString m_outgoingPath;
    QString m_outgoingName;
    QString m_outgoingDetail;
    bb::cascades::ArrayDataModel *m_devices;
    bool m_scanning;
    QString m_selectedDeviceName;
    QString m_selectedDeviceAddress;
    QString m_selectedDeviceInstance;
    int m_selectedDevicePort;
    bool m_sendActive;
    bool m_sendFailed;
    QString m_sendStatus;
    QMutex m_discoveryMutex;
    bool m_scanRequested;
    QString m_resolveInstanceRequested;
    bool m_sendRefreshPending;
    QString m_localDeviceName;
    QAtomicInt m_stopRequested;
    pthread_t m_workerThread;
    bool m_workerStarted;

};

#endif
