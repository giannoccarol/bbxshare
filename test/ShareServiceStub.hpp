#ifndef SHARESVC_HPP_
#define SHARESVC_HPP_

#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>
#include <QtCore/QObject>
#include <QtCore/QString>

class ShareService : public QObject {
    Q_OBJECT

public:
    explicit ShareService(QObject *parent = 0)
        : QObject(parent), m_decision(-1) {}

    bool beginConsent(const QString &, const QString &)
    {
        QMutexLocker locker(&m_mutex);
        m_decision = 1;
        return true;
    }

    int consentDecision()
    {
        QMutexLocker locker(&m_mutex);
        return m_decision;
    }

    QString lastStatus()
    {
        QMutexLocker locker(&m_mutex);
        return m_status;
    }

    QString lastSendStatus()
    {
        QMutexLocker locker(&m_mutex);
        return m_sendStatus;
    }

    void finishConsent()
    {
        QMutexLocker locker(&m_mutex);
        m_decision = -1;
    }

public slots:
    void setStatus(const QString &status)
    {
        QMutexLocker locker(&m_mutex);
        m_status = status;
    }
    void setSendStatus(const QString &status)
    {
        QMutexLocker locker(&m_mutex);
        m_sendStatus = status;
    }
    void appendEvent(const QString &, const QString &, const QString &) {}
    void setTransferProgress(float, const QString &) {}
    void clearTransferProgress() {}

private:
    QMutex m_mutex;
    int m_decision;
    QString m_status;
    QString m_sendStatus;
};

#endif
