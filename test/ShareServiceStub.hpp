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

    void finishConsent()
    {
        QMutexLocker locker(&m_mutex);
        m_decision = -1;
    }

public slots:
    void setStatus(const QString &) {}
    void setSendStatus(const QString &) {}
    void appendEvent(const QString &, const QString &) {}
    void setTransferProgress(float, const QString &) {}
    void clearTransferProgress() {}

private:
    QMutex m_mutex;
    int m_decision;
};

#endif
