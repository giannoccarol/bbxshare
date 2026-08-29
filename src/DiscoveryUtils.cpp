#include "DiscoveryUtils.hpp"

#include <QtCore/QObject>

namespace BbxDiscovery {

namespace {

bool isReadableDeviceName(const QString &name)
{
    if (name.isEmpty() || name.contains(QChar(0xfffd))) return false;
    for (int i = 0; i < name.size(); ++i) {
        const ushort c = name.at(i).unicode();
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

QString fallbackDeviceName(const QByteArray &endpoint)
{
    if (endpoint.isEmpty()) return QObject::tr("Dispositivo vicino");
    const int type = ((unsigned char)endpoint.at(0) >> 1) & 7;
    switch (type) {
    case 1: return QObject::tr("Telefono vicino");
    case 2: return QObject::tr("Tablet vicino");
    case 3: return QObject::tr("Computer vicino");
    default: return QObject::tr("Dispositivo vicino");
    }
}

}

QString endpointDisplayName(const QByteArray &endpoint)
{
    if (endpoint.size() >= 18 && (endpoint.at(0) & 0x10) == 0) {
        const int nameLength = (unsigned char)endpoint.at(17);
        if (nameLength > 0 && endpoint.size() >= 18 + nameLength) {
            const QString candidate = QString::fromUtf8(
                endpoint.constData() + 18, nameLength).trimmed();
            if (isReadableDeviceName(candidate)) return candidate;
        }
    }
    return fallbackDeviceName(endpoint);
}

bool containsQuickShareService(const char *rawData, int length)
{
    if (!rawData || length <= 0) return false;
    const unsigned char *data = (const unsigned char *)rawData;
    int pos = 0;
    while (pos < length) {
        const int fieldLength = data[pos++];
        if (fieldLength == 0) break;
        if (pos + fieldLength > length) break;
        const int type = data[pos++];
        const int payloadLength = fieldLength - 1;
        const unsigned char *payload = data + pos;

        if (type == 0x16 && payloadLength >= 2) {
            const unsigned uuid = payload[0] | ((unsigned)payload[1] << 8);
            if (uuid == 0xFE2C || uuid == 0xFEF3) return true;
        } else if ((type == 0x02 || type == 0x03) && payloadLength >= 2) {
            for (int i = 0; i + 1 < payloadLength; i += 2) {
                const unsigned uuid = payload[i] | ((unsigned)payload[i + 1] << 8);
                if (uuid == 0xFE2C || uuid == 0xFEF3) return true;
            }
        }
        pos += payloadLength;
    }
    return false;
}

}
