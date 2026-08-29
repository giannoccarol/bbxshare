#ifndef DISCOVERYUTILS_HPP_
#define DISCOVERYUTILS_HPP_

#include <QtCore/QByteArray>
#include <QtCore/QString>

namespace BbxDiscovery {

QString endpointDisplayName(const QByteArray &endpoint);
bool containsQuickShareService(const char *rawData, int length);

}

#endif
