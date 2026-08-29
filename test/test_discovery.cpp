#include "../src/DiscoveryUtils.hpp"

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <stdio.h>

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

int main()
{
    QByteArray named;
    named.append((char)(1 << 1));
    named.append(QByteArray(16, '\x42'));
    named.append((char)7);
    named.append("Pixel 9", 7);
    if (BbxDiscovery::endpointDisplayName(named) != QString::fromUtf8("Pixel 9"))
        return fail("nome endpoint esteso");

    QByteArray shortPhone;
    shortPhone.append((char)(1 << 1));
    shortPhone.append(QByteArray(16, '\x24'));
    if (BbxDiscovery::endpointDisplayName(shortPhone) !=
        QString::fromUtf8("Telefono vicino"))
        return fail("fallback record Android 17");

    QByteArray shortComputer;
    shortComputer.append((char)(3 << 1));
    shortComputer.append(QByteArray(16, '\x18'));
    if (BbxDiscovery::endpointDisplayName(shortComputer) !=
        QString::fromUtf8("Computer vicino"))
        return fail("fallback peer BBX/desktop");

    QByteArray fe2c;
    fe2c.append((char)27);
    fe2c.append((char)0x16);
    fe2c.append((char)0x2c);
    fe2c.append((char)0xfe);
    fe2c.append(QByteArray(24, '\0'));
    if (!BbxDiscovery::containsQuickShareService(fe2c.constData(), fe2c.size()))
        return fail("advertisement FE2C");

    const char fef3[] = { 3, 0x03, (char)0xf3, (char)0xfe };
    if (!BbxDiscovery::containsQuickShareService(fef3, sizeof(fef3)))
        return fail("advertisement FEF3");

    const char malformed[] = { 12, 0x16, 0x2c };
    if (BbxDiscovery::containsQuickShareService(malformed, sizeof(malformed)))
        return fail("advertisement troncato");

    puts("OK — endpoint Android 17 e BLE FE2C/FEF3");
    return 0;
}
