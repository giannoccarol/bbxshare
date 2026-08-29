// runner di debug host: avvia il responder e resta vivo 15s
#include "../src/ShareService.hpp"
#include <QtCore/QCoreApplication>
#include <unistd.h>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    ShareService svc;
    svc.start(15353);
    sleep(15);
    return 0;
}
