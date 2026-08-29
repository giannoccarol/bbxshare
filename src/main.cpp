#include <bb/cascades/Application>
#include <bb/cascades/AbstractPane>
#include <bb/cascades/QmlDocument>
#include <bb/cascades/ThemeSupport>
#include <bb/cascades/VisualStyle>
#include <bb/cascades/pickers/FilePicker>
#include <bb/cascades/pickers/FilePickerMode>
#include <bb/cascades/pickers/FilePickerViewMode>
#include <bb/cascades/pickers/FileType>

#include <QtCore/QFile>
#include <QtCore/QDir>
#include <QtCore/QList>
#include <QtCore/QTextStream>
#include <QtDeclarative/QDeclarativeError>
#include <QtGlobal>

#include "ShareService.hpp"

using namespace bb::cascades;

// log dei warning QML/C++ in file leggibile da SSH (shared folder)
static void logHandler(QtMsgType type, const char *msg)
{
    Q_UNUSED(type);
    QFile f(QDir::homePath() + QLatin1String("/bbxshare.log"));
    if (f.open(QIODevice::Append | QIODevice::Text)) {
        QTextStream ts(&f);
        ts << msg << "\n";
        f.close();
    }
}

Q_DECL_EXPORT int main(int argc, char **argv)
{
    qInstallMsgHandler(logHandler);

    qmlRegisterType<bb::cascades::pickers::FilePicker>(
        "bb.cascades.pickers", 1, 0, "FilePicker");
    qmlRegisterUncreatableType<bb::cascades::pickers::FilePickerMode>(
        "bb.cascades.pickers", 1, 0, "FilePickerMode", "");
    qmlRegisterUncreatableType<bb::cascades::pickers::FilePickerViewMode>(
        "bb.cascades.pickers", 1, 0, "FilePickerViewMode", "");
    qmlRegisterUncreatableType<bb::cascades::pickers::FileType>(
        "bb.cascades.pickers", 1, 0, "FileType", "");

    Application app(argc, argv);
    app.themeSupport()->setVisualStyle(VisualStyle::Dark);

    ShareService share;
    QObject errorContext;

    QmlDocument *qml = QmlDocument::create("asset:///main.qml").parent(&app);
    qml->setContextProperty("share", &share);
    QString qmlErrorText;
    if (qml->hasErrors()) {
        const QList<QDeclarativeError> errors = qml->errors();
        for (int i = 0; i < errors.size(); ++i) {
            logHandler(QtCriticalMsg, errors.at(i).toString().toUtf8().constData());
            qmlErrorText += errors.at(i).toString() + QLatin1String("\n");
        }
    }

    AbstractPane *root = qmlErrorText.isEmpty()
        ? qml->createRootObject<AbstractPane>() : 0;
    if (!root) {
        if (qmlErrorText.isEmpty())
            qmlErrorText = QLatin1String("main.qml: creazione root fallita");
        logHandler(QtCriticalMsg, qmlErrorText.toUtf8().constData());

        QmlDocument *errorQml = QmlDocument::create("asset:///error.qml").parent(&app);
        errorContext.setProperty("text", qmlErrorText);
        errorQml->setContextProperty("qmlError", &errorContext);
        root = errorQml->createRootObject<AbstractPane>();
        if (!root)
            return EXIT_FAILURE;
    }
    app.setScene(root);

    share.start();

    return Application::exec();
}
