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
#include <QtCore/QLocale>
#include <QtCore/QTextCodec>
#include <QtCore/QTranslator>
#include <QtCore/QTextStream>
#include <QtDeclarative/QDeclarativeError>
#include <QtGlobal>

#include "ShareService.hpp"

using namespace bb::cascades;

// Catena traduzioni: lingua del device -> inglese (fallback garantito) ->
// italiano (solo per stringhe assenti da tutti i .qm, cioè la lingua base).
static QTranslator *g_baseTranslator = 0;
static QTranslator *g_langTranslator = 0;

static void installTranslations()
{
    QCoreApplication *app = QCoreApplication::instance();
    const QString tdir = QLatin1String("app/native/assets/translations");

    // Base inglese sempre installata.
    if (!g_baseTranslator)
        g_baseTranslator = new QTranslator(app);
    app->removeTranslator(g_baseTranslator);
    bool baseLoaded = g_baseTranslator->load(
        QLatin1String(":/translations/bbxshare_en.qm"));
    if (!baseLoaded)
        baseLoaded = g_baseTranslator->load(QLatin1String("bbxshare_en"), tdir);
    if (baseLoaded)
        app->installTranslator(g_baseTranslator);

    // Lingua del device, come fa il sample ufficiale weatherguesser: QLocale()
    // (il default locale e' inizializzato da BB10 con la lingua impostata).
    QString lang = QLocale().name();
    lang = lang.section(QLatin1Char('_'), 0, 0).toLower();
    if (lang.isEmpty() || lang.size() > 3)
        lang = QLatin1String("en");

    bool langLoaded = false;
    if (lang != QLatin1String("en")) {
        if (!g_langTranslator)
            g_langTranslator = new QTranslator(app);
        app->removeTranslator(g_langTranslator);
        langLoaded = g_langTranslator->load(
            QLatin1String(":/translations/bbxshare_") + lang + QLatin1String(".qm"));
        if (!langLoaded)
            langLoaded = g_langTranslator->load(QLatin1String("bbxshare_") + lang, tdir);
        if (langLoaded)
            app->installTranslator(g_langTranslator);
    }

    // ponytail: log diagnostico temporaneo su cartella shared, da togliere
    // una volta verificata la selezione lingua.
    const QString selfQml = QCoreApplication::translate("main", "Receive");
    const QString selfCpp = QObject::tr("Send completed");
    const QString selfBar = QCoreApplication::translate("main", "Attività");
    QDir().mkpath(QLatin1String("/accounts/1000/shared/downloads/BBXShare"));
    QFile diag(QLatin1String("/accounts/1000/shared/downloads/BBXShare/i18n.log"));
    if (diag.open(QIODevice::Append | QIODevice::Text)) {
        QTextStream ts(&diag);
        ts << "locale=" << QLocale().name() << " -> lang=" << lang
           << " base_en=" << baseLoaded << " device_lang=" << langLoaded
           << " test_qml=" << selfQml << " test_cpp=" << selfCpp
           << " test_bar=" << selfBar << "\n";
    }
}

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

    // In Qt4 le sorgenti tr() sono Latin-1 di default: senza questo, ogni
    // stringa con accenti (Attività, ·, —) non matcha le chiavi nei .qm.
    QTextCodec::setCodecForTr(QTextCodec::codecForName("UTF-8"));
    QTextCodec::setCodecForCStrings(QTextCodec::codecForName("UTF-8"));

    installTranslations();

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
