#!/usr/bin/env python3
# Genera assets/translations/bbxshare_{en,de,fr,es,nl,it}.ts a partire dalle
# sorgenti tr()/qsTr(). Lingua base: italiano (sourcelanguage).
import re, sys, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

# key -> [en, de, fr, es, nl].  Le chiavi aggiunte possono avere anche una
# sesta voce italiana esplicita; per le stringhe sorgente italiane esistenti
# l'italiano viene comunque generato dinamicamente come identità.
T = {
 "%1 KB · pronto per l'invio": ["%1 KB · ready to send", "%1 KB · bereit zum Senden", "%1 KB · prêt à envoyer", "%1 KB · listo para enviar", "%1 KB · klaar om te verzenden"],
 "%1 MB · pronto per l'invio": ["%1 MB · ready to send", "%1 MB · bereit zum Senden", "%1 MB · prêt à envoyer", "%1 MB · listo para enviar", "%1 MB · klaar om te verzenden"],
 "%1 di %2": ["%1 of %2", "%1 von %2", "%1 sur %2", "%1 de %2", "%1 van %2"],
 "%1 elementi": ["%1 items", "%1 Elemente", "%1 éléments", "%1 elementos", "%1 items"],
 "%1 vuole condividere %2 elemento/i": ["%1 wants to share %2 item(s)", "%1 möchte %2 Element(e) teilen", "%1 souhaite partager %2 élément(s)", "%1 quiere compartir %2 elemento(s)", "%1 wil %2 item(s) delen"],
 "%1\nTotale: %2 · PIN %3": ["%1\nTotal: %2 · PIN %3", "%1\nGesamt: %2 · PIN %3", "%1\nTotal : %2 · code PIN %3", "%1\nTotal: %2 · PIN %3", "%1\nTotaal: %2 · PIN %3"],
 "1 elemento": ["1 item", "1 Element", "1 élément", "1 elemento", "1 item"],
 "Accetta": ["Accept", "Annehmen", "Accepter", "Aceptar", "Accepteren"],
 "Apri File Picker": ["Open file picker", "Dateiauswahl öffnen", "Ouvrir le sélecteur de fichiers", "Abrir selector de archivos", "Bestandskiezer openen"],
 "Attendi la conferma su %1": ["Waiting for confirmation on %1", "Warte auf Bestätigung auf %1", "En attente de confirmation sur %1", "Esperando confirmación en %1", "Wachten op bevestiging op %1"],
 "Attendo conferma ricezione da %1…": ["Waiting for reception confirmation from %1…", "Warte auf Empfangsbestätigung von %1…", "Attente de la confirmation de réception de %1…", "Esperando confirmación de recepción de %1…", "Wachten op ontvangstbevestiging van %1…"],
 "Attenzione: join multicast fallita: %1": ["Warning: multicast join failed: %1", "Warnung: Multicast-Beitritt fehlgeschlagen: %1", "Attention : échec de l'adhésion multicast : %1", "Atención: falló la unión multicast: %1", "Waarschuwing: multicast-deelname mislukt: %1"],
 "Attività": ["Activity", "Aktivität", "Activité", "Actividad", "Activiteit"],
 "activity_title": ["Activity", "Aktivität", "Activité", "Actividad", "Activiteit", "Attività"],
 "activity_open_hint": ["Tap a received file in Activity to open its folder in File Manager.", "Tippe eine empfangene Datei in Aktivität an, um den Ordner im Dateimanager zu öffnen.", "Touchez un fichier reçu dans Activité pour ouvrir son dossier dans le Gestionnaire de fichiers.", "Toca un archivo recibido en Actividad para abrir su carpeta en el Gestor de archivos.", "Tik op een ontvangen bestand in Activiteit om de map in Bestandsbeheer te openen.", "Tocca un file ricevuto in Attività per aprire la sua cartella nel File Manager."],
 "Attivo — visibile come \"%1\" — IP %2, TCP %3": ["Active — visible as \"%1\" — IP %2, TCP %3", "Aktiv — sichtbar als \"%1\" — IP %2, TCP %3", "Actif — visible comme \"%1\" — IP %2, TCP %3", "Activo — visible como \"%1\" — IP %2, TCP %3", "Actief — zichtbaar als \"%1\" — IP %2, TCP %3"],
 "Avvio del servizio...": ["Starting service...", "Dienst wird gestartet...", "Démarrage du service...", "Iniciando el servicio...", "Service starten..."],
 "Avvio invio fallito": ["Failed to start send", "Senden konnte nicht gestartet werden", "Échec du démarrage de l'envoi", "No se pudo iniciar el envío", "Starten van verzending mislukt"],
 "Avvio sessione TCP fallito: %1": ["TCP session start failed: %1", "TCP-Sitzung fehlgeschlagen: %1", "Échec du démarrage de la session TCP : %1", "Fallo al iniciar sesión TCP: %1", "Starten van TCP-sessie mislukt: %1"],
 "Bind mDNS fallita: %1": ["mDNS bind failed: %1", "mDNS-Bind fehlgeschlagen: %1", "Échec du bind mDNS : %1", "Fallo de bind mDNS: %1", "mDNS-bind mislukt: %1"],
 "Cambia dispositivo": ["Change device", "Gerät wechseln", "Changer d'appareil", "Cambiar dispositivo", "Apparaat wijzigen"],
 "Cerca dispositivi": ["Search for devices", "Nach Geräten suchen", "Rechercher des appareils", "Buscar dispositivos", "Apparaten zoeken"],
 "Cerca i receiver Quick Share disponibili sulla stessa Wi-Fi.": ["Search for Quick Share receivers on the same Wi-Fi.", "Nach Quick-Share-Empfängern im selben WLAN suchen.", "Rechercher des récepteurs Quick Share sur le même Wi-Fi.", "Buscar receptores de Quick Share en la misma Wi-Fi.", "Zoek naar Quick Share-ontvangers op dezelfde Wi-Fi."],
 "Collega i due telefoni alla stessa rete Wi-Fi.": ["Connect both phones to the same Wi-Fi network.", "Verbinde beide Telefone mit demselben WLAN.", "Connectez les deux téléphones au même réseau Wi-Fi.", "Conecta ambos teléfonos a la misma red Wi-Fi.", "Verbind beide telefoons met hetzelfde Wi-Fi-netwerk."],
 "Conferma il trasferimento da %1 — PIN %2": ["Confirm the transfer from %1 — PIN %2", "Bestätige die Übertragung von %1 — PIN %2", "Confirmez le transfert de %1 — code PIN %2", "Confirma la transferencia de %1 — PIN %2", "Bevestig de overdracht van %1 — PIN %2"],
 "Confronta il PIN e accetta sul BlackBerry.": ["Compare the PIN and accept on the BlackBerry.", "Vergleiche die PIN und bestätige auf dem BlackBerry.", "Comparez le code PIN et acceptez sur le BlackBerry.", "Compara el PIN y acepta en el BlackBerry.", "Vergelijk de PIN en accepteer op de BlackBerry."],
 "ConnectionRequest protobuf non valido": ["Invalid ConnectionRequest protobuf", "Ungültiges ConnectionRequest-Protobuf", "Protobuf ConnectionRequest invalide", "Protobuf ConnectionRequest no válido", "Ongeldige ConnectionRequest-protobuf"],
 "ConnectionResponse client mancante": ["Missing client ConnectionResponse", "ConnectionResponse des Clients fehlt", "ConnectionResponse du client manquante", "Falta ConnectionResponse del cliente", "ConnectionResponse van client ontbreekt"],
 "ConnectionResponse del receiver non valida": ["Invalid receiver ConnectionResponse", "Ungültige ConnectionResponse des Empfängers", "ConnectionResponse du récepteur invalide", "ConnectionResponse del receptor no válida", "Ongeldige ConnectionResponse van ontvanger"],
 "Connessione a %1": ["Connecting to %1", "Verbinde mit %1", "Connexion à %1", "Conectando con %1", "Verbinden met %1"],
 "Connessione al dispositivo…": ["Connecting to device…", "Verbindung zum Gerät…", "Connexion à l'appareil…", "Conectando con el dispositivo…", "Verbinding maken met apparaat…"],
 "Connessione da %1 (%2) — negoziazione sicura": ["Connection from %1 (%2) — secure negotiation", "Verbindung von %1 (%2) — sichere Aushandlung", "Connexion de %1 (%2) — négociation sécurisée", "Conexión de %1 (%2) — negociación segura", "Verbinding van %1 (%2) — veilige onderhandeling"],
 "Connessione…": ["Connecting…", "Verbinden…", "Connexion…", "Conectando…", "Verbinden…"],
 "Da Android": ["From Android", "Von Android", "Depuis Android", "Desde Android", "Vanuit Android"],
 "Da Quick Share su Android scegli BBX Share.": ["In Quick Share on Android, choose BBX Share.", "Wähle in Quick Share auf Android BBX Share.", "Dans Quick Share sur Android, choisissez BBX Share.", "En Quick Share en Android, elige BBX Share.", "Kies in Quick Share op Android voor BBX Share."],
 "Destinatario: %1": ["Recipient: %1", "Empfänger: %1", "Destinataire : %1", "Destinatario: %1", "Ontvanger: %1"],
 "Destinazione": ["Destination", "Ziel", "Destination", "Destino", "Bestemming"],
 "Dispositivi vicini": ["Nearby devices", "Geräte in der Nähe", "Appareils à proximité", "Dispositivos cercanos", "Apparaten in de buurt"],
 "ECDH fallito": ["ECDH failed", "ECDH fehlgeschlagen", "Échec ECDH", "ECDH fallido", "ECDH mislukt"],
 "ECDH server fallito": ["Server ECDH failed", "ECDH mit Server fehlgeschlagen", "Échec ECDH serveur", "ECDH del servidor fallido", "Server-ECDH mislukt"],
 "Errore invio: %1": ["Send error: %1", "Sendefehler: %1", "Erreur d'envoi : %1", "Error de envío: %1", "Verzendfout: %1"],
 "Errore ricezione: %1": ["Receive error: %1", "Empfangsfehler: %1", "Erreur de réception : %1", "Error de recepción: %1", "Ontvangfout: %1"],
 "Errore socket: %1": ["Socket error: %1", "Socket-Fehler: %1", "Erreur de socket : %1", "Error de socket: %1", "Socketfout: %1"],
 "I file inviati e ricevuti compariranno qui.": ["Sent and received files will appear here.", "Gesendete und empfangene Dateien erscheinen hier.", "Les fichiers envoyés et reçus apparaîtront ici.", "Los archivos enviados y recibidos aparecerán aquí.", "Verzonden en ontvangen bestanden verschijnen hier."],
 "IP locale aggiornato: %1": ["Local IP updated: %1", "Lokale IP aktualisiert: %1", "IP locale mise à jour : %1", "IP local actualizado: %1", "Lokaal IP bijgewerkt: %1"],
 "Impossibile avviare l'invio": ["Cannot start sending", "Senden nicht möglich", "Impossible de démarrer l'envoi", "No se puede iniciar el envío", "Kan verzending niet starten"],
 "In attesa dei dati...": ["Waiting for data...", "Warte auf Daten...", "En attente des données...", "Esperando datos...", "Wachten op gegevens..."],
 "Introduction mancante": ["Missing Introduction", "Introduction fehlt", "Introduction manquante", "Falta Introduction", "Introduction ontbreekt"],
 "Invia": ["Send", "Senden", "Envoyer", "Enviar", "Verzenden"],
 "Invia %1": ["Send %1", "%1 senden", "Envoyer %1", "Enviar %1", "%1 verzenden"],
 "Inviato a %1 · %2": ["Sent to %1 · %2", "An %1 gesendet · %2", "Envoyé à %1 · %2", "Enviado a %1 · %2", "Verzonden naar %1 · %2"],
 "Invio completato": ["Send completed", "Senden abgeschlossen", "Envoi terminé", "Envío completado", "Verzenden voltooid"],
 "Invio completato a %1": ["Sent to %1", "An %1 gesendet", "Envoyé à %1", "Enviado a %1", "Verzonden naar %1"],
 "Invio di %1": ["Sending %1", "Sende %1", "Envoi de %1", "Enviando %1", "%1 verzenden"],
 "Invio in corso": ["Sending", "Wird gesendet", "Envoi en cours", "Enviando", "Verzenden"],
 "Invio in corso…": ["Sending…", "Wird gesendet…", "Envoi en cours…", "Enviando…", "Bezig met verzenden…"],
 "Invio non riuscito": ["Send failed", "Senden fehlgeschlagen", "Échec de l'envoi", "Envío fallido", "Verzenden mislukt"],
 "Listener TCP fallito: %1": ["TCP listener failed: %1", "TCP-Listener fehlgeschlagen: %1", "Échec de l'écoute TCP : %1", "Fallo del listener TCP: %1", "TCP-listener mislukt: %1"],
 "Negoziazione sicura con %1": ["Secure negotiation with %1", "Sichere Aushandlung mit %1", "Négociation sécurisée avec %1", "Negociación segura con %1", "Veilige onderhandeling met %1"],
 "Nessun device trovato. Attiva Quick Share sul telefono e riprova.": ["No devices found. Enable Quick Share on the phone and try again.", "Keine Geräte gefunden. Aktiviere Quick Share auf dem Telefon und versuche es erneut.", "Aucun appareil trouvé. Activez Quick Share sur le téléphone et réessayez.", "No se encontraron dispositivos. Activa Quick Share en el teléfono y reintenta.", "Geen apparaten gevonden. Schakel Quick Share in op de telefoon en probeer opnieuw."],
 "Nessun trasferimento": ["No transfers", "Keine Übertragungen", "Aucun transfert", "Sin transferencias", "Geen overdrachten"],
 "PairedKeyEncryption mancante": ["Missing PairedKeyEncryption", "PairedKeyEncryption fehlt", "PairedKeyEncryption manquante", "Falta PairedKeyEncryption", "PairedKeyEncryption ontbreekt"],
 "PairedKeyResult mancante": ["Missing PairedKeyResult", "PairedKeyResult fehlt", "PairedKeyResult manquant", "Falta PairedKeyResult", "PairedKeyResult ontbreekt"],
 "PayloadTransfer non valido": ["Invalid PayloadTransfer", "Ungültiges PayloadTransfer", "PayloadTransfer invalide", "PayloadTransfer no válido", "Ongeldige PayloadTransfer"],
 "Pronto a ricevere": ["Ready to receive", "Bereit zum Empfangen", "Prêt à recevoir", "Listo para recibir", "Klaar om te ontvangen"],
 "Pronto sulla rete Wi-Fi": ["Ready on the Wi-Fi network", "Bereit im WLAN", "Prêt sur le réseau Wi-Fi", "Listo en la red Wi-Fi", "Gereed op het Wi-Fi-netwerk"],
 "Pulisci": ["Clear", "Leeren", "Effacer", "Limpiar", "Wissen"],
 "Quick Share · %1": ["Quick Share · %1", "Quick Share · %1", "Quick Share · %1", "Quick Share · %1", "Quick Share · %1"],
 "RICHIESTA QUICK SHARE": ["QUICK SHARE REQUEST", "QUICK-SHARE-ANFRAGE", "DEMANDE QUICK SHARE", "SOLICITUD QUICK SHARE", "QUICK SHARE-VERZOEK"],
 "Ricerca dispositivi vicini…": ["Searching for nearby devices…", "Suche nach Geräten in der Nähe…", "Recherche d'appareils à proximité…", "Buscando dispositivos cercanos…", "Zoeken naar apparaten in de buurt…"],
 "Ricerca in corso…": ["Searching…", "Suche…", "Recherche…", "Buscando…", "Zoeken…"],
 "Ricerca terminata": ["Search finished", "Suche beendet", "Recherche terminée", "Búsqueda finalizada", "Zoeken voltooid"],
 "Ricevi": ["Receive", "Empfangen", "Recevoir", "Recibir", "Ontvangen"],
 "Ricevuto da %1 · %2": ["Received from %1 · %2", "Empfangen von %1 · %2", "Reçu de %1 · %2", "Recibido de %1 · %2", "Ontvangen van %1 · %2"],
 "Ricezione %1 — %2 / %3": ["Receiving %1 — %2 / %3", "Empfange %1 — %2 / %3", "Réception de %1 — %2 / %3", "Recibiendo %1 — %2 / %3", "Ontvangen van %1 — %2 / %3"],
 "Ricezione in corso": ["Receiving", "Wird empfangen", "Réception en cours", "Recibiendo", "Ontvangen"],
 "Richiesta di invio a %1 — attendo conferma": ["Send request to %1 — waiting for confirmation", "Sendeanfrage an %1 — warte auf Bestätigung", "Demande d'envoi à %1 — attente de confirmation", "Solicitud de envío a %1 — esperando confirmación", "Verzoek om te verzenden naar %1 — wachten op bevestiging"],
 "Richiesta in arrivo": ["Incoming request", "Eingehende Anfrage", "Requête entrante", "Solicitud entrante", "Inkomend verzoek"],
 "Rifiuta": ["Reject", "Ablehnen", "Refuser", "Rechazar", "Weigeren"],
 "Rimuovi": ["Remove", "Entfernen", "Retirer", "Quitar", "Verwijderen"],
 "Scegli il file da inviare": ["Choose the file to send", "Wähle die zu sendende Datei", "Choisissez le fichier à envoyer", "Elige el archivo a enviar", "Kies het bestand om te verzenden"],
 "Scegli prima un file": ["Choose a file first", "Wähle zuerst eine Datei", "Choisissez d'abord un fichier", "Elige primero un archivo", "Kies eerst een bestand"],
 "Scegli un altro file": ["Choose another file", "Andere Datei wählen", "Choisir un autre fichier", "Elegir otro archivo", "Kies een ander bestand"],
 "Scegli un file": ["Choose a file", "Datei wählen", "Choisir un fichier", "Elegir un archivo", "Kies een bestand"],
 "SecureMessage server non valido": ["Invalid server SecureMessage", "Ungültige SecureMessage des Servers", "SecureMessage du serveur invalide", "SecureMessage del servidor no válida", "Ongeldige SecureMessage van server"],
 "SecureMessage/HMAC non valido": ["Invalid SecureMessage/HMAC", "Ungültiges SecureMessage/HMAC", "SecureMessage/HMAC invalide", "SecureMessage/HMAC no válido", "Ongeldige SecureMessage/HMAC"],
 "Segnale Quick Share BLE rilevato: annuncio Wi-Fi inviato": ["Quick Share BLE signal detected: Wi-Fi announcement sent", "Quick-Share-BLE-Signal erkannt: WLAN-Ankündigung gesendet", "Signal BLE Quick Share détecté : annonce Wi-Fi envoyée", "Señal BLE de Quick Share detectada: anuncio Wi-Fi enviado", "Quick Share BLE-signaal gedetecteerd: Wi-Fi-aankondiging verzonden"],
 "Stato invio": ["Send status", "Sendestatus", "État de l'envoi", "Estado de envío", "Verzendstatus"],
 "Testo ricevuto %1.txt": ["Received text %1.txt", "Empfangener Text %1.txt", "Texte reçu %1.txt", "Texto recibido %1.txt", "Ontvangen tekst %1.txt"],
 "Tocca un file ricevuto in Attività per aprire la sua cartella nel File Manager.": ["Tap a received file in Activity to open its folder in File Manager.", "Tippe eine empfangene Datei in Aktivität an, um den Ordner im Dateimanager zu öffnen.", "Touchez un fichier reçu dans Activité pour ouvrir son dossier dans le Gestionnaire de fichiers.", "Toca un archivo recibido en Actividad para abrir su carpeta en el Gestor de archivos.", "Tik op een ontvangen bestand in Activiteit om de map in Bestandsbeheer te openen."],
 "Trasferimento completato": ["Transfer completed", "Übertragung abgeschlossen", "Transfert terminé", "Transferencia completada", "Overdracht voltooid"],
 "Trasferimento in corso": ["Transfer in progress", "Übertragung läuft", "Transfert en cours", "Transferencia en curso", "Overdracht bezig"],
 "UKEY2 ClientFinish non valido": ["Invalid UKEY2 ClientFinish", "Ungültiges UKEY2 ClientFinish", "UKEY2 ClientFinish invalide", "UKEY2 ClientFinish no válido", "Ongeldige UKEY2 ClientFinish"],
 "UKEY2 ClientInit non supportato": ["Unsupported UKEY2 ClientInit", "UKEY2 ClientInit nicht unterstützt", "UKEY2 ClientInit non pris en charge", "UKEY2 ClientInit no admitido", "UKEY2 ClientInit niet ondersteund"],
 "UKEY2 ServerInit non valido": ["Invalid UKEY2 ServerInit", "Ungültiges UKEY2 ServerInit", "UKEY2 ServerInit invalide", "UKEY2 ServerInit no válido", "Ongeldige UKEY2 ServerInit"],
 "Verifica del canale cifrato": ["Verifying encrypted channel", "Überprüfe verschlüsselten Kanal", "Vérification du canal chiffré", "Verificando canal cifrado", "Versleuteld kanaal controleren"],
 "Visibile sulla Wi-Fi come BBX Share": ["Visible on Wi-Fi as BBX Share", "Sichtbar im WLAN als BBX Share", "Visible sur le Wi-Fi sous le nom BBX Share", "Visible en la Wi-Fi como BBX Share", "Zichtbaar op Wi-Fi als BBX Share"],
 "chiave pubblica client non valida": ["invalid client public key", "ungültiger öffentlicher Clientschlüssel", "clé publique client invalide", "clave pública del cliente no válida", "ongeldige openbare clientsleutel"],
 "chiusura del trasferimento fallita": ["failed to close the transfer", "Schließen der Übertragung fehlgeschlagen", "échec de la clôture du transfert", "fallo al cerrar la transferencia", "sluiten van overdracht mislukt"],
 "cifratura AES fallita": ["AES encryption failed", "AES-Verschlüsselung fehlgeschlagen", "échec du chiffrement AES", "fallo de cifrado AES", "AES-versleuteling mislukt"],
 "cipher P-256/SHA-512 assente": ["P-256/SHA-512 cipher missing", "P-256/SHA-512-Chiffre fehlt", "chiffrement P-256/SHA-512 absent", "falta el cifrado P-256/SHA-512", "P-256/SHA-512-cijfer ontbreekt"],
 "commitment UKEY2 non corrispondente": ["UKEY2 commitment mismatch", "UKEY2-Commitment stimmt nicht überein", "engagement UKEY2 non correspondant", "compromiso UKEY2 no coincidente", "UKEY2-commitment komt niet overeen"],
 "conferma di ricezione scaduta": ["reception confirmation timed out", "Zeitüberschreitung bei Empfangsbestätigung", "délai de confirmation de réception dépassé", "confirmación de recepción agotada", "time-out ontvangstbevestiging"],
 "conferma ricezione non valida": ["invalid reception confirmation", "ungültige Empfangsbestätigung", "confirmation de réception invalide", "confirmación de recepción no válida", "ongeldige ontvangstbevestiging"],
 "connessione a %1:%2: %3": ["connection to %1:%2: %3", "Verbindung zu %1:%2: %3", "connexion à %1:%2 : %3", "conexión a %1:%2: %3", "verbinding met %1:%2: %3"],
 "connessione chiusa dal telefono": ["connection closed by the phone", "Verbindung vom Telefon geschlossen", "connexion fermée par le téléphone", "conexión cerrada por el teléfono", "verbinding gesloten door telefoon"],
 "connessione persa a fine invio": ["connection lost at end of send", "Verbindung am Ende des Sendens verloren", "connexion perdue en fin d'envoi", "conexión perdida al final del envío", "verbinding verloren aan einde verzending"],
 "connessione persa durante l'invio": ["connection lost during send", "Verbindung beim Senden verloren", "connexion perdue pendant l'envoi", "conexión perdida durante el envío", "verbinding verloren tijdens verzenden"],
 "connessione rifiutata dal receiver": ["connection rejected by receiver", "Verbindung vom Empfänger abgelehnt", "connexion refusée par le récepteur", "conexión rechazada por el receptor", "verbinding geweigerd door ontvanger"],
 "connessione rifiutata: %1": ["connection refused: %1", "Verbindung abgelehnt: %1", "connexion refusée : %1", "conexión rechazada: %1", "verbinding geweigerd: %1"],
 "coordinate P-256 fuori formato": ["P-256 coordinates out of range", "P-256-Koordinaten außerhalb des Bereichs", "coordonnées P-256 hors format", "coordenadas P-256 fuera de rango", "P-256-coördinaten buiten bereik"],
 "coordinate server non valide": ["invalid server coordinates", "ungültige Server-Koordinaten", "coordonnées serveur invalides", "coordenadas del servidor no válidas", "ongeldige servercoördinaten"],
 "device Android ha annullato": ["Android device cancelled", "Android-Gerät abgebrochen", "l'appareil Android a annulé", "el dispositivo Android canceló", "Android-apparaat geannuleerd"],
 "dimensione frame non valida: %1": ["invalid frame size: %1", "ungültige Framegröße: %1", "taille de trame invalide : %1", "tamaño de trama no válido: %1", "ongeldige framegrootte: %1"],
 "endpoint info troppo corto": ["endpoint info too short", "Endpoint-Info zu kurz", "info endpoint trop courte", "información de endpoint demasiado corta", "endpoint-info te kort"],
 "file di destinazione non aperto: %1": ["destination file not open: %1", "Zieldatei nicht geöffnet: %1", "fichier de destination non ouvert : %1", "archivo de destino no abierto: %1", "doelbestand niet geopend: %1"],
 "file di origine non valido": ["invalid source file", "ungültige Quelldatei", "fichier source invalide", "archivo de origen no válido", "ongeldig bronbestand"],
 "file incompleto: %1": ["incomplete file: %1", "unvollständige Datei: %1", "fichier incomplet : %1", "archivo incompleto: %1", "onvolledig bestand: %1"],
 "frame Share non valido": ["invalid Share frame", "ungültiger Share-Frame", "trame Share invalide", "trama Share no válida", "ongeldige Share-frame"],
 "frame ricevuto non valido": ["invalid received frame", "ungültiger empfangener Frame", "trame reçue invalide", "trama recibida no válida", "ongeldige ontvangen frame"],
 "frame server senza tipo": ["server frame without type", "Server-Frame ohne Typ", "trame serveur sans type", "trama del servidor sin tipo", "serverframe zonder type"],
 "generazione chiave P-256 fallita": ["P-256 key generation failed", "P-256-Schlüsselerzeugung fehlgeschlagen", "échec de génération de clé P-256", "fallo al generar clave P-256", "P-256-sleutelgeneratie mislukt"],
 "impossibile aprire il file": ["cannot open file", "Datei kann nicht geöffnet werden", "impossible d'ouvrir le fichier", "no se puede abrir el archivo", "kan bestand niet openen"],
 "impossibile creare %1": ["cannot create %1", "%1 kann nicht erstellt werden", "impossible de créer %1", "no se puede crear %1", "kan %1 niet maken"],
 "indirizzo device non valido": ["invalid device address", "ungültige Geräteadresse", "adresse d'appareil invalide", "dirección de dispositivo no válida", "ongeldig apparaatadres"],
 "invio ConnectionRequest fallito": ["failed to send ConnectionRequest", "Senden von ConnectionRequest fehlgeschlagen", "échec d'envoi de ConnectionRequest", "fallo al enviar ConnectionRequest", "verzenden ConnectionRequest mislukt"],
 "invio ConnectionResponse fallito": ["failed to send ConnectionResponse", "Senden von ConnectionResponse fehlgeschlagen", "échec d'envoi de ConnectionResponse", "fallo al enviar ConnectionResponse", "verzenden ConnectionResponse mislukt"],
 "invio UKEY2 ClientFinish fallito": ["failed to send UKEY2 ClientFinish", "Senden von UKEY2 ClientFinish fehlgeschlagen", "échec d'envoi de UKEY2 ClientFinish", "fallo al enviar UKEY2 ClientFinish", "verzenden UKEY2 ClientFinish mislukt"],
 "invio UKEY2 ServerInit fallito": ["failed to send UKEY2 ServerInit", "Senden von UKEY2 ServerInit fehlgeschlagen", "échec d'envoi de UKEY2 ServerInit", "fallo al enviar UKEY2 ServerInit", "verzenden UKEY2 ServerInit mislukt"],
 "invio metadati file fallito": ["failed to send file metadata", "Senden der Datei-Metadaten fehlgeschlagen", "échec d'envoi des métadonnées du fichier", "fallo al enviar metadatos del archivo", "verzenden van bestandsmetadata mislukt"],
 "invio rifiutato o scaduto dal device": ["send rejected or expired on device", "Senden am Gerät abgelehnt oder abgelaufen", "envoi refusé ou expiré sur l'appareil", "envío rechazado o caducado en el dispositivo", "verzenden geweigerd of verlopen op apparaat"],
 "invio risultato chiave fallito": ["failed to send key result", "Senden des Schlüsselergebnisses fehlgeschlagen", "échec d'envoi du résultat de clé", "fallo al enviar resultado de clave", "verzenden sleutelresultaat mislukt"],
 "invio verifica chiave fallito": ["failed to send key verification", "Senden der Schlüsselprüfung fehlgeschlagen", "échec d'envoi de la vérification de clé", "fallo al enviar verificación de clave", "verzenden sleutelverificatie mislukt"],
 "lettura chiave P-256 fallita": ["failed to read P-256 key", "Lesen des P-256-Schlüssels fehlgeschlagen", "échec de lecture de la clé P-256", "fallo al leer clave P-256", "lezen van P-256-sleutel mislukt"],
 "lettura chiave pubblica fallita": ["failed to read public key", "Lesen des öffentlichen Schlüssels fehlgeschlagen", "échec de lecture de la clé publique", "fallo al leer clave pública", "lezen van openbare sleutel mislukt"],
 "lettura del file fallita": ["file read failed", "Dateilesen fehlgeschlagen", "échec de lecture du fichier", "fallo al leer el archivo", "lezen van bestand mislukt"],
 "mDNS query tipo %1 da %2 -> risposto": ["mDNS query type %1 from %2 -> answered", "mDNS-Anfrage Typ %1 von %2 -> beantwortet", "requête mDNS type %1 de %2 -> répondue", "consulta mDNS tipo %1 de %2 -> respondida", "mDNS-query type %1 van %2 -> beantwoord"],
 "metadata file incompleti": ["incomplete file metadata", "unvollständige Datei-Metadaten", "métadonnées de fichier incomplètes", "metadatos de archivo incompletos", "onvolledige bestandsmetadata"],
 "metadata testo incompleti": ["incomplete text metadata", "unvollständige Text-Metadaten", "métadonnées de texte incomplètes", "metadatos de texto incompletos", "onvolledige tekstmetadata"],
 "nessun risultato chiave dal receiver": ["no key result from receiver", "kein Schlüsselergebnis vom Empfänger", "aucun résultat de clé du récepteur", "sin resultado de clave del receptor", "geen sleutelresultaat van ontvanger"],
 "nessuna conferma di connessione dal receiver": ["no connection confirmation from receiver", "keine Verbindungsbestätigung vom Empfänger", "aucune confirmation de connexion du récepteur", "sin confirmación de conexión del receptor", "geen verbindingsbevestiging van ontvanger"],
 "nessuna risposta UKEY2 dal receiver": ["no UKEY2 response from receiver", "keine UKEY2-Antwort vom Empfänger", "aucune réponse UKEY2 du récepteur", "sin respuesta UKEY2 del receptor", "geen UKEY2-antwoord van ontvanger"],
 "nessuna verifica chiave dal receiver": ["no key verification from receiver", "keine Schlüsselprüfung vom Empfänger", "aucune vérification de clé du récepteur", "sin verificación de clave del receptor", "geen sleutelverificatie van ontvanger"],
 "nome endpoint troncato": ["endpoint name truncated", "Endpoint-Name abgeschnitten", "nom d'endpoint tronqué", "nombre de endpoint truncado", "endpointnaam afgekapt"],
 "offset payload bytes non valido": ["invalid payload bytes offset", "ungültiger Payload-Bytes-Offset", "offset des octets de charge invalide", "offset de bytes de payload no válido", "ongeldige payload-bytes-offset"],
 "offset risposta non valido": ["invalid response offset", "ungültiger Antwort-Offset", "offset de réponse invalide", "offset de respuesta no válido", "ongeldige respons-offset"],
 "offset/dimensione non valida per %1": ["invalid offset/size for %1", "ungültiger Offset/Größe für %1", "offset/taille invalides pour %1", "offset/tamaño no válidos para %1", "ongeldige offset/grootte voor %1"],
 "payload file sconosciuto: %1": ["unknown file payload: %1", "unbekannte Datei-Nutzlast: %1", "charge de fichier inconnue : %1", "payload de archivo desconocido: %1", "onbekende bestandspayload: %1"],
 "payload risposta non valido": ["invalid response payload", "ungültige Antwort-Nutzlast", "charge de réponse invalide", "payload de respuesta no válido", "ongeldige respons-payload"],
 "payload transfer mancante": ["missing payload transfer", "Payload-Transfer fehlt", "transfert de charge manquant", "falta transferencia de payload", "payload-overdracht ontbreekt"],
 "poll TCP: %1": ["TCP poll: %1", "TCP-Poll: %1", "poll TCP : %1", "poll TCP: %1", "TCP-poll: %1"],
 "punto P-256 client non valido": ["invalid client P-256 point", "ungültiger Client-P-256-Punkt", "point P-256 client invalide", "punto P-256 del cliente no válido", "ongeldig client P-256-punt"],
 "punto server non valido": ["invalid server point", "ungültiger Server-Punkt", "point serveur invalide", "punto del servidor no válido", "ongeldig serverpunt"],
 "risposta Share non valida": ["invalid Share response", "ungültige Share-Antwort", "réponse Share invalide", "respuesta Share no válida", "ongeldige Share-respons"],
 "risposta di consenso non valida": ["invalid consent response", "ungültige Zustimmungsantwort", "réponse de consentement invalide", "respuesta de consentimiento no válida", "ongeldige toestemmingsrespons"],
 "scrittura fallita: %1": ["write failed: %1", "Schreiben fehlgeschlagen: %1", "échec d'écriture : %1", "fallo de escritura: %1", "schrijven mislukt: %1"],
 "sequenza SecureMessage non valida": ["invalid SecureMessage sequence", "ungültige SecureMessage-Sequenz", "séquence SecureMessage invalide", "secuencia SecureMessage no válida", "ongeldige SecureMessage-sequentie"],
 "sequenza SecureMessage server non valida": ["invalid server SecureMessage sequence", "ungültige SecureMessage-Sequenz des Servers", "séquence SecureMessage du serveur invalide", "secuencia SecureMessage del servidor no válida", "ongeldige SecureMessage-sequentie van server"],
 "socket TCP: %1": ["TCP socket: %1", "TCP-Socket: %1", "socket TCP : %1", "socket TCP: %1", "TCP-socket: %1"],
 "timeout connessione al device": ["connection timeout to device", "Zeitüberschreitung bei Geräteverbindung", "délai de connexion à l'appareil dépassé", "tiempo de conexión al dispositivo agotado", "time-out bij verbinden met apparaat"],
 "tipo di allegato non supportato": ["unsupported attachment type", "nicht unterstützter Anhangstyp", "type de pièce jointe non pris en charge", "tipo de adjunto no admitido", "niet-ondersteund bijlagetype"],
 "tipo payload non supportato: %1": ["unsupported payload type: %1", "nicht unterstützter Payload-Typ: %1", "type de charge non pris en charge : %1", "tipo de payload no admitido: %1", "niet-ondersteund payloadtype: %1"],
 "trasferimento annullato dal telefono": ["transfer cancelled by the phone", "Übertragung vom Telefon abgebrochen", "transfert annulé par le téléphone", "transferencia cancelada por el teléfono", "overdracht geannuleerd door telefoon"],
 "un altro trasferimento è già in attesa": ["another transfer is already pending", "eine andere Übertragung ist bereits in Wartestellung", "un autre transfert est déjà en attente", "ya hay otra transferencia en espera", "er is al een andere overdracht in behandeling"],
 "Dispositivo vicino": ["Nearby device", "Gerät in der Nähe", "Appareil à proximité", "Dispositivo cercano", "Apparaat in de buurt"],
 "Telefono vicino": ["Nearby phone", "Telefon in der Nähe", "Téléphone à proximité", "Teléfono cercano", "Telefoon in de buurt"],
 "Tablet vicino": ["Nearby tablet", "Tablet in der Nähe", "Tablette à proximité", "Tableta cercana", "Tablet in de buurt"],
 "Computer vicino": ["Nearby computer", "Computer in der Nähe", "Ordinateur à proximité", "Ordenador cercano", "Computer in de buurt"],
 "%1 file": ["%1 file", "%1 Datei(en)", "%1 fichier(s)", "%1 archivo(s)", "%1 bestand(en)"],
 "Il dispositivo non è più disponibile: esegui una nuova ricerca": ["The device is no longer available: search again", "Das Gerät ist nicht mehr verfügbar: suche erneut", "L'appareil n'est plus disponible : relancez la recherche", "El dispositivo ya no está disponible: busca de nuevo", "Het apparaat is niet meer beschikbaar: zoek opnieuw"],
 "Impossibile avviare il servizio di rete": ["Cannot start the network service", "Der Netzwerkdienst kann nicht gestartet werden", "Impossible de démarrer le service réseau", "No se puede iniciar el servicio de red", "Kan de netwerkservice niet starten"],
 "cartella di destinazione non disponibile": ["destination folder unavailable", "Zielordner nicht verfügbar", "dossier de destination indisponible", "carpeta de destino no disponible", "doelmap niet beschikbaar"],
 "cartella di destinazione non scrivibile": ["destination folder not writable", "Zielordner nicht beschreibbar", "dossier de destination non inscriptible", "carpeta de destino no escribible", "doelmap niet beschrijfbaar"],
 "dimensione totale non valida": ["invalid total size", "ungültige Gesamtgröße", "taille totale invalide", "tamaño total no válido", "ongeldige totale grootte"],
 "identificatore o dimensione file non validi": ["invalid file identifier or size", "ungültige Datei-Kennung oder -Größe", "identifiant ou taille de fichier invalides", "identificador o tamaño de archivo no válidos", "ongeldige bestands-id of -grootte"],
 "impossibile verificare lo spazio disponibile": ["cannot check available space", "verfügbarer Speicherplatz kann nicht geprüft werden", "impossible de vérifier l'espace disponible", "no se puede verificar el espacio disponible", "kan beschikbare ruimte niet controleren"],
 "payload testo troppo grande o non valido": ["text payload too large or invalid", "Text-Nutzlast zu groß oder ungültig", "charge de texte trop grande ou invalide", "payload de texto demasiado grande o no válido", "tekst-payload te groot of ongeldig"],
 "spazio insufficiente: servono almeno %1": ["insufficient space: at least %1 required", "Nicht genügend Speicherplatz: mindestens %1 erforderlich", "espace insuffisant : au moins %1 requis", "espacio insuficiente: se necesita al menos %1", "onvoldoende ruimte: minimaal %1 nodig"],
 "Attendi la conferma su %1 — verifica PIN %2": ["Wait for confirmation on %1 — verify PIN %2", "Warte auf die Bestätigung auf %1 — PIN %2 prüfen", "Attendez la confirmation sur %1 — vérifiez le code PIN %2", "Espera la confirmación en %1 — verifica el PIN %2", "Wacht op bevestiging op %1 — controleer pincode %2"],
 "Attenzione: impossibile verificare l'unicità del nome mDNS": ["Warning: unable to verify mDNS name uniqueness", "Warnung: Eindeutigkeit des mDNS-Namens kann nicht geprüft werden", "Attention : impossible de vérifier l'unicité du nom mDNS", "Advertencia: no se puede verificar la unicidad del nombre mDNS", "Waarschuwing: uniciteit van mDNS-naam kan niet worden gecontroleerd"],
 "Invio di %1 file": ["Sending %1 files", "%1 Dateien werden gesendet", "Envoi de %1 fichiers", "Enviando %1 archivos", "%1 bestanden verzenden"],
 "Richiesta di invio a %1 — PIN %2 — attendo conferma": ["Send request to %1 — PIN %2 — waiting for confirmation", "Sendeanfrage an %1 — PIN %2 — warte auf Bestätigung", "Demande d'envoi à %1 — code PIN %2 — attente de confirmation", "Solicitud de envío a %1 — PIN %2 — esperando confirmación", "Verzoek aan %1 — pincode %2 — wachten op bevestiging"],
 "Scegli uno o più file da inviare": ["Choose one or more files to send", "Wähle eine oder mehrere Dateien zum Senden", "Choisissez un ou plusieurs fichiers à envoyer", "Elige uno o más archivos para enviar", "Kies een of meer bestanden om te verzenden"],
 "connessione chiusa dal receiver": ["connection closed by receiver", "Verbindung vom Empfänger geschlossen", "connexion fermée par le récepteur", "conexión cerrada por el receptor", "verbinding gesloten door ontvanger"],
 "dimensione payload file incoerente": ["inconsistent file payload size", "Inkonsistente Datei-Nutzlastgröße", "taille de charge de fichier incohérente", "tamaño de payload de archivo incoherente", "inconsistente grootte van bestandspayload"],
 "dimensione totale dei file non valida": ["invalid total file size", "Ungültige Gesamtgröße der Dateien", "taille totale des fichiers invalide", "tamaño total de archivos no válido", "ongeldige totale bestandsgrootte"],
 "file di origine non valido: %1": ["invalid source file: %1", "Ungültige Quelldatei: %1", "fichier source invalide : %1", "archivo de origen no válido: %1", "ongeldig bronbestand: %1"],
 "frame di controllo non valido": ["invalid control frame", "Ungültiger Kontrollframe", "trame de contrôle invalide", "frame de control no válido", "ongeldig besturingsframe"],
 "frame server non valido": ["invalid server frame", "Ungültiger Server-Frame", "trame serveur invalide", "frame del servidor no válido", "ongeldig serverframe"],
 "identificatore o offset payload non valido": ["invalid payload identifier or offset", "Ungültige Nutzlastkennung oder -position", "identifiant ou décalage de charge invalide", "identificador u offset de payload no válido", "ongeldige payload-id of offset"],
 "impossibile aprire il file o dimensione modificata": ["cannot open file or its size changed", "Datei kann nicht geöffnet werden oder ihre Größe wurde geändert", "impossible d'ouvrir le fichier ou sa taille a changé", "no se puede abrir el archivo o su tamaño cambió", "kan bestand niet openen of de grootte is gewijzigd"],
 "lettura stato receiver fallita": ["failed to read receiver status", "Empfängerstatus konnte nicht gelesen werden", "échec de la lecture de l'état du récepteur", "falló la lectura del estado del receptor", "lezen van ontvangerstatus mislukt"],
 "limite memoria payload superato": ["payload memory limit exceeded", "Nutzlast-Speicherlimit überschritten", "limite mémoire de charge dépassée", "límite de memoria de payload superado", "geheugenlimiet voor payload overschreden"],
 "nessun file da inviare": ["no files to send", "Keine Dateien zum Senden", "aucun fichier à envoyer", "no hay archivos para enviar", "geen bestanden om te verzenden"],
 "payload bytes incompleto": ["incomplete byte payload", "Unvollständige Byte-Nutzlast", "charge d'octets incomplète", "payload de bytes incompleto", "onvolledige bytepayload"],
 "payload bytes troppo grande o incoerente": ["byte payload too large or inconsistent", "Byte-Nutzlast zu groß oder inkonsistent", "charge d'octets trop grande ou incohérente", "payload de bytes demasiado grande o incoherente", "bytepayload te groot of inconsistent"],
 "risposta Share incompleta": ["incomplete Share response", "Unvollständige Share-Antwort", "réponse Share incomplète", "respuesta Share incompleta", "onvolledig Share-antwoord"],
 "risposta Share troppo grande": ["Share response too large", "Share-Antwort zu groß", "réponse Share trop grande", "respuesta Share demasiado grande", "Share-antwoord te groot"],
 "trasferimento annullato dal receiver": ["transfer cancelled by receiver", "Übertragung vom Empfänger abgebrochen", "transfert annulé par le récepteur", "transferencia cancelada por el receptor", "overdracht geannuleerd door ontvanger"],
 "trasferimento interrotto per inattività": ["transfer stopped due to inactivity", "Übertragung wegen Inaktivität beendet", "transfert interrompu pour inactivité", "transferencia interrumpida por inactividad", "overdracht gestopt wegens inactiviteit"],
 "Errore UI BBX Share": ["BBX Share UI error", "BBX Share UI-Fehler", "Erreur UI BBX Share", "Error de UI de BBX Share", "BBX Share UI-fout"],
}

LANGS = ["en", "de", "fr", "es", "nl", "it"]
LANG_ATTR = {"en":"en", "de":"de", "fr":"fr", "es":"es", "nl":"nl", "it":"it"}

def scan_cpp():
    keys = set()
    pat = re.compile(r'\bQObject::tr\("((?:[^"\\]|\\.)*)"\)|\btr\("((?:[^"\\]|\\.)*)"\)')
    for f in ["src/ShareService.cpp","src/QuickShareSender.cpp","src/QuickShareSession.cpp"]:
        for m in pat.finditer(open(f).read()):
            s = m.group(1) or m.group(2)
            s = s.replace('\\"','"').replace('\\\\','\\').replace('\\n','\n')
            keys.add(s)
    return keys

def scan_qml():
    ctx = {}
    pat = re.compile(r'qsTr\("((?:[^"\\]|\\.)*)"\)')
    for f in ["assets/main.qml","assets/error.qml"]:
        ks = set()
        name = f.rsplit("/",1)[-1].rsplit(".",1)[0]
        for m in pat.finditer(open(f).read()):
            s = m.group(1)
            s = s.replace('\\"','"').replace('\\\\','\\')
            s = re.sub(r'\\u([0-9a-fA-F]{4})', lambda x: chr(int(x.group(1),16)), s)
            ks.add(s)
        ctx[name] = ks
    return ctx

def xml_escape(s):
    return s.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')

def write_ts(path, lang, contexts):
    lines = ['<?xml version="1.0" encoding="utf-8"?>',
             '<!DOCTYPE TS>',
             '<TS version="2.1" language="%s" sourcelanguage="it">' % LANG_ATTR[lang]]
    for name, keys in contexts:
        lines.append('<context>')
        lines.append('    <name>%s</name>' % name)
        for k in sorted(keys):
            t = T.get(k)
            lines.append('    <message>')
            lines.append('        <source>%s</source>' % xml_escape(k))
            if t:
                # La maggior parte delle sorgenti è italiana e mantiene la
                # stessa forma nel catalogo it; le nuove chiavi ASCII possono
                # invece fornire una traduzione italiana esplicita.
                if lang == "it":
                    value = t[5] if len(t) > 5 else k
                else:
                    value = t[LANGS.index(lang)]
                lines.append('        <translation>%s</translation>' % xml_escape(value))
            else:
                lines.append('        <translation type="unfinished"></translation>')
            lines.append('    </message>')
        lines.append('</context>')
    lines.append('</TS>')
    open(path, "w").write("\n".join(lines) + "\n")

cpp_keys = scan_cpp()
qml_ctx = scan_qml()
missing = []
for k in sorted(cpp_keys | set().union(*qml_ctx.values())):
    if k not in T:
        missing.append(k)

contexts = [("QObject", cpp_keys)] + list(qml_ctx.items())
for lang in LANGS:
    write_ts("assets/translations/bbxshare_%s.ts" % lang, lang, contexts)
    print("scritto", lang)

if missing:
    print("CHIAVI SENZA TRADUZIONE:", len(missing))
    for k in missing: print("  >>", repr(k))
else:
    print("tutte le chiavi tradotte")
