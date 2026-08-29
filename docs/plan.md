# BBX Share — piano

Obiettivo: scambio file BB10 <-> Android Quick Share, app nativa Cascades.

La parte di protocollo è stata implementata in C++ per BB10 prendendo come
riferimento la documentazione pubblica di [NearDrop](https://github.com/grishka/NearDrop)
e l'implementazione di [rquickshare](https://github.com/Martichou/rquickshare).
Non vengono inclusi nel progetto sorgenti Rust, dipendenze Cargo o file `.proto`
di quei repository; vedere `NOTICE.md` per provenienza e licenze.

## Protocollo

Quick Share (ex Nearby Share) è reverse-engineered in progetti open source di riferimento:

- NearDrop (Swift) — ricezione su macOS/desktop.
- rquickshare (Rust) — send/receive su Linux/macOS.

Punti chiave del protocollo:

1. Discovery: BLE advertisement (dati manufacturer Google) + mDNS `_FC9F5ED42C8A._tcp` sulla LAN.
2. Handshake/chiavi: protobuf + UKEY2 con ECDH P-256 effimero.
3. Trasferimento: payload cifrati sul canale negotiated (Wi-Fi/LAN).

Vincolo BB10: l'API pubblica può scansionare gli advertisement BLE ma non impostare il payload service-data Quick Share richiesto da Android. BBX Share ascolta quindi FE2C/FEF3 per rilanciare subito l'annuncio mDNS; il trasferimento resta sulla LAN Wi-Fi. La cifratura del protocollo usa primitive OpenSSL userspace e il codec protobuf minimale locale.

## Fasi

1. **mDNS proof** — COMPLETATA lato host (2026-08-28):
   - `src/ShareService.cpp`: responder mDNS (UDP 5353, gruppo 224.0.0.251) che risponde
     a PTR/SRV/TXT/A per `_FC9F5ED42C8A._tcp.local`, + annunci periodici (TTL 120s),
     + listener TCP con porta effimera advertised in SRV.
   - identità host/istanza casuali e valide per ogni avvio, probe anti-collisione,
     cache passiva PTR/SRV/TXT/A con scadenza TTL, goodbye TTL=0 e query di
     completamento rate-limited per record frammentati.
   - heartbeat mDNS ogni 4 secondi, burst all'avvio/ricerca e rilancio immediato
     quando lo scanner BLE BB10 rileva Quick Share FE2C/FEF3; risposte QU unicast
     e TTL multicast 255 per maggiore compatibilità con Pixel recenti.
   - Costruzione record conforme a NearDrop PROTOCOL.md: nome istanza = base64url
     di `0x23 | endpoint ID (4 char ASCII) | FC 9F 5E | 00 00`; TXT `n=` = base64url
     di `(deviceType<<1) | 16 byte random | nome length-prefixed`.
   - Test host `test/test_mdns.cpp` (compila con Qt6Core su Linux, porta mDNS
     parametrizzata per evitare avahi/resolved): query PTR -> risposta con TXT `n=`
     decodificabile e nome device atteso, SRV con porta > 0. 5/5 pass.
     La compilazione richiede il setup host/BBNDK e un MOC compatibile; il
     comando usato durante lo sviluppo è annotato nei sorgenti del test.
   - Verifica indipendente: `dig @127.0.0.1 -p <porta> _FC9F5ED42C8A._tcp.local PTR`.
   - Restante per chiudere la fase: installazione BAR sul device e comparsa reale
     nel menu Quick Share del telefono (stessa Wi-Fi).
2. **Ricezione** — COMPLETATA end-to-end su Q10 (2026-08-28):
   - `ProtoWire`: codec protobuf wire-format minimale, con controllo dei limiti e
     test host dedicato; non richiede una libreria protobuf assente dal sysroot.
   - `QuickShareSession`: handshake server UKEY2, ECDH P-256 OpenSSL, verifica
     commitment SHA-512, HKDF-SHA256, AES-256-CBC, HMAC-SHA256 e sequence number.
   - scambio PairedKeyEncryption/PairedKeyResult, parsing Introduction, consenso
     esplicito con nome dispositivo/allegati/PIN e keep-alive durante l'attesa.
   - ricezione streaming di file e payload testo in
     `/accounts/1000/shared/downloads/BBXShare`, nomi sanificati, collisioni gestite,
     progress UI e rimozione dei file parziali in caso di errore; verifica preventiva
     di directory scrivibile/spazio libero, limiti su frame e buffer, timeout di
     inattività e confronto HMAC constant-time.
   - riferimenti di protocollo: [NearDrop PROTOCOL.md](https://github.com/grishka/NearDrop/blob/master/PROTOCOL.md)
     e [rquickshare](https://github.com/Martichou/rquickshare); nessuna libreria dei due progetti viene inclusa nel BAR.
   - verificati: build ARMv7, test codec protobuf, deploy su device di sviluppo,
     processo vivo, advertisement mDNS risolto su LAN e listener TCP raggiungibile.
   - verificati sul device: comparsa in Quick Share Android, conferma PIN,
     accettazione sul Q10, ricezione e apertura del file salvato.
3. **Invio** — COMPLETATA con la versione `0.4.1.1` (verificata su Android reale 2026-08-29):
   - invoke target applicazione `dev.bbos10.BBXShare.share` per `bb.action.SHARE`
     e URI `file://`, così BBX Share compare nel menu Condividi nativo;
   - File Picker Cascades multi-selezione e coda UI di uno o più file in uscita;
   - discovery mDNS dei receiver vicini con query a burst, cache dei record
     frammentati e annunci periodici; elenco selezionabile con nomi leggibili e
     nuova risoluzione SRV/TXT mirata prima di avviare ogni invio;
   - handshake Quick Share client UKEY2, PIN locale visibile, consenso remoto e
     streaming cifrato AES-256-CBC/HMAC-SHA256 verso il device scelto;
   - ordine handshake corretto includendo la ConnectionResponse in chiaro prima
     del canale cifrato e disconnessione finale conforme al protocollo;
   - payload ID unici per allegato, chunk da 64 KiB, deadline globale e gestione
     della cancellazione/keep-alive del peer durante lo streaming;
   - test end-to-end locale multi-file superato su 716.863 byte complessivi,
     verificati byte per byte;
   - test bidirezionale con Android reale superato (2026-08-29): invio e ricezione
     di una immagine da 2 MB senza errori di protocollo o integrità;
   - restante: solo il vincolo strutturale di discovery BLE (nessun advertisement
     payload Quick Share da BB10, visibilità via rilancio mDNS).
   - peer BBX Share omonimi non vengono più scartati: il nome annunciato include
     il suffisso del dispositivo e l'autofiltro usa esclusivamente l'IP locale,
     rendendo possibile BB10 ↔ BB10 sulla stessa Wi-Fi.
   - la ripresa byte-range tra sessioni diverse non è prevista dal flusso Quick
     Share interoperabile implementato: un trasferimento interrotto viene pulito
     e può essere ritentato dall'inizio.
4. **UX** — seconda espansione completata con la versione `0.4.0.1`:
   - interfaccia Cascades dark coerente con Q10;
   - Action Bar nativa inferiore con Attività, Ricevi e Invia; rimossi title bar
     branded e pannello diagnostico superiore;
   - cronologia cancellabile e tappabile: un file ricevuto invoca il File Manager
     sulla cartella, con fallback al viewer associato al file;
   - guida contestuale, stato ricezione compatto, progress bar e card di consenso;
   - stringhe C++ decodificate esplicitamente come UTF-8 e accenti QML espressi
     con escape Unicode per evitare mojibake sulla toolchain legacy.
   - fallback lingua esplicito su inglese per ogni locale non supportato;
     l'italiano non viene più selezionato come fallback implicito.

## Workflow

```bash
cd "<Native BBOS 10 workspace>"
source env.sh
./scripts/build.sh projects/BBXShare debug
./scripts/package.sh projects/BBXShare
./scripts/verify-bar.sh projects/BBXShare/BBXShare.bar
```

Permessi bar-descriptor: `run_native`, `access_shared`.

## Firma

L'app non potrà mai essere firmata ufficialmente: BlackBerry ha chiuso i server
di signing e la trust chain originale non è più disponibile. Il BAR resta quindi
unsigned e l'installazione avviene solo via sideload su device rooted/trust-bypassed.
