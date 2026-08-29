# BBX Share

BBX Share is an unofficial native BlackBerry 10 application for exchanging
files with Android devices that support Google Nearby Share / Quick Share.
It targets the Wi-Fi LAN path and is implemented with C++, Qt/Cascades,
QNX sockets, OpenSSL primitives, and a small protobuf wire-format codec.

This is an experimental community project. It is not affiliated with,
endorsed by, or sponsored by BlackBerry Limited or Google LLC. “BlackBerry”,
“Android”, “Nearby Share”, and “Quick Share” are the property of their
respective owners.

## App icon

<p align="center">
  <img src="assets/images/bbxshare-icon-144.png" width="144" alt="BBX Share app icon">
</p>

The BBX Share icon uses three connected nodes to suggest sharing and device-
to-device transfer, with a subtle geometric “B” in the negative space. Its
dark graphite, navy, cyan, and blue palette takes inspiration from the crisp,
layered visual language of BlackBerry 10 while remaining an original mark.

The BAR descriptor includes platform-specific icon assets for the common BB10
smartphone resolutions:

| Device display | Icon asset |
| --- | ---: |
| 720 × 720 | 90 × 90 px |
| 720 × 1280 | 96 × 96 px |
| 768 × 1280 | 110 × 110 px |
| 1440 × 1440 | 144 × 144 px |

The source artwork is kept in `assets/images/`, while the descriptor exposes
the matching sizes to the BB10 launcher and package metadata.

## Current status

As of 2026-08-29:

- the sender includes the Quick Share `NEARBY_SHARE` use case, a non-zero
  attachment id, and image/video/audio/app classification for strict Android
  receivers;
- the sender negotiates and drains the safe-disconnect handshake when the peer
  advertises it, avoiding false success caused by closing TCP before Android
  finishes committing the received file;
- mDNS discovery and advertisement for the Nearby Share Wi-Fi LAN service are
  implemented, with expiring record caches, follow-up queries, unique local
  identities, collision probing, and graceful service shutdown;
- Android Quick Share BLE advertisements are observed on BB10 and trigger an
  immediate mDNS re-announcement; a four-second mDNS heartbeat and short burst
  cover Pixel devices that do not actively repeat their PTR query;
- the BB10 receiver implements the UKEY2 handshake, ECDH P-256 key exchange,
  constant-time authentication checks, PIN confirmation, bounded encrypted
  payload handling, storage preflight, and streamed file writes;
- the BB10 sender can discover a receiver, display the verification PIN,
  negotiate the encrypted channel, request consent, send one or more selected
  files, and react to peer cancellation during streaming;
- the locally built host tests pass for the protobuf codec, mDNS responder,
  and a 716,863-byte encrypted two-file sender/receiver transfer;
- development notes record a successful receive flow on a Q10;
- the final bidirectional test with a real Android Quick Share sender remains
  open.

The project listens for the Quick Share BLE service as a discovery wake-up but
cannot publish Quick Share's custom BLE service-data payload through the public
BB10 API. Both devices must therefore remain on a network that permits local
mDNS and TCP traffic.

## Supported transfers

| Direction | Payload | Current support |
| --- | --- | --- |
| Android Quick Share -> BB10 | One or more files | Supported by the receiver; original names and extensions are preserved. |
| Android Quick Share -> BB10 | Shared text | Supported; each text payload is saved as a dated `.txt` file. |
| BB10 -> Android Quick Share | One or more local files | Supported by the sender after file and nearby-device selection. |
| BB10 -> BB10 | One or more files in either direction | Supported when BBX Share is open on both devices and both are on the same LAN. |

Outgoing files are not restricted by extension. JPEG, PNG, GIF, MP4/M4V,
MP3/M4A, PDF, TXT, and LOG receive a specific MIME type; every other regular
file is sent as `application/octet-stream`. The sender and receiver support a
multi-file introduction and use a distinct non-zero payload ID for every file.
Received items are written incrementally to
`/accounts/1000/shared/downloads/BBXShare`, and name collisions create a new
numbered file instead of overwriting an existing one. Before consent, the
receiver verifies that the destination is writable and has enough free space.

Folder transfer, Wi-Fi credentials, structured contacts, and specialized
clipboard payloads are not implemented. An incoming Quick Share text or URL is
stored as plain text rather than dispatched to another application. Android
interoperability remains experimental because Quick Share behavior varies
between device and OS versions.

## Technical flow

Discovery uses the `_FC9F5ED42C8A._tcp.local` service over IPv4 mDNS. BBX Share
sends an initial announcement burst, repeats its announcement every four
seconds, answers multicast and QU unicast questions, and immediately announces
again when its BLE scanner observes Quick Share service UUID `FE2C` or `FEF3`.
Each process uses a randomized valid host/instance identity and probes for a
collision before announcing. Discovered PTR/SRV/TXT/A records are retained only
until their advertised TTL expires; incomplete records trigger throttled
follow-up queries instead of disappearing at the end of a scan window.
Android 17's anonymous 17-byte endpoint record is displayed as a friendly
device-type fallback instead of exposing its encoded identifier.

The file path uses a direct TCP connection on the advertised LAN port. Session
setup follows UKEY2 with ephemeral ECDH P-256, HKDF-derived keys, and a visible
four-digit verification PIN. Protocol messages use the project's small
protobuf wire codec; transferred frames are protected with
AES-256-CBC and HMAC-SHA256. File data is streamed in 64 KiB chunks so a whole
file does not need to fit in RAM and peer cancellation can be observed between
chunks. Global transfer and inactivity deadlines prevent stalled sessions from
remaining open indefinitely. The receiver validates payload IDs, offsets,
declared sizes, buffer limits, and completion flags before reporting success.

Interrupted transfers are cleaned up and can be retried, but byte-range resume
across a new Quick Share session is not part of the interoperable protocol flow
implemented by this project.

Bluetooth is currently only a discovery wake-up. The public BB10 Bluetooth API
does not expose the custom service-data advertisement required to reproduce the
complete Android BLE-first visibility path, so Wi-Fi must remain connected on
both devices.

The UI uses the device language when an English, German, French, Spanish, or
Dutch catalog is available. Unsupported locales, including Italian, fall back
to English.

## Repository contents

```text
BBXShare.pro          BB10 qmake project
bar-descriptor.xml    BAR manifest
src/                  C++ application and protocol implementation
assets/               Cascades/QML UI and icons
test/                 Host-side tests and test fixtures
docs/                 Development notes and protocol plan
```

Generated build output, BAR packages, object files, host test executables,
generated `moc_*.cpp` files, and SDK-specific Makefiles are intentionally not
part of the public source set. See `.gitignore`.

## Building in the Native BBOS 10 workspace

The BlackBerry Native SDK is a build prerequisite and is not redistributed in
this repository. The supported toolchain is BBNDK host `10.3.1.12`, target
`10.3.1.995`, architecture `armle-v7`, with the legacy Java runtime supplied
by the parent Native BBOS 10 workspace.

From the parent workspace:

```bash
source ./env.sh
./scripts/doctor.sh
./scripts/build.sh projects/BBXShare debug
./scripts/package.sh projects/BBXShare
./scripts/verify-bar.sh projects/BBXShare/BBXShare.bar
```

Do not commit the generated `arm/` directory or `BBXShare.bar`. They contain
machine-specific paths and, in the current working copy, debug information.

## Host tests

The tests are deliberately kept separate from the BB10 application target.
`test/test_proto.cpp` is a standalone host test. The mDNS and outbound tests
also compile application sources and therefore need the BBNDK headers and a
matching Qt/MOC setup; they are development tests, not yet a reproducible
fresh-clone CI target. None of the prebuilt test executables or generated MOC
sources is part of the public source set.

The end-to-end test uses `BBXSHARE_DOWNLOAD_DIR` to redirect received files to
a temporary directory. The application default is the BB10 shared downloads
directory.

## Provenance and third-party notices

The implementation was written in C++ for BB10. No Rust source file, Cargo
dependency, or binary from `rquickshare` is vendored in this repository. The
protocol implementation was informed by the publicly documented protocol and
message flow in [rquickshare](https://github.com/Martichou/rquickshare) and
[NearDrop](https://github.com/grishka/NearDrop). The exact attribution and
license analysis is in [`NOTICE.md`](NOTICE.md).

The protocol references do not make this application an official Google
client. The project should be treated as interoperability software and must
not imply access to Google services or private APIs.

## License

BBX Share is released under the GNU General Public License, version 3 only
(GPL-3.0-only). See [`LICENSE`](LICENSE).

This license choice is conservative: the current audit found protocol-derived
constants and independently written C++ code, but it keeps the project
compatible with the copyleft terms that would apply if GPL-covered
`rquickshare` implementation code were ever adapted. Any future port or copy
of upstream code must preserve its notices, identify modifications and dates,
and remain compliant with GPLv3.
