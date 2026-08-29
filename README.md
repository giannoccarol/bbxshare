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

- mDNS discovery and advertisement for the Nearby Share Wi-Fi LAN service are
  implemented;
- the BB10 receiver implements the UKEY2 handshake, ECDH P-256 key exchange,
  PIN confirmation, encrypted payload handling, and streamed file writes;
- the BB10 sender can discover a receiver, negotiate the encrypted channel,
  request consent, and stream a selected file;
- the locally built host test binaries pass for the protobuf codec, mDNS
  responder, and a 716,837-byte encrypted sender/receiver transfer;
- development notes record a successful receive flow on a Q10;
- the final bidirectional test with a real Android Quick Share sender remains
  open.

The project does not implement the Bluetooth advertisement path. Both devices
must be on a network that permits local mDNS and TCP traffic.

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
