# BBX Share — provenance and third-party notices

## Scope of this notice

This notice records the external projects consulted while implementing the
Nearby Share / Quick Share interoperability layer. It is intentionally
explicit about the difference between using a protocol description and
copying source code.

The current BBX Share tree contains C++/Qt code, QML, tests, and BlackBerry
10 packaging metadata. A source scan found no Rust source, Cargo manifest,
vendored dependency, or binary imported from `rquickshare`.

## rquickshare

- Project: [Martichou/rquickshare](https://github.com/Martichou/rquickshare)
- License: [GNU GPL version 3](https://github.com/Martichou/rquickshare/blob/master/LICENSE)
- Reference snapshot consulted locally: commit
  [`378d8ae969941bee4bf60ad34ac9cf8bb7005eb7`](https://github.com/Martichou/rquickshare/commit/378d8ae969941bee4bf60ad34ac9cf8bb7005eb7)
- Relevant implementation references:
  - [mDNS discovery](https://github.com/Martichou/rquickshare/blob/378d8ae969941bee4bf60ad34ac9cf8bb7005eb7/core_lib/src/hdl/mdns_discovery.rs)
  - [inbound protocol handler](https://github.com/Martichou/rquickshare/blob/378d8ae969941bee4bf60ad34ac9cf8bb7005eb7/core_lib/src/hdl/inbound.rs)
  - [outbound protocol handler](https://github.com/Martichou/rquickshare/blob/378d8ae969941bee4bf60ad34ac9cf8bb7005eb7/core_lib/src/hdl/outbound.rs)
  - [protocol message definitions](https://github.com/Martichou/rquickshare/tree/378d8ae969941bee4bf60ad34ac9cf8bb7005eb7/core_lib/src/proto_src)

BBX Share used rquickshare as a reference for the protocol state machine,
Nearby Share message layout, mDNS behavior, UKEY2 labels, key derivation
labels, encrypted payload framing, and interoperability debugging. These
references were reimplemented in C++ and are not a port of the Rust source.
The rquickshare README also credits [NearDrop](https://github.com/grishka/NearDrop)
and [QNearbyShare](https://github.com/vicr123/QNearbyShare) as upstream
projects in its own development history.

If a future commit copies or ports GPL-covered rquickshare implementation
code, it must keep the upstream copyright/license notices, clearly mark the
modifications and relevant date, provide the corresponding source, and keep
the resulting derivative work under GPLv3. Interactive distributions must
also provide the applicable GPL legal notices. This repository is already
licensed GPL-3.0-only so that future changes do not silently introduce an
incompatible license.

## NearDrop

- Project: [grishka/NearDrop](https://github.com/grishka/NearDrop)
- Protocol notes: [PROTOCOL.md](https://github.com/grishka/NearDrop/blob/master/PROTOCOL.md)
- License: [The Unlicense](https://github.com/grishka/NearDrop/blob/master/UNLICENSE)

NearDrop was consulted for the reverse-engineered Wi-Fi LAN protocol,
including the service name, endpoint-info structure, UKEY2 exchange,
encrypted message layers, payload framing, and the documented limitations of
the interoperability path. No NearDrop source file is included in BBX Share.

## Chromium / Google protocol material

NearDrop documents that some protobuf definitions were collected from
Chromium sources. BBX Share does not redistribute those `.proto` files or
Chromium code; it uses a small hand-written wire-format codec and the field
layouts needed for the interoperability implementation. Google, Android,
Nearby Share, and Quick Share remain third-party names and trademarks.

## BlackBerry/QNX and OpenSSL

The application links against the BlackBerry Native SDK/QNX and OpenSSL
facilities available in the target SDK. The SDK, target sysroot, Java runtime,
and system libraries are not included in this repository and remain subject
to their own terms. Do not publish the local SDK or generated BAR artifacts as
part of this source repository.
