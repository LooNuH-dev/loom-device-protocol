# LoomDeviceProtocol

The reference library for the Loom Device Protocol: what a device needs to be
found by Loom's apps, pair with them, prove itself, and ask a paired device to
search, read a link or provide track files.

**Version 1.2.0, draft.** Version 1 may change before it is declared stable.
The specification is [PROTOCOL.md](PROTOCOL.md); changes are in
[CHANGELOG.md](CHANGELOG.md). Licence: Apache-2.0 ([LICENSE](LICENSE)).

## What is in it

| Area | Types |
|---|---|
| Versions and negotiation | `DeviceProtocol`, `WireProtocol`, `WireFeature` |
| Discovery | `PeerAdvertisement` (TXT record, `mayAcquire(for:)`) |
| Control channel | `MessageFraming`, `WireMessage`, `JSONValue`, `PeerHello`, `Capability` |
| Handing over fetched files | `Handover`, `Handover.Ledger` |
| Proving a paired device | `ControlAuth`, `RequestSignature`, `ReplayGuard` |
| Pairing | `PasskeyExchange`, `CodePairingRoute`, `PairingSecret`, `PairedDevice`, `TrustStoring` |
| Data channel | `HTTPRequest`, `HTTPRequestReader`, `HTTPResponse`, `HTTPByteRange` |

It holds no network code of its own: bring your own TCP, TLS and mDNS, and
feed bytes to the readers. Dependencies: Foundation and
[swift-crypto](https://github.com/apple/swift-crypto) (Apache-2.0). It builds
wherever Swift and swift-crypto do.

## Use

```swift
.package(path: "../loom-device-protocol")   // until it is published
```

```swift
import LoomDeviceProtocol

var reader = MessageFraming.Reader()
for message in try reader.read(bytesFromTheSocket) {
    if let hello = PeerHello(message), let version = hello.negotiatedVersion() {
        // speak `version`; send your own hello and then `auth`
    }
}
```

## Build and test

Swift 5.9 or later, on macOS or Linux:

```sh
swift build
swift test
```

## Implementing a device

You do not need this library to implement the protocol; PROTOCOL.md is the
contract. In order, a device:

1. **Is found** (PROTOCOL.md 2): advertises `_loom._tcp` with the TXT keys,
   including `versions` and `caps` (`acquire` if it searches and fetches;
   `noPlayback` if it plays nothing), and `serves` if it serves only some
   peers (1.4).
2. **Talks** (3): length-prefixed JSON over TLS, `hello` first, then `auth`
   once paired. Unknown kinds and feature tokens are ignored.
3. **Pairs** (5): the typed-code exchange, version 2; keeps the peer's
   certificate fingerprint and the shared secret.
4. **Serves or reads files** (6): signed HTTP requests on the data channel.
5. **Searches, reads links and fetches** (7), and hands fetched files over
   by `fetchReady` → `GET /api/variant/{fileId}` → `fetchDone` (7.5).

Run your implementation against this library's types (for example,
`MessageFraming.Reader`, `PeerHello`, `RequestSignature`) in tests to check
byte-for-byte agreement.

`ProtocolHardeningTests` throws malformed, truncated, oversized and random
input at every reader; the fuzz runs are seeded and repeatable.
