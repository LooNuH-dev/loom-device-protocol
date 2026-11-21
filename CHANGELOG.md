# Changelog

This package and PROTOCOL.md follow [Semantic Versioning](https://semver.org).
The major version is the protocol major that devices announce in `versions`.

## 1.2.0 — 2026-11-22 (draft, may change)

- A device may limit which peers it serves (PROTOCOL.md 1.4): `serves` in
  `hello` and the TXT record, by device class and optionally same device
  only (`ios;local`). Absent: serves everyone. Reference: `PeerFilter`,
  `serves(_:sameHost:)` on `PeerHello` and `PeerAdvertisement`;
  `mayAcquire(for:)` and `mayBeLegacyHost(of:)` respect it.
- `fetchReady` on success must carry `bytes` and `sha256` (PROTOCOL.md 7.5);
  `Handover.Ready` refuses one without them, or with a digest that is not
  32 bytes. Failures (`ok: false`) are unchanged.

## 1.1.0 — 2026-11-21 (draft, may change)

- Handover of fetched files (PROTOCOL.md 7.5): `serviceFetch` answers with
  `fetchId`; new kinds `fetchReady` (names the `fileId`) and `fetchDone`
  (the requester has it; the file may be deleted). Covers an acquiring device
  that keeps no library. Reference: `Handover`, `Handover.Ledger`.
- Capability `noPlayback` (PROTOCOL.md 1.3): a device that plays nothing and
  takes no transport control says so; others never offer it as a place to
  play. Reference: `mayPlay` on `PeerHello` and `PeerAdvertisement`.
- Licence: Apache-2.0 (was MIT).

## 1.0.0 — 2026-11-19 (draft, may change)

First version as its own package, carved out of Loom's shared core.

- Framing, envelope, `hello`, `auth`, discovery (TXT record), pairing
  version 2, signed data-channel requests, and the four request kinds for
  search, links and fetching (`serviceSearch`, `serviceFetch`, `linkLookup`,
  `linkAction`).
- New: `versions` in `hello` and in the TXT record, negotiated to the highest
  shared major; feature token `open1`; `caps` in the TXT record, so a device
  that can acquire is found before connecting.
- Hardening (see the security audit): bounded `hello` fields and TXT values,
  digits-only `Content-Length` and agreeing duplicates, a per-reader frame
  limit, and each signed write taken once (`ReplayGuard`).
