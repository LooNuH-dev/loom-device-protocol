# Loom Device Protocol

**Version 1.1.0 — draft. Licence of the reference library: Apache-2.0. Version 1 may change before it is declared stable.**

This document describes what a device needs to take part in a Loom network:
how it is found, how it pairs, how two paired devices prove themselves to each
other, and how one device asks another to search, read a link and provide
track files. It describes the wire only. Anything not written here is not part
of the protocol, including names of types in any implementation.

Loom's own apps speak more than this to each other (playback, their libraries,
their lists). Those messages are not part of this protocol. A device that
implements only this protocol never needs them, and ignores them if it
receives them (1.3).

Words: a **device** is anything that speaks this protocol. The **initiator** of
a connection is the device that opened it; the **responder** accepted it and
is the TLS server. Neither role says anything about what a device holds or can
do.

---

## 1. General rules

1. **JSON only**, UTF-8 without a byte-order mark. No binary serialisations.
2. **Field names are fixed** as written here.
3. **Byte order is explicit**: lengths are big-endian.
4. **Unknown is not an error.** An unknown message `type`, an unknown field,
   an unknown feature token or capability name is skipped. This is what lets
   versions coexist.
5. **Fields that do not apply are absent**, not `null`.

### 1.1 Versions

Two numbers say what a device speaks:

| Name | Where | Meaning |
|---|---|---|
| `versions` | `hello`, TXT record | The major versions of **this** protocol the device implements, e.g. `[1]`. This document is major version 1. |
| `proto` | `hello`, TXT record | The wire generation. Always `1` for this document. It moves only on a break nobody could talk across. |

Within a major version, additions are announced as feature tokens (`features`,
3.3) and do not change either number.

**Negotiation.** Each device takes the other's `versions` (from `hello`, or
earlier from the TXT record) and uses the **highest version both name**. If
they share none, the connection carries nothing after `hello` and is closed.
A Loom build that predates `versions` sends none; it is read as `[1]`.

The reference library's own version follows Semantic Versioning; its major is
the protocol major.

### 1.2 Feature tokens

| Token | Meaning |
|---|---|
| `open1` | Implements major version 1 of this protocol. Sent beside `versions`. |
| `peer1` | Equal devices: no device is a host. Required for version 1. |
| `auth1` | Proves the pair's secret on the control channel (`auth`, 3.4). Required. |
| `pairing2` | Pairs by a typed code, version 2 (5). Required. |

### 1.3 Capabilities

What a device does for others. Missing capabilities are limits of a platform,
not roles: a device without one may ask a device that has it.

| Name | Meaning |
|---|---|
| `acquire` | The device answers a search, reads links, and provides the track files it fetches for them (7). |
| `serveData` | The device's data channel (6) is up now. |
| `noPlayback` | The device plays nothing and takes no transport control. Others must not offer it as a place to play, steer its playback, or add it to a shared listening session. A device that does not say it is taken to play, as before. |

Other names may appear; they are skipped.

---

## 2. Discovery

Every device, while it can accept connections, **both** advertises itself and
browses for others, over multicast DNS service discovery (RFC 6762, RFC 6763).

- Service type: `_loom._tcp`.
- A device that stops listening (for example, put in the background) simply
  disappears from others' lists. That is not an error.

TXT record (each value at most 200 bytes):

| Key | Type | Meaning |
|---|---|---|
| `proto` | integer | Wire generation, `1` |
| `device` | string | Display name |
| `deviceid` | string | Stable identifier: the same across restarts, renames and address changes |
| `class` | string | `desktop`, `android` or `ios`; decides who shows the pairing code (5.1). An unknown value is read as `desktop` |
| `versions` | list | Protocol majors, comma-separated: `1` |
| `caps` | list | Capabilities, comma-separated: `acquire,serveData` |
| `tracks`, `rev`, `playing` | — | Used by Loom's own apps; other devices may omit them and should ignore them |

A record without `proto`, `device` or a non-empty `deviceid`, or with a value
over 200 bytes, is not shown.

**Finding a device to ask.** A device that wants a search, a link or a track
file sent to it may ask any paired device whose record says a shared
`versions` entry and the capability `acquire`, whatever its class. Discovery
grants no trust: anyone on the network can publish a record. Trust comes only
from pairing (5).

**One connection per pair.** Each device connects to each paired device it
sees. When two connected to each other at once, after the `hello` exchange the
connection whose initiator has the smaller `deviceid` (byte-wise UTF-8) stays;
its responder closes the other.

---

## 3. Control channel

One long-lived TCP connection over TLS (6.3) per pair. Messages flow both ways
at either side's initiative.

### 3.1 Framing

```
+--------------------+--------------------------+
| length: UInt32 BE  | body: JSON, UTF-8        |
| 4 bytes            | exactly "length" bytes   |
+--------------------+--------------------------+
```

- The length counts the body only.
- The largest body is **8 MiB**. A larger length closes the connection before
  any memory is allocated for it. A body of length 0, or one that is not a
  JSON object with a string `type`, closes it too.
- TCP is a stream: one message may arrive in pieces, several in one piece.

### 3.2 Envelope

```json
{ "type": "hello", "id": "m1", "replyTo": "m0", "ok": true, "payload": { } }
```

| Field | Required | Meaning |
|---|---|---|
| `type` | yes | Kind of message |
| `id` | no | The message's identifier; present when an answer is expected |
| `replyTo` | no | The `id` being answered |
| `ok` | no | Whether the request succeeded; answers only |
| `payload` | no | Kind-specific content |

A request that gets no answer within the time the asker allows is treated as
unanswered; the asker says so to its user.

### 3.3 `hello`

The first message each side sends on every connection.

| Field | Required | Meaning |
|---|---|---|
| `proto` | yes | `1` |
| `deviceId` | yes | As in the TXT record; at most 200 bytes |
| `deviceName` | no | Display name |
| `class` | yes | As in the TXT record |
| `versions` | yes | Protocol majors, array of integers |
| `features` | yes | Feature tokens (1.2), array of strings |
| `caps` | yes | Capabilities (1.3), array of strings; may be empty |
| `dataPort` | no | Port of the data channel (6); absent or `0`: none now |
| `nonce` | yes | 16 fresh random bytes, base64, new on every connection |

Readers take at most 64 `features` and 64 `caps` entries of at most 64 bytes
each, and at most 16 `versions`; the rest is ignored.

Other fields may be present (Loom's own apps send some); they are ignored.

Example:

```json
{ "type": "hello", "id": "m1",
  "payload": { "proto": 1, "deviceId": "A3F2…", "deviceName": "Studio",
               "class": "desktop", "versions": [1],
               "features": ["auth1", "open1", "pairing2", "peer1"],
               "caps": ["acquire", "serveData"], "dataPort": 52311,
               "nonce": "q8pR…" } }
```

### 3.4 `auth`

On receiving the other side's `hello`, each side sends:

```json
{ "type": "auth", "payload": { "proof": "<base64 HMAC-SHA256>" } }
```

```
proof = HMAC-SHA256(pair secret,
          "Loom auth v1" ‖ len16(sender deviceId) ‖ len16(receiver deviceId)
          ‖ initiator nonce ‖ responder nonce
          ‖ len16(SHA-256 of the responder's certificate))
```

`‖` is byte concatenation; `len16(x)` is the length of `x` as UInt16 BE
followed by `x`; strings are UTF-8; nonces are the decoded 16 bytes.

The sender's id comes first, so one side's proof cannot be returned to it. The
responder's certificate fingerprint binds the proof to this TLS session. A
proof that does not hold, or a `hello` naming a device with no pair secret,
closes the connection.

**Until the other side's `auth` holds, a device acts on nothing but `hello`,
`auth` and the pairing messages (5).** A responder may hold messages that
arrive in the meantime and act on them once `auth` holds; it closes the
connection if anything but pairing arrives before `hello`, if it is made to
hold more than 256 messages or 8 MiB, or if no proof arrives within 30 s
(120 s while pairing).

---

## 4. Message kinds

| `type` | Section |
|---|---|
| `hello` | 3.3 |
| `auth` | 3.4 |
| `pairingOffer`, `pairingCommit`, `pairingReveal`, `pairingCheck`, `pairingConfirm` | 5 |
| `serviceSearch`, `serviceFetch`, `linkLookup`, `linkAction`, `fetchReady`, `fetchDone` | 7 |

Every other `type` is outside this protocol and is ignored.

---

## 5. Pairing

Pairing happens once. Afterwards, each side keeps three things about the
other: its `deviceId`, the SHA-256 of its TLS certificate, and a 32-byte pair
secret. A certificate change on either side requires pairing again.

Pairing runs on a control connection before `auth`, so the TLS client accepts
any certificate on that one connection and reports its fingerprint; the
exchange below binds the result to it.

### 5.1 Who shows the code

Order of classes: `desktop`, `android`, `ios`. The device whose class comes
earlier **shows** the code (S); the other **enters** it (E). With equal
classes, the initiator shows.

### 5.2 Exchange (version 2)

A typed six-digit code used as a password, proved bit by bit (the passkey
method of short-range wireless pairing), with HMAC-SHA256. It needs ECDH on
P-256, SHA-256, HMAC and HKDF only.

Notation: I initiator, R responder, `pk` a raw P-256 public key (64 bytes,
X ‖ Y), `fp` SHA-256 of a certificate. Binary fields in JSON are base64.

1. **Keys.** I → R: `pairingOffer` with `version: 2`, `publicKey`,
   `deviceId`, `deviceName`, `class`, `fingerprint` (its `fp`). R → I: the
   same fields without `fingerprint`. A side that cannot take the role it is
   given answers `pairingConfirm` with `ok: false`.

   ```
   T = "Loom pairing v2" ‖ len16(fp_R) ‖ len16(fp_I) ‖ len16(pk_R) ‖ len16(pk_I)
       ‖ len16(id_R) ‖ len16(id_I) ‖ len16(class_R) ‖ len16(class_I)
   ```

2. **Code.** S picks a uniformly random `r` in 0…999 999 and shows it as six
   digits. The person types it on E. A new `r` for every attempt.

3. **Twenty rounds**, `i` = 0…19, one per bit `r_i = (r >> i) & 1`:
   - E sends `pairingCommit { "round": i, "commit": C_E }` with fresh 16-byte
     `n_E`;
   - S answers with its own `pairingCommit` (`C_S`, fresh `n_S`);
   - E sends `pairingReveal { "round": i, "nonce": n_E }`; S recomputes `C_E`
     with its `r_i` and stops on a mismatch;
   - S sends `pairingReveal` with `n_S`; E checks `C_S` the same way.

   ```
   C_E = HMAC-SHA256(key n_E, 0x45 ‖ pk_E ‖ pk_S ‖ T ‖ i ‖ (0x80 | r_i))
   C_S = HMAC-SHA256(key n_S, 0x53 ‖ pk_S ‖ pk_E ‖ T ‖ i ‖ (0x80 | r_i))
   ```

   `i` is one byte. A message out of turn stops the exchange.

4. **Secret and check.** `Z` is the ECDH shared secret (X coordinate).

   ```
   secret = HKDF-SHA256(Z, salt = n_E(19) ‖ n_S(19), info = T ‖ r as UInt32 BE, 32 bytes)
   mac_E  = HMAC-SHA256(key secret, "check" ‖ 0x45 ‖ T)
   mac_S  = HMAC-SHA256(key secret, "check" ‖ 0x53 ‖ T)
   ```

   E sends `pairingCheck { "mac": mac_E }`; S verifies, keeps the pair, and
   answers `pairingCheck` with `mac_S` and `pairingConfirm` with `ok: true`.
   E verifies and keeps the pair. Nothing is kept on a `pairingConfirm` alone.

**Wrong code.** S sends `pairingConfirm` with `ok: false` and
`{ "reason": "codeMismatch", "retry": true }`, and shows a **new** code. After
three misses it sends `retry: false` and stops. A device closes a connection
that sends more than 160 pairing messages.

---

## 6. Data channel

HTTP/1.1 over TLS, on the port named by `hello.dataPort`. Connections are kept
open between requests.

### 6.1 Routes in this protocol

| Method | Path | Meaning |
|---|---|---|
| `GET` | `/api/variant/{id}` | A track file. Single byte ranges: `bytes=a-b`, `bytes=a-`, `bytes=-n` |
| `POST` | `/api/import` | Send a track file to the device. Body streamed; `Content-Length` required, at most 2 GiB; headers `X-Loom-Filename` (a hint; only its last component is used) and `X-Loom-Content-SHA256` (signed digest of the body). Answer `200` once the file is taken in, `415` if it is not audio, `503` when the device cannot take files now |

Other paths on the same port belong to Loom's own apps and are outside this
protocol; they are signed the same way (6.2).

Limits a device applies: a request head of at most 64 KiB; a buffered body of
at most 1 MiB on these routes; a `Content-Length` of digits only, and two
`Content-Length` headers must agree; at most 6 open connections per address
and 64 in total.

### 6.2 Signed requests

**Every request** is signed with the pair secret. There are no unsigned routes,
including from the same machine.

| Header | Value |
|---|---|
| `X-Loom-Device` | The client's `deviceId` |
| `X-Loom-Date` | Milliseconds since the Unix epoch |
| `X-Loom-Signature` | HMAC-SHA256, base64 |

```
signed = "Loom request v1\n" + METHOD + "\n" + target + "\n" + date + "\n" + SHA-256(body)
```

`target` is the path with its query, parameters sorted by name. For
`/api/import`, `SHA-256(body)` is the digest declared in
`X-Loom-Content-SHA256`; the receiver checks the arrived file against it and
discards it on a mismatch.

Clocks may differ by up to **5 minutes** either way. A request that changes
something (not `GET`) is accepted once: a repeat of the same signature within
the window is refused.

An unsigned or wrongly signed request answers `401`.

### 6.3 TLS

- Every device has a self-signed certificate. TLS 1.2 or later.
- The TLS client checks that the server's leaf certificate's SHA-256 equals
  the fingerprint kept at pairing; chains and authorities are not consulted.
- The TLS server learns who the client is from `auth` (3.4) and from request
  signatures (6.2); no client certificates are used.
- There is no fallback to an unencrypted connection.

---

## 7. Search, links and track files

A device without `acquire` may ask a paired device that has it. Every kind
here is a request with `id` and an answer with `replyTo`.

### 7.1 `serviceSearch`

Request: `{ "query": "<free text>" }`.

Answer: `results` — at most 15 rows, best first; optional `albums` (at most 3
rows) and `artists` (at most 2 rows); optional `failure` (why some sources did
not answer) and `searched` (names of the sources that answered). Source names
are display text chosen by the answering device.

A row:

| Field | Meaning |
|---|---|
| `title`, `channel` | What the row is called and a second line |
| `durationMs` | Length, if known |
| `provider` | An opaque token naming where the row came from; sent back unchanged |
| `sourceID` | An opaque identifier of the row at that source; sent back unchanged |
| `kind` | `track` (default), `album`, `playlist` or `artist` |
| `isBest`, `inLibrary`, `confidence`, `quality`, `alsoOn`, `why`, `step` | Optional hints for display |

### 7.2 `serviceFetch`

Request: `{ "provider": …, "sourceID": … }` from a row. Answer: `ok: true`
and `fetchId` (an opaque string naming this fetch) when the answering device
has taken the fetch, or `ok: false` and `reason`. The file follows as in 7.5.

### 7.3 `linkLookup`

Request: `{ "link": "<text the user pasted>" }`. Answer: `card` with `url`,
optional `platform` (an opaque token), `kind` (`track`, `album`, `playlist`,
`artist`), `title`, `subtitle`, `artworkURL`, `trackCount`, `inLibraryCount`,
`items` (at most 50: `title`, `artist`, `durationMs`, `inLibrary`, optional
`sourceID`) and `actions` (`download`, `importPlaylist`, `addToLibrary`;
unknown values skipped); or `ok: false` and `failure`.

### 7.4 `linkAction`

Request: `url` from the card, `action`, optional `only` (array of `sourceID`
to limit a `download`) and `folderID`. Answer: `ok: true` and `done` (a line
saying what was done), or `ok: false` and `reason`.

### 7.5 Track files and handover

The requester learns the file from the acquisition itself, never from a
library listing:

1. **Fetch.** `serviceFetch` → answer with `fetchId` (7.2).
2. **Ready.** When the file exists, the acquiring device sends
   `fetchReady` (a request with `id`):

   ```json
   { "type": "fetchReady", "id": "m9", "ok": true,
     "payload": { "fetchId": "F1", "fileId": "v-42", "bytes": 8123456,
                  "sha256": "<base64>", "format": "flac" } }
   ```

   `fileId` is 1–128 characters of `[A-Za-z0-9._-]`, not `.` or `..`. On
   failure: `ok: false`, no `fileId`, and `reason`.
3. **Hand over.** The requester reads `GET /api/variant/{fileId}` (6.1),
   resuming with `Range` as needed, and checks `bytes` and `sha256`.
4. **Confirm.** The requester sends `fetchDone` with `fetchId` and `fileId`:
   `ok: true` once it holds the file, `ok: false` to give it up. The
   acquiring device answers with `replyTo` and `ok: true`.
5. **Delete.** The acquiring device may then delete the file.

A file waiting for its requester is readable only by the device that asked
for it. `fetchDone` from any other device, or naming another `fetchId`, is
ignored.

**A device that keeps no library.** An acquiring device need not keep what
it fetches. Such a device holds each file only from step 2 to step 5 and then
deletes it. A file whose requester has not confirmed within 24 hours is
deleted too, and a device may hold at most a bounded number of waiting files
(the reference library: 256, oldest first). A requester that reads a deleted
file gets `404` and may ask again with `serviceFetch`.

A device that does keep a library may keep the file after step 5; the
exchange is the same.

---

## 8. Changes

See CHANGELOG.md beside this document.
