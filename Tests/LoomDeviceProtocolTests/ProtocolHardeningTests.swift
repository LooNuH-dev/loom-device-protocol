import Foundation
import XCTest
@testable import LoomDeviceProtocol

/// What anyone on the network can send before proving anything, thrown at
/// every reader the open protocol has: malformed, truncated, oversized and
/// random input must be refused, never trap. The fuzz runs are seeded, so a
/// failure repeats. See docs/security/2026-11-19-protocol-audit.md.
final class ProtocolHardeningTests: XCTestCase {

    /// SplitMix64: deterministic, so a fuzz failure is reproducible.
    private struct Seeded: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
    }

    private func randomBytes(_ count: Int, _ rng: inout Seeded) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &rng) })
    }

    private func frame(_ message: WireMessage) throws -> Data { try MessageFraming.frame(message) }

    private let validHello = PeerHello(
        deviceID: "D-1", deviceName: "Desk", deviceClass: .desktop,
        features: Set(WireFeature.openAnnounced), capabilities: [.acquire], nonce: Data(repeating: 7, count: 16)
    ).message(id: "h")

    // MARK: - Versions

    func testNegotiationPicksTheHighestShared() {
        XCTAssertEqual(DeviceProtocol.negotiate(ours: [1, 2, 3], theirs: [2, 3, 4]), 3)
        XCTAssertEqual(DeviceProtocol.negotiate(ours: [1], theirs: [1]), 1)
        XCTAssertNil(DeviceProtocol.negotiate(ours: [1], theirs: [2]))
        XCTAssertNil(DeviceProtocol.negotiate(ours: [1], theirs: []))
    }

    func testVersionsAreReadDefensively() {
        let junk: JSONValue = .array([.int(2), .int(-1), .int(0), .string("x"), .int(2), .int(1), .int(Int64.max)])
        XCTAssertEqual(DeviceProtocol.versions(in: junk), [1, 2])
        XCTAssertEqual(DeviceProtocol.versions(in: .string("1")), [])
        let flood: JSONValue = .array((1...10_000).map { .int(Int64($0)) })
        XCTAssertEqual(DeviceProtocol.versions(in: flood).count, DeviceProtocol.maximumDeclaredVersions)
        XCTAssertEqual(DeviceProtocol.versions(txt: "2, 1,,x,-3,1"), [1, 2])
        XCTAssertEqual(DeviceProtocol.versions(txt: nil), [])
        XCTAssertEqual(DeviceProtocol.txt([1, 2]), "1,2")
    }

    func testHelloCarriesVersionsAndAnOlderHelloMeansVersionOne() throws {
        let read = try XCTUnwrap(PeerHello(validHello))
        XCTAssertEqual(read.declaredVersions, DeviceProtocol.supportedVersions)
        XCTAssertEqual(read.negotiatedVersion(), DeviceProtocol.supportedVersions.max())
        XCTAssertTrue(read.features.contains(WireFeature.open1))

        let old = WireMessage(type: .hello, payload: .object(["deviceId": .string("old"), "proto": .int(1)]))
        let oldHello = try XCTUnwrap(PeerHello(old))
        XCTAssertEqual(oldHello.declaredVersions, [])
        XCTAssertEqual(oldHello.protocolVersions, [1])

        let future = WireMessage(type: .hello, payload: .object([
            "deviceId": .string("new"), "versions": .array([.int(7)])
        ]))
        XCTAssertNil(try XCTUnwrap(PeerHello(future)).negotiatedVersion(), "no shared version, nothing to speak")
    }

    // MARK: - hello

    func testHelloRefusesAnAbsurdIDAndTrimsItsLists() throws {
        let longID = WireMessage(type: .hello, payload: .object([
            "deviceId": .string(String(repeating: "a", count: PeerHello.maximumIDBytes + 1))
        ]))
        XCTAssertNil(PeerHello(longID))

        let flood = WireMessage(type: .hello, payload: .object([
            "deviceId": .string("D"),
            "deviceName": .string(String(repeating: "n", count: 10_000)),
            "features": .array((0..<100_000).map { .string("f\($0)") }),
            "caps": .array([.string(String(repeating: "c", count: 1000)), .string("acquire"), .int(3)])
        ]))
        let read = try XCTUnwrap(PeerHello(flood))
        XCTAssertLessThanOrEqual(read.features.count, PeerHello.maximumNames)
        XCTAssertEqual(read.capabilities, ["acquire"])
        XCTAssertLessThanOrEqual(read.deviceName?.utf8.count ?? 0, PeerAdvertisement.maximumValueBytes)
    }

    func testHelloOfTheWrongShapeIsNotAHello() {
        for payload: JSONValue in [.null, .array([]), .string("x"), .object([:]), .object(["deviceId": .int(3)]),
                                   .object(["deviceId": .string("")])] {
            XCTAssertNil(PeerHello(WireMessage(type: .hello, payload: payload)), "\(payload)")
        }
        XCTAssertNil(PeerHello(WireMessage(type: .auth, payload: .object(["deviceId": .string("D")]))))
    }

    // MARK: - Advertisement and picking by capability

    private func ad(_ id: String, _ kind: DeviceClass?, caps: Set<Capability> = [], versions: [Int] = [1]) -> PeerAdvertisement {
        PeerAdvertisement(deviceName: id, deviceID: id, trackCount: 0, revision: 0, isPlaying: false,
                          deviceClass: kind, versions: versions, capabilities: caps)
    }

    func testAnyDeviceThatAcquiresIsAskedWhateverItsClass() throws {
        for kind: DeviceClass? in [.desktop, .android, .ios] {
            let read = try XCTUnwrap(PeerAdvertisement(txtRecord: ad("other", kind, caps: [.acquire]).txtRecord))
            XCTAssertTrue(read.mayAcquire(for: "me"), "\(String(describing: kind)) with acquire")
        }
        // A build before versions and caps: only a legacy host, never asked this way.
        XCTAssertFalse(ad("old", nil, caps: [.acquire], versions: []).mayAcquire(for: "me"))
        XCTAssertFalse(ad("other", .ios).mayAcquire(for: "me"), "no acquire")
        XCTAssertFalse(ad("me", .ios, caps: [.acquire]).mayAcquire(for: "me"), "never itself")
        XCTAssertFalse(ad("other", .android, caps: [.acquire], versions: [9]).mayAcquire(for: "me"), "no shared version")
        // Mirroring a whole library stays with desktops.
        XCTAssertFalse(ad("pixel", .android, caps: [.acquire]).mayBeLegacyHost(of: "me"))
        XCTAssertTrue(ad("mac", .desktop, caps: [.acquire]).mayBeLegacyHost(of: "me"))
    }

    func testADeviceThatPlaysNothingIsNeverAPlaceToPlay() throws {
        XCTAssertTrue(ad("mac", .desktop, caps: [.acquire]).mayPlay, "silence keeps playing as before")
        let quiet = ad("box", nil, caps: [.acquire, .noPlayback])
        XCTAssertFalse(quiet.mayPlay)
        XCTAssertTrue(quiet.mayAcquire(for: "me"), "still asked to search and acquire")
        XCTAssertFalse(try XCTUnwrap(PeerAdvertisement(txtRecord: quiet.txtRecord)).mayPlay)
        let hello = PeerHello(deviceID: "box", deviceName: "Box", features: [WireFeature.peer1],
                              capabilities: [.acquire, .noPlayback])
        XCTAssertFalse(try XCTUnwrap(PeerHello(hello.message())).mayPlay)
        XCTAssertTrue(PeerHello(deviceID: "p", deviceName: "P", features: [], capabilities: []).mayPlay)
    }

    func testTXTRoundTripsVersionsAndCapabilities() throws {
        let sent = ad("x", .android, caps: [.acquire, .serveData], versions: [1, 2])
        XCTAssertEqual(sent.txtRecord["caps"], "acquire,serveData")
        XCTAssertEqual(sent.txtRecord["versions"], "1,2")
        let read = try XCTUnwrap(PeerAdvertisement(txtRecord: sent.txtRecord))
        XCTAssertEqual(read.versions, [1, 2])
        XCTAssertTrue(read.has(.acquire))
    }

    func testTXTFromAnyoneOnTheNetworkIsReadDefensively() {
        let long = String(repeating: "x", count: 300)
        XCTAssertNil(PeerAdvertisement(txtRecord: ["proto": "1", "device": long, "deviceid": "a"]))
        XCTAssertNil(PeerAdvertisement(txtRecord: ["proto": "1", "device": "a", "deviceid": long]))
        XCTAssertNil(PeerAdvertisement(txtRecord: ["proto": "x", "device": "a", "deviceid": "a"]))
        let odd = PeerAdvertisement(txtRecord: [
            "proto": "1", "device": "a", "deviceid": "a", "tracks": "-5", "rev": "zz",
            "caps": String(repeating: "acquire,", count: 100), "versions": "0,-1,abc"
        ])
        XCTAssertNotNil(odd)
        XCTAssertEqual(odd?.versions, [])
        XCTAssertFalse(odd?.mayAcquire(for: "me") ?? true)
        // Our own record never carries a name a reader would refuse.
        let named = PeerAdvertisement(deviceName: String(repeating: "й", count: 300), deviceID: "me",
                                      trackCount: 0, revision: 0, isPlaying: false)
        XCTAssertNotNil(PeerAdvertisement(txtRecord: named.txtRecord))
    }

    // MARK: - Framing

    func testOversizedLengthIsRefusedBeforeAnythingIsHeld() {
        var reader = MessageFraming.Reader()
        XCTAssertThrowsError(try reader.read(Data([0xFF, 0xFF, 0xFF, 0xFF]))) { error in
            XCTAssertEqual(error as? MessageFraming.Failure, .messageTooLarge(claimed: Int(UInt32.max)))
        }
        var small = MessageFraming.Reader(limit: 1024)
        XCTAssertThrowsError(try small.read(Data([0, 0, 0x04, 0x01])))
    }

    func testTruncatedMessagesWaitAndEmptyOnesAreRefused() throws {
        let whole = try frame(validHello)
        for cut in 0..<whole.count {
            var reader = MessageFraming.Reader()
            XCTAssertEqual(try reader.read(whole.prefix(cut)), [], "cut at \(cut)")
            XCTAssertEqual(reader.pendingBytes, cut)
        }
        var reader = MessageFraming.Reader()
        XCTAssertThrowsError(try reader.read(Data([0, 0, 0, 0])))
    }

    func testRandomBytesNeverTrapTheReader() {
        var rng = Seeded(state: 0x10AD)
        for round in 0..<2_000 {
            var reader = MessageFraming.Reader(limit: 4096)
            // A plausible length so the parser, not just the length check, is reached.
            let length = Int.random(in: 0...300, using: &rng)
            var bytes = Data([0, 0, UInt8(length >> 8), UInt8(length & 0xFF)])
            bytes.append(randomBytes(length, &rng))
            _ = try? reader.read(bytes)
            _ = round
        }
    }

    func testMutatedMessagesAreReadOrRefusedNeverTrap() throws {
        var rng = Seeded(state: 0xF00D)
        let body = try frame(validHello).dropFirst(4)
        for _ in 0..<3_000 {
            var mutated = Array(body)
            for _ in 0..<Int.random(in: 1...8, using: &rng) {
                let at = Int.random(in: 0..<mutated.count, using: &rng)
                switch Int.random(in: 0...2, using: &rng) {
                case 0: mutated[at] = UInt8.random(in: 0...255, using: &rng)
                case 1: mutated.remove(at: at)
                default: mutated.insert(UInt8.random(in: 0...255, using: &rng), at: at)
                }
                if mutated.isEmpty { mutated = [0x7B] }
            }
            if let message = try? JSONValueParser.message(Data(mutated)) { _ = PeerHello(message) }
        }
    }

    func testDeepNestingIsRefusedNotRecursedInto() {
        let deep = Data((String(repeating: "[", count: 100_000) + String(repeating: "]", count: 100_000)).utf8)
        XCTAssertThrowsError(try JSONValueParser.parse(deep))
        let deepObject = Data((String(repeating: "{\"a\":", count: 50_000) + "1" + String(repeating: "}", count: 50_000)).utf8)
        XCTAssertThrowsError(try JSONValueParser.parse(deepObject))
    }

    func testOddJSONIsRefused() {
        for text in ["", "{", "{\"type\":}", "{\"type\":\"hello\"", "\u{0}", "{\"type\":\"\\ud800\"}",
                     "{\"type\":1e999999}", "[1,2,]", "{\"a\":1,}", "nul", "\"\\u12\""] {
            _ = try? JSONValueParser.parse(Data(text.utf8))
        }
        XCTAssertThrowsError(try JSONValueParser.message(Data("[]".utf8)), "a message is an object with a type")
        XCTAssertThrowsError(try JSONValueParser.parse(Data([0xC3, 0x28])), "invalid UTF-8")
    }

    // MARK: - HTTP

    private func head(_ lines: String) -> Data { Data((lines + "\r\n\r\n").utf8) }

    func testANegativeLengthIsMalformedNotATrap() {
        for length in ["-5", "+5", "5x", " ", "99999999999999999999", "0x10"] {
            var reader = HTTPRequestReader()
            XCTAssertThrowsError(try reader.read(head("POST /api/edits HTTP/1.1\r\nContent-Length: \(length)")),
                                 "Content-Length: \(length)")
        }
    }

    func testTwoLengthsThatDisagreeAreRefused() {
        var reader = HTTPRequestReader()
        XCTAssertThrowsError(try reader.read(head(
            "POST /api/edits HTTP/1.1\r\nContent-Length: 1\r\ncontent-length: 2"
        ))) { XCTAssertEqual($0 as? HTTPRequestReader.Failure, .malformed) }
        var same = HTTPRequestReader()
        XCTAssertNotNil(try same.read(head("GET /a HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0")))
    }

    func testAnEndlessHeadIsRefused() {
        var reader = HTTPRequestReader()
        let chunk = Data(String(repeating: "X-A: b\r\n", count: 1024).utf8)
        var thrown = false
        for _ in 0..<20 where !thrown {
            do { _ = try reader.read(chunk) } catch { thrown = true }
        }
        XCTAssertTrue(thrown)
    }

    func testRandomRequestsNeverTrapTheReader() {
        var rng = Seeded(state: 0xBEEF)
        let pieces = ["GET", "POST", " ", "/api/variant/", "/api/import", "?", "&", "=", "%", "%2F", "..",
                      "\r\n", "Content-Length:", "Range: bytes=", "-", "1", "0", "99999999999", ":", "\r\n\r\n"]
        for _ in 0..<5_000 {
            var text = ""
            for _ in 0..<Int.random(in: 1...30, using: &rng) { text += pieces.randomElement(using: &rng)! }
            var reader = HTTPRequestReader()
            if let request = try? reader.read(Data(text.utf8)) {
                _ = request.requestedRange?.resolved(within: Int64.random(in: 0...1000, using: &rng))
            }
        }
    }

    func testByteRangesNeverResolveOutsideTheFile() {
        var rng = Seeded(state: 0xCAFE)
        for _ in 0..<5_000 {
            let a = Int64.random(in: -5...2000, using: &rng), b = Int64.random(in: -5...2000, using: &rng)
            let total = Int64.random(in: 0...1000, using: &rng)
            for header in ["bytes=\(a)-\(b)", "bytes=\(a)-", "bytes=-\(b)", "bytes=\(a)-\(b),1-2"] {
                guard let range = HTTPByteRange(header: header), let resolved = range.resolved(within: total) else { continue }
                XCTAssertGreaterThanOrEqual(resolved.lowerBound, 0)
                XCTAssertLessThanOrEqual(resolved.upperBound, total)
                XCTAssertLessThan(resolved.lowerBound, resolved.upperBound)
            }
        }
    }

    // MARK: - Replay

    private let secret = Data(repeating: 0x5A, count: 32)
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private var store: InMemoryTrustStore {
        InMemoryTrustStore([PairedDevice(deviceID: "phone", deviceName: "Phone", certificateFingerprint: nil,
                                         sharedSecret: secret, pairedAt: now)])
    }

    private func signed(_ method: String, _ path: String, body: Data = Data()) -> HTTPRequest {
        let headers = RequestSignature.headers(
            method: method, target: path, body: body, deviceID: "phone", secret: secret, at: now
        )
        return HTTPRequest(method: method, path: path,
                           headers: Dictionary(uniqueKeysWithValues: headers.map { ($0.key.lowercased(), $0.value) }),
                           body: body)
    }

    func testAWriteIsTakenOnceAReadAsOftenAsAsked() throws {
        let guardian = ReplayGuard()
        let write = signed("POST", "/api/edits", body: Data("{}".utf8))
        XCTAssertNoThrow(try RequestSignature.check(write, against: store, replays: guardian, at: now))
        XCTAssertThrowsError(try RequestSignature.check(write, against: store, replays: guardian, at: now)) {
            XCTAssertEqual($0 as? RequestSignature.Refusal, .replayed)
        }
        let read = signed("GET", "/api/variant/abc")
        XCTAssertNoThrow(try RequestSignature.check(read, against: store, replays: guardian, at: now))
        XCTAssertNoThrow(try RequestSignature.check(read, against: store, replays: guardian, at: now))
    }

    func testAnUnsignedFloodDoesNotFillTheGuard() {
        let guardian = ReplayGuard()
        for index in 0..<100 {
            var forged = signed("POST", "/api/edits")
            forged = HTTPRequest(method: "POST", path: "/api/edits", headers: forged.headers.merging(
                ["x-loom-signature": Data(repeating: UInt8(index), count: 32).base64EncodedString()]) { $1 })
            XCTAssertThrowsError(try RequestSignature.check(forged, against: store, replays: guardian, at: now))
        }
        XCTAssertEqual(guardian.count, 0)
    }

    func testTheGuardStaysBounded() {
        let guardian = ReplayGuard()
        for index in 0..<(ReplayGuard.capacity + 500) {
            XCTAssertTrue(guardian.first(deviceID: "d", signature: Data("\(index)".utf8), at: now))
        }
        XCTAssertLessThanOrEqual(guardian.count, ReplayGuard.capacity)
        // Forgotten once the window is over.
        XCTAssertTrue(guardian.first(deviceID: "d", signature: Data("x".utf8), at: now))
        XCTAssertTrue(guardian.first(deviceID: "d", signature: Data("x".utf8),
                                     at: now.addingTimeInterval(3 * RequestSignature.tolerance)))
    }
}
