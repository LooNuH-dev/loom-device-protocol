import Crypto
import Foundation
import XCTest
@testable import LoomDeviceProtocol

/// Proving a request came from a paired device.
final class RequestSignatureTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)
    private let secret = Data(repeating: 0x5A, count: 32)

    private func store(secret: Data? = nil) -> InMemoryTrustStore {
        InMemoryTrustStore([
            PairedDevice(
                deviceID: "phone",
                deviceName: "Phone",
                certificateFingerprint: nil,
                sharedSecret: secret ?? self.secret,
                pairedAt: now
            )
        ])
    }

    /// Builds a request the way a client would, signed.
    private func signed(
        method: String = "GET",
        path: String = "/api/catalog",
        query: [String: String] = ["since": "41209"],
        body: Data = Data(),
        secret: Data? = nil,
        at moment: Date? = nil
    ) -> HTTPRequest {
        let headers = RequestSignature.headers(
            method: method,
            target: RequestSignature.target(path: path, query: query),
            body: body,
            deviceID: "phone",
            secret: secret ?? self.secret,
            at: moment ?? now
        )
        return HTTPRequest(
            method: method,
            path: path,
            query: query,
            headers: Dictionary(uniqueKeysWithValues: headers.map { ($0.key.lowercased(), $0.value) }),
            body: body
        )
    }

    func testASignedRequestIsRecognised() throws {
        let device = try RequestSignature.check(signed(), against: store(), at: now)

        XCTAssertEqual(device.deviceID, "phone")
    }

    func testAnUnsignedRequestIsRefused() {
        let bare = HTTPRequest(method: "GET", path: "/api/catalog")

        XCTAssertThrowsError(try RequestSignature.check(bare, against: store(), at: now)) {
            XCTAssertEqual($0 as? RequestSignature.Refusal, .unsigned)
        }
    }

    func testADeviceThatWasNeverPairedIsRefused() {
        XCTAssertThrowsError(
            try RequestSignature.check(signed(), against: InMemoryTrustStore(), at: now)
        ) {
            XCTAssertEqual($0 as? RequestSignature.Refusal, .notFromAPairedDevice)
        }
    }

    /// Signed with the right shape and the wrong key.
    func testAnotherDevicesSecretDoesNotWork() {
        let theirs = signed(secret: Data(repeating: 0x11, count: 32))

        XCTAssertThrowsError(try RequestSignature.check(theirs, against: store(), at: now)) {
            XCTAssertEqual($0 as? RequestSignature.Refusal, .wrongSignature)
        }
    }

    /// A recorded request is worthless once the window has passed.
    func testAnOldRequestIsRefused() {
        let old = signed(at: now.addingTimeInterval(-RequestSignature.tolerance - 1))

        XCTAssertThrowsError(try RequestSignature.check(old, against: store(), at: now)) {
            XCTAssertEqual($0 as? RequestSignature.Refusal, .tooOldOrTooNew)
        }
    }

    /// Clocks drift both ways, and neither side sets the other's.
    func testAModestlyWrongClockIsToleratedInEitherDirection() throws {
        for skew in [-RequestSignature.tolerance + 1, RequestSignature.tolerance - 1] {
            let request = signed(at: now.addingTimeInterval(skew))
            XCTAssertNoThrow(try RequestSignature.check(request, against: store(), at: now))
        }
    }

    /// A signature for one thing must not work for another. The query is part
    /// of that: it is what says which revision to send.
    func testASignatureDoesNotCarryToAnotherRequest() {
        var altered = signed()
        altered = HTTPRequest(
            method: altered.method,
            path: altered.path,
            query: ["since": "0"],
            headers: altered.headers,
            body: altered.body
        )

        XCTAssertThrowsError(try RequestSignature.check(altered, against: store(), at: now)) {
            XCTAssertEqual($0 as? RequestSignature.Refusal, .wrongSignature)
        }
    }

    func testASignatureForReadingDoesNotAuthoriseWriting() {
        let reading = signed(method: "GET", path: "/api/import", query: [:])
        let writing = HTTPRequest(
            method: "POST", path: "/api/import", headers: reading.headers
        )

        XCTAssertThrowsError(try RequestSignature.check(writing, against: store(), at: now)) {
            XCTAssertEqual($0 as? RequestSignature.Refusal, .wrongSignature)
        }
    }

    /// What was sent must not be swappable for something else of any length.
    func testChangingTheBodyBreaksTheSignature() {
        let sent = signed(method: "POST", path: "/api/import", query: [:], body: Data("one".utf8))
        let swapped = HTTPRequest(
            method: "POST", path: "/api/import", headers: sent.headers, body: Data("two".utf8)
        )

        XCTAssertThrowsError(try RequestSignature.check(swapped, against: store(), at: now)) {
            XCTAssertEqual($0 as? RequestSignature.Refusal, .wrongSignature)
        }
    }

    /// A dictionary has no order, so both ends have to agree on one.
    func testTheTargetIsBuiltTheSameWayWhateverOrderTheQueryIsIn() {
        XCTAssertEqual(
            RequestSignature.target(path: "/api/catalog", query: ["b": "2", "a": "1"]),
            "/api/catalog?a=1&b=2"
        )
    }
    // MARK: - A body that is not in hand

    /// A file goes up in pieces and is written to disk as it comes, so the
    /// receiver has no body to hash when the signature has to be checked. What
    /// is signed is the sender's claim about the digest instead — and the file
    /// is held to that claim once it has all arrived.
    func testAPromisedDigestIsWhatGetsSigned() throws {
        let file = Data("a whole album side".utf8)
        let promised = Data(SHA256.hash(data: file))

        let headers = RequestSignature.headers(
            method: "POST",
            target: "/api/import",
            bodyDigest: promised,
            deviceID: "phone",
            secret: secret,
            at: now
        )

        // The head arrives with only the first scrap of the file behind it,
        // which is exactly the case that broke signing the bytes themselves.
        let request = HTTPRequest(
            method: "POST", path: "/api/import",
            headers: lowercased(headers), body: file.prefix(4)
        )

        XCTAssertEqual(
            try RequestSignature.check(
                request, against: store(), bodyArrivesSeparately: true, at: now
            ).deviceID,
            "phone"
        )
        XCTAssertEqual(RequestSignature.declaredDigest(of: request), promised)
    }

    /// The claim is signed, so it cannot be quietly changed to match a
    /// different file.
    func testATamperedDigestIsRefused() throws {
        let headers = RequestSignature.headers(
            method: "POST",
            target: "/api/import",
            bodyDigest: Data(SHA256.hash(data: Data("one".utf8))),
            deviceID: "phone",
            secret: secret,
            at: now
        )
        var altered = lowercased(headers)
        altered[RequestSignature.digestHeader.lowercased()] =
            Data(SHA256.hash(data: Data("another".utf8))).base64EncodedString()

        let request = HTTPRequest(
            method: "POST", path: "/api/import", headers: altered
        )

        XCTAssertThrowsError(
            try RequestSignature.check(
                request, against: store(), bodyArrivesSeparately: true, at: now
            )
        )
    }

    /// The claim is only ever worth what settles it, and nothing settles it on a
    /// route whose body is already here. So on those routes the bytes are what
    /// is hashed, and a request declaring a digest for a body it did not send is
    /// signed over something this host will not agree to.
    func testADeclaredDigestIsIgnoredWhenTheBodyIsInHand() throws {
        let sent = Data("the body actually sent".utf8)
        let claimed = Data(SHA256.hash(data: Data("something else entirely".utf8)))

        let headers = RequestSignature.headers(
            method: "POST",
            target: "/api/edits",
            bodyDigest: claimed,
            deviceID: "phone",
            secret: secret,
            at: now
        )
        let request = HTTPRequest(
            method: "POST", path: "/api/edits", headers: lowercased(headers), body: sent
        )

        XCTAssertThrowsError(try RequestSignature.check(request, against: store(), at: now)) {
            XCTAssertEqual($0 as? RequestSignature.Refusal, .wrongSignature)
        }
    }

    /// The same request signed over the bytes it carries is fine, so the refusal
    /// above is about the claim and not about the route.
    func testABodyInHandSignedOverItselfIsAccepted() throws {
        let sent = Data("the body actually sent".utf8)
        let headers = RequestSignature.headers(
            method: "POST", target: "/api/edits", body: sent,
            deviceID: "phone", secret: secret, at: now
        )
        let request = HTTPRequest(
            method: "POST", path: "/api/edits", headers: lowercased(headers), body: sent
        )

        XCTAssertEqual(
            try RequestSignature.check(request, against: store(), at: now).deviceID, "phone"
        )
    }

    /// Requests without a body are unaffected: they sign the bytes, as before.
    func testAnOrdinaryRequestStillSignsItsOwnBody() throws {
        let headers = RequestSignature.headers(
            method: "GET", target: "/api/catalog", deviceID: "phone", secret: secret, at: now
        )
        let request = HTTPRequest(
            method: "GET", path: "/api/catalog", headers: lowercased(headers)
        )

        XCTAssertNil(RequestSignature.declaredDigest(of: request))
        XCTAssertEqual(try RequestSignature.check(request, against: store(), at: now).deviceID, "phone")
    }

    private func lowercased(_ headers: [String: String]) -> [String: String] {
        Dictionary(uniqueKeysWithValues: headers.map { ($0.key.lowercased(), $0.value) })
    }

}
