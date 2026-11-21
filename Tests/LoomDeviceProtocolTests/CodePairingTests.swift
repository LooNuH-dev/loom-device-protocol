import Crypto
import Foundation
import XCTest
@testable import LoomDeviceProtocol

/// Pairing two devices that share no account.
final class CodePairingTests: XCTestCase {

    private let fingerprint = Data(repeating: 0xA1, count: 32)

    /// Runs the exchange between two halves and gives back what each side got.
    private func exchange(
        host: CodePairingRoute.Half,
        client: CodePairingRoute.Half,
        hostFingerprint: Data? = nil,
        clientSeesFingerprint: Data? = nil
    ) throws -> (host: CodePairingRoute.Agreement, client: CodePairingRoute.Agreement) {
        let hostSide = try CodePairingRoute.agree(
            ours: host,
            theirPublicKey: client.publicKey,
            theirDeviceID: client.deviceID,
            hostFingerprint: hostFingerprint ?? fingerprint,
            hostDeviceID: host.deviceID
        )
        let clientSide = try CodePairingRoute.agree(
            ours: client,
            theirPublicKey: host.publicKey,
            theirDeviceID: host.deviceID,
            hostFingerprint: clientSeesFingerprint ?? hostFingerprint ?? fingerprint,
            hostDeviceID: host.deviceID
        )
        return (hostSide, clientSide)
    }

    private func half(_ id: String) -> CodePairingRoute.Half {
        CodePairingRoute.Half(deviceID: id, deviceName: id)
    }

    func testBothEndsAgreeOnTheSameKeyAndTheSameDigits() throws {
        let (host, client) = try exchange(host: half("mac"), client: half("phone"))

        XCTAssertEqual(host.sharedSecret, client.sharedSecret)
        XCTAssertEqual(host.confirmationCode, client.confirmationCode)
        XCTAssertEqual(host.sharedSecret.count, 32)
    }

    func testTheDigitsAreSixOfThem() throws {
        for _ in 0..<50 {
            let (host, _) = try exchange(host: half("mac"), client: half("phone"))

            XCTAssertEqual(host.confirmationCode.count, 6)
            XCTAssertTrue(host.confirmationCode.allSatisfy(\.isNumber))
        }
    }

    /// The whole point. Somebody relaying the pairing agrees one key with each
    /// side, so the two screens no longer show the same thing — which is the
    /// question the person is being asked.
    func testSomebodyInTheMiddleMakesTheTwoScreensDisagree() throws {
        let mac = half("mac")
        let phone = half("phone")
        let middle = half("middle")

        // The Mac believes it is talking to the phone; the phone believes it is
        // talking to the Mac. Both are talking to the one in the middle.
        let macSide = try CodePairingRoute.agree(
            ours: mac, theirPublicKey: middle.publicKey, theirDeviceID: "phone",
            hostFingerprint: fingerprint, hostDeviceID: "mac"
        )
        let phoneSide = try CodePairingRoute.agree(
            ours: phone, theirPublicKey: middle.publicKey, theirDeviceID: "mac",
            hostFingerprint: fingerprint, hostDeviceID: "mac"
        )

        XCTAssertNotEqual(macSide.confirmationCode, phoneSide.confirmationCode)
        XCTAssertNotEqual(macSide.sharedSecret, phoneSide.sharedSecret)
    }

    /// Bound to the connection it runs over: a relay that terminates TLS
    /// presents its own certificate, and the digits change.
    func testARelayedConnectionShowsDifferentDigits() throws {
        let (host, client) = try exchange(
            host: half("mac"),
            client: half("phone"),
            hostFingerprint: fingerprint,
            clientSeesFingerprint: Data(repeating: 0xB2, count: 32)
        )

        XCTAssertNotEqual(host.confirmationCode, client.confirmationCode)
    }

    /// Each pairing stands on its own: two runs between the same two devices
    /// agree different keys, so a key learned once is of no use later.
    func testEveryPairingAgreesItsOwnKey() throws {
        let first = try exchange(host: half("mac"), client: half("phone"))
        let second = try exchange(host: half("mac"), client: half("phone"))

        XCTAssertNotEqual(first.host.sharedSecret, second.host.sharedSecret)
    }

    /// The digits are shown on two screens and to whoever is in the room. They
    /// must not be a window onto the key.
    func testTheDigitsAreNotThePrefixOfTheKey() throws {
        let (host, _) = try exchange(host: half("mac"), client: half("phone"))
        let keyDigits = host.sharedSecret.prefix(4).map { String($0) }.joined()

        XCTAssertFalse(keyDigits.hasPrefix(host.confirmationCode))
    }

    func testRubbishInPlaceOfAPublicKeyIsRefused() {
        XCTAssertThrowsError(try CodePairingRoute.agree(
            ours: half("mac"),
            theirPublicKey: Data("not a key".utf8),
            theirDeviceID: "phone",
            hostFingerprint: fingerprint,
            hostDeviceID: "mac"
        )) { error in
            XCTAssertEqual(error as? CodePairingRoute.Failure, .notAPublicKey)
        }
    }

    /// What is kept afterwards is the same thing every other route produces, so
    /// nothing above pairing has to know which was used.
    func testItEndsAtTheSamePlaceAsTheOtherRoute() throws {
        let (host, _) = try exchange(host: half("mac"), client: half("phone"))

        let pairing = CodePairingRoute.pairing(
            with: host, hostDeviceID: "mac", hostDeviceName: "Mac",
            hostFingerprint: fingerprint
        )
        let store = InMemoryTrustStore()
        try store.remember(pairing.asPairedDevice())

        XCTAssertEqual(try store.paired(deviceID: "mac")?.sharedSecret, host.sharedSecret)
        XCTAssertEqual(try store.paired(deviceID: "mac")?.certificateFingerprint, fingerprint)
    }
}
