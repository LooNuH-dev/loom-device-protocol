import XCTest
@testable import LoomDeviceProtocol

/// Pairing version 2: the code is a password proved a bit at a time.
/// See PROTOCOL.md 5.3.
final class PasskeyPairingTests: XCTestCase {

    private let macFingerprint = Data(repeating: 0xAB, count: 32)

    private struct Ends {
        var shower: PasskeyExchange
        var enterer: PasskeyExchange
    }

    /// A Mac answering (and showing), an iPhone that connected (and types).
    private func ends(code: Int, keysSeenByPhone: Data? = nil) throws -> Ends {
        let mac = CodePairingRoute.Half(deviceID: "MAC", deviceName: "Studio")
        let phone = CodePairingRoute.Half(deviceID: "PHONE", deviceName: "iPhone")
        let responder = PasskeyParty(
            fingerprint: macFingerprint, publicKey: mac.publicKey, deviceID: "MAC", deviceClass: .desktop
        )
        let initiator = PasskeyParty(
            fingerprint: Data(), publicKey: phone.publicKey, deviceID: "PHONE", deviceClass: .ios
        )
        let responderAsPhoneSees = PasskeyParty(
            fingerprint: macFingerprint, publicKey: keysSeenByPhone ?? mac.publicKey,
            deviceID: "MAC", deviceClass: .desktop
        )
        return Ends(
            shower: try PasskeyExchange(role: .shower, ours: mac, responder: responder, initiator: initiator, code: code),
            enterer: try PasskeyExchange(role: .enterer, ours: phone, responder: responderAsPhoneSees, initiator: initiator)
        )
    }

    private enum Result: Equatable {
        case paired(shower: Data, enterer: Data)
        case showerFailed(PasskeyExchange.Failure)
        case entererFailed(PasskeyExchange.Failure)
    }

    /// Carries messages back and forth until somebody finishes.
    private func run(_ ends: inout Ends, typed: Int) -> Result {
        var toShower: [WireMessage]
        guard case .send(let first) = ends.enterer.enter(code: typed) else { return .entererFailed(.outOfOrder) }
        toShower = first
        var showerSecret: Data?
        for _ in 0..<500 {
            var toEnterer: [WireMessage] = []
            for message in toShower {
                switch ends.shower.receive(message) {
                case .send(let out): toEnterer += out
                case .paired(let secret, let out): showerSecret = secret; toEnterer += out
                case .failed(let failure, _): return .showerFailed(failure)
                case .retry: XCTFail("the shower is never asked to retry")
                }
            }
            toShower = []
            for message in toEnterer {
                switch ends.enterer.receive(message) {
                case .send(let out): toShower += out
                case .paired(let secret, _):
                    guard let showerSecret else { XCTFail("the enterer finished first"); return .entererFailed(.outOfOrder) }
                    return .paired(shower: showerSecret, enterer: secret)
                case .failed(let failure, _): return .entererFailed(failure)
                case .retry: XCTFail("no retry was offered")
                }
            }
        }
        XCTFail("the exchange never finished")
        return .entererFailed(.outOfOrder)
    }

    func testTheRightCodePairsBothEndsOnOneSecret() throws {
        var pair = try ends(code: 482_913)
        guard case .paired(let a, let b) = run(&pair, typed: 482_913) else { return XCTFail("did not pair") }
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.count, PairingSecret.byteCount)
    }

    func testCodesWithLeadingZerosAndTheExtremesWork() throws {
        for code in [0, 7, 999_999] {
            var pair = try ends(code: code)
            guard case .paired = run(&pair, typed: code) else { return XCTFail("\(code) did not pair") }
        }
        XCTAssertEqual(PasskeyExchange.display(7), "000007")
    }

    func testAWrongCodeIsCaughtByTheShower() throws {
        var pair = try ends(code: 482_913)
        XCTAssertEqual(run(&pair, typed: 482_912), .showerFailed(.codeMismatch))
    }

    func testTwoSecretsFromTwoRunsDiffer() throws {
        var first = try ends(code: 111_111)
        var second = try ends(code: 111_111)
        guard case .paired(let a, _) = run(&first, typed: 111_111),
              case .paired(let b, _) = run(&second, typed: 111_111)
        else { return XCTFail("did not pair") }
        XCTAssertNotEqual(a, b)
    }

    /// Somebody in the middle hands the phone their own key. The person types
    /// the right code; the transcripts no longer agree, and the very first
    /// bit says so.
    func testASubstitutedKeyFailsEvenWithTheRightCode() throws {
        let intruder = CodePairingRoute.Half(deviceID: "MAC", deviceName: "Studio")
        var pair = try ends(code: 482_913, keysSeenByPhone: intruder.publicKey)
        XCTAssertEqual(run(&pair, typed: 482_913), .showerFailed(.codeMismatch))
    }

    /// The reflection attack on Passkey Entry: an intruder that hands a
    /// device its own public key and its own commitments back. Without the
    /// role in what is committed to, a commitment made by one side with the
    /// same keys would read as the other side's.
    func testACommitmentCannotBeReflectedBackAsTheOtherSides() {
        let key = CodePairingRoute.Half(deviceID: "X", deviceName: "X").publicKey
        let nonce = Data(repeating: 7, count: 16)
        let transcript = Data("t".utf8)
        let byShower = PasskeyExchange.commitment(
            by: .shower, nonce: nonce, mine: key, theirs: key, transcript: transcript, round: 0, bit: 1
        )
        let asIfByEnterer = PasskeyExchange.commitment(
            by: .enterer, nonce: nonce, mine: key, theirs: key, transcript: transcript, round: 0, bit: 1
        )
        XCTAssertNotEqual(byShower, asIfByEnterer)
    }

    func testARetryStartsAgainOnANewCode() throws {
        var pair = try ends(code: 482_913)
        XCTAssertEqual(run(&pair, typed: 100_000), .showerFailed(.codeMismatch))

        // The shower lets the person try again, with a code they have not seen.
        pair.shower.restart(code: 555_555)
        XCTAssertEqual(pair.enterer.receive(PasskeyExchange.refusal(retry: true)), .retry)
        guard case .paired(let a, let b) = run(&pair, typed: 555_555) else { return XCTFail("did not pair") }
        XCTAssertEqual(a, b)
    }

    func testARefusalWithoutRetryEndsIt() throws {
        var pair = try ends(code: 1)
        guard case .failed(.refused, _) = pair.enterer.receive(PasskeyExchange.refusal(retry: false))
        else { return XCTFail("a final refusal ends the exchange") }
    }

    func testAMessageOutOfTurnEndsIt() throws {
        var pair = try ends(code: 1)
        let reveal = WireMessage(type: .pairingReveal, payload: .object([
            "round": .int(0), "nonce": .string(Data(count: 16).base64EncodedString())
        ]))
        guard case .failed(.outOfOrder, let send) = pair.shower.receive(reveal)
        else { return XCTFail("a reveal before any commit is out of order") }
        XCTAssertEqual(send.first?.type, .pairingConfirm)
        XCTAssertEqual(send.first?.ok, false)
    }

    func testATamperedCheckIsRefused() throws {
        var pair = try ends(code: 3)
        guard case .send(var toShower) = pair.enterer.enter(code: 3) else { return XCTFail() }
        while true {
            var toEnterer: [WireMessage] = []
            for message in toShower {
                var message = message
                if message.type == .pairingCheck {
                    message = WireMessage(type: .pairingCheck, payload: .object([
                        "mac": .string(Data(repeating: 1, count: 32).base64EncodedString())
                    ]))
                    guard case .failed(.checkFailed, _) = pair.shower.receive(message)
                    else { return XCTFail("a wrong check must be refused") }
                    return
                }
                guard case .send(let out) = pair.shower.receive(message) else { return XCTFail() }
                toEnterer += out
            }
            toShower = []
            for message in toEnterer {
                guard case .send(let out) = pair.enterer.receive(message) else { return XCTFail() }
                toShower += out
            }
        }
    }

    func testTheTranscriptCannotRunTwoIdentitiesTogether() {
        func party(_ id: String) -> PasskeyParty {
            PasskeyParty(fingerprint: Data(), publicKey: Data(), deviceID: id, deviceClass: .ios)
        }
        XCTAssertNotEqual(
            PasskeyExchange.transcript(responder: party("AB"), initiator: party("C")),
            PasskeyExchange.transcript(responder: party("A"), initiator: party("BC"))
        )
    }

    // MARK: - Who shows

    func testRolesFollowTheClassOrder() {
        XCTAssertEqual(PasskeyRole.of(ours: .desktop, theirs: .ios, weStarted: false), .shower)
        XCTAssertEqual(PasskeyRole.of(ours: .ios, theirs: .desktop, weStarted: true), .enterer)
        XCTAssertEqual(PasskeyRole.of(ours: .android, theirs: .ios, weStarted: false), .shower)
        XCTAssertEqual(PasskeyRole.of(ours: .android, theirs: .desktop, weStarted: true), .enterer)
        XCTAssertEqual(PasskeyRole.of(ours: .ios, theirs: .ios, weStarted: true), .shower)
        XCTAssertEqual(PasskeyRole.of(ours: .ios, theirs: .ios, weStarted: false), .enterer)
        XCTAssertEqual(PasskeyRole.of(ours: .desktop, theirs: .desktop, weStarted: true), .shower)
    }

    /// The rule two builds that both know it agree on: whoever
    /// started types the code, the other shows it, for every pair of classes.
    /// The person starts on the device in their hand and reads the code off
    /// the other one.
    func testUnderTheNewRuleWhoeverStartedTypes() {
        for ours in DeviceClass.allCases {
            for theirs in DeviceClass.allCases {
                XCTAssertEqual(PasskeyRole.of(ours: ours, theirs: theirs, weStarted: true, rule: .starterEnters), .enterer,
                               "\(ours) started with \(theirs)")
                XCTAssertEqual(PasskeyRole.of(ours: ours, theirs: theirs, weStarted: false, rule: .starterEnters), .shower,
                               "\(theirs) started with \(ours)")
            }
        }
    }

    /// The new rule only when both offers say so: a build before it keeps the
    /// class order, and so does this side with it, or both would show.
    func testTheRuleIsAgreedInTheOffers() {
        func offer(_ fields: [String: JSONValue]) -> WireMessage {
            WireMessage(type: .pairingOffer, id: "o", payload: .object(["version": .int(2)].merging(fields) { a, _ in a }))
        }
        XCTAssertEqual(PasskeyRule.agreed(with: offer([PasskeyRule.offerKey: .string("starterEnters")])), .starterEnters)
        XCTAssertEqual(PasskeyRule.agreed(with: offer([:])), .byClass, "a build before the new rule")
        XCTAssertEqual(PasskeyRule.agreed(with: offer([PasskeyRule.offerKey: .string("somethingLater")])), .byClass)
        XCTAssertEqual(PasskeyRole.of(ours: .android, theirs: .ios, weStarted: true), .shower, "the old rule by default")
    }

    func testAnUnknownClassReadsAsDesktop() {
        XCTAssertEqual(DeviceClass(wire: "watch"), .desktop)
        XCTAssertEqual(DeviceClass(wire: nil), .desktop)
        XCTAssertEqual(DeviceClass(wire: "android"), .android)
    }
}
