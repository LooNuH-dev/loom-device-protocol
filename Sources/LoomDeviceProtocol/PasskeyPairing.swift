import Crypto
import Foundation

/// What kind of device this is, for the one thing that tells devices apart:
/// who shows the pairing code and who types it.
public enum DeviceClass: String, Sendable, CaseIterable {
    case desktop
    case android
    case ios

    /// Read off the wire. Anything this build has not heard of is read as
    /// `desktop`, as PROTOCOL.md 2 says: a newer class is likelier to have a
    /// screen to show a code on than not.
    public init(wire: String?) {
        self = wire.flatMap(DeviceClass.init(rawValue:)) ?? .desktop
    }

    /// A phone: it listens only while open, and dials what it sees then.
    public var isMobile: Bool { self != .desktop }

    /// Earlier shows. desktop → Android → iOS.
    var rank: Int {
        switch self {
        case .desktop: return 0
        case .android: return 1
        case .ios: return 2
        }
    }

    #if os(iOS)
    public static let this: DeviceClass = .ios
    #elseif os(Android)
    public static let this: DeviceClass = .android
    #else
    public static let this: DeviceClass = .desktop
    #endif
}

/// Which half of a passkey pairing a device plays. See PROTOCOL.md 5.2.
public enum PasskeyRole: Sendable, Equatable {
    /// Picks the code and shows it.
    case shower
    /// Is told the code by a person.
    case enterer

    /// Under `rule`. By class: the earlier class shows; between two of a
    /// kind, the one that started. Once both know it: whoever started types.
    public static func of(
        ours: DeviceClass, theirs: DeviceClass, weStarted: Bool, rule: PasskeyRule = .byClass
    ) -> PasskeyRole {
        if rule == .starterEnters { return weStarted ? .enterer : .shower }
        if ours.rank != theirs.rank { return ours.rank < theirs.rank ? .shower : .enterer }
        return weStarted ? .shower : .enterer
    }

    var tag: UInt8 { self == .shower ? 0x53 : 0x45 }  // "S", "E"
}

/// How two devices decide who shows the code. Each offer says
/// which this build knows (`offerKey`); the new rule holds only when both
/// do, so a build from before it and this one still agree.
public enum PasskeyRule: Sendable, Equatable {
    /// The earlier class shows (desktop → Android → iOS): every build.
    case byClass
    /// Whoever started types, the other shows: the person starts on the
    /// device in their hand and reads the code off the other one.
    case starterEnters

    /// The offer field that says a build knows `starterEnters`.
    public static let offerKey = "roles"
    static let starterEntersValue = "starterEnters"

    /// The rule, given the other side's offer: this build knows both.
    public static func agreed(with theirOffer: WireMessage) -> PasskeyRule {
        theirOffer.payload?[offerKey]?.stringValue == starterEntersValue ? .starterEnters : .byClass
    }

    /// Put in every offer this build sends.
    public static var offerField: (String, JSONValue) { (offerKey, .string(starterEntersValue)) }
}

/// One side of a pairing exchange, as both sides write it into the transcript.
public struct PasskeyParty: Sendable, Equatable {
    /// SHA-256 of the device's certificate; empty for a device that has none
    /// yet (an iPhone before it listens). See PROTOCOL.md 5.3.
    public let fingerprint: Data
    public let publicKey: Data
    public let deviceID: String
    public let deviceClass: DeviceClass

    public init(fingerprint: Data, publicKey: Data, deviceID: String, deviceClass: DeviceClass) {
        self.fingerprint = fingerprint
        self.publicKey = publicKey
        self.deviceID = deviceID
        self.deviceClass = deviceClass
    }
}

/// Pairing by a code a person reads off one device and types into the other,
/// with the code as a password rather than something derived from the key.
/// See PROTOCOL.md 5.3.
///
/// Why: when the digits are derived from the agreed key and only one side
/// compares them, only that side learns anything. The side showing them is
/// left trusting whoever it agreed a key with, and a device in the middle
/// would stay paired with it whatever the other screen said. So the code is
/// fresh and random, and each side proves it knows the code one bit at a time,
/// committing to every bit before it sees the other side's — Passkey Entry from
/// Bluetooth LE Secure Connections, with HMAC-SHA256 in place of AES-CMAC.
/// Nothing beyond ECDH, HMAC and HKDF: no group arithmetic of our own.
///
/// A value type driven by messages, with no network and no clock, so both ends
/// can be run against each other in a test.
public struct PasskeyExchange: Sendable {

    public static let rounds = 20
    /// The largest code: six digits fit in the twenty bits proved.
    public static let codeRange = 0..<1_000_000

    public enum Failure: Error, Equatable, Sendable {
        /// A bit did not match: the code typed is not the code shown — or
        /// somebody in the middle guessed one wrong.
        case codeMismatch
        /// The final check did not hold: the two ends do not hold the same key.
        case checkFailed
        /// A message that does not belong where it arrived.
        case outOfOrder
        /// The other side said no.
        case refused
        case notAPublicKey
    }

    public enum Step: Equatable, Sendable {
        /// Send these, then wait.
        case send([WireMessage])
        /// Done: keep this secret for the other device, and send these.
        case paired(secret: Data, send: [WireMessage])
        /// The other side asked for the code again: a new one is showing there.
        case retry
        case failed(Failure, send: [WireMessage])
    }

    private enum State: Sendable {
        case awaitingCode
        case awaitingCommit(round: Int)
        case sentCommit(round: Int, nonce: Data, theirCommit: Data?)
        case sentReveal(round: Int, theirCommit: Data)
        case awaitingCheck(lastOurs: Data, lastTheirs: Data)
        case sentCheck(secret: Data)
        case finished
    }

    public let role: PasskeyRole
    private let ours: CodePairingRoute.Half
    private let theirKey: Data
    private let transcript: Data
    private let shared: Data
    private let makeNonce: @Sendable () -> Data
    private var code: Int?
    private var state: State
    /// The last nonces of each side, which salt the final secret.
    private var lastEntererNonce = Data()
    private var lastShowerNonce = Data()

    /// - Parameters:
    ///   - responder, initiator: both parties, the same on both ends, in the
    ///     order of the connection's roles.
    ///   - code: for the shower, the code it shows. Nil for the enterer.
    ///   - nonce: given so a test can repeat an exchange. Sixteen random bytes
    ///     otherwise.
    public init(
        role: PasskeyRole,
        ours: CodePairingRoute.Half,
        responder: PasskeyParty,
        initiator: PasskeyParty,
        code: Int? = nil,
        nonce: @escaping @Sendable () -> Data = PasskeyExchange.randomNonce
    ) throws {
        let theirs = responder.publicKey == ours.publicKey ? initiator : responder
        guard let theirKey = try? P256.KeyAgreement.PublicKey(rawRepresentation: theirs.publicKey)
        else { throw Failure.notAPublicKey }
        let agreed = try ours.privateKey.sharedSecretFromKeyAgreement(with: theirKey)

        self.role = role
        self.ours = ours
        self.theirKey = theirs.publicKey
        self.transcript = Self.transcript(responder: responder, initiator: initiator)
        self.shared = agreed.withUnsafeBytes { Data($0) }
        self.makeNonce = nonce
        self.code = code
        self.state = role == .shower ? .awaitingCommit(round: 0) : .awaitingCode
    }

    public static func randomNonce() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        var generator = SystemRandomNumberGenerator()
        for index in bytes.indices { bytes[index] = generator.next() }
        return Data(bytes)
    }

    /// A fresh code for the shower to show.
    public static func newCode() -> Int {
        Int.random(in: codeRange)
    }

    /// The code as shown and typed: six digits, leading zeros kept.
    public static func display(_ code: Int) -> String {
        String(format: "%06d", code)
    }

    // MARK: - Driving it

    /// The enterer has been told the code; the first round starts.
    public mutating func enter(code typed: Int) -> Step {
        guard role == .enterer, case .awaitingCode = state, Self.codeRange.contains(typed)
        else { return fail(.outOfOrder) }
        code = typed
        return .send([commit(round: 0)])
    }

    /// Starts over on the same keys with a new code, after a mismatch the
    /// shower chose to let the person retry. Nonces are fresh: every bit of
    /// the old code that went over the wire is worthless now.
    public mutating func restart(code newCode: Int?) {
        code = role == .shower ? newCode : nil
        state = role == .shower ? .awaitingCommit(round: 0) : .awaitingCode
        lastEntererNonce = Data()
        lastShowerNonce = Data()
    }

    public mutating func receive(_ message: WireMessage) -> Step {
        switch message.type {
        case .pairingConfirm where message.ok == false:
            state = .finished
            if message.payload?["retry"]?.boolValue == true, role == .enterer {
                restart(code: nil)
                return .retry
            }
            return .failed(.refused, send: [])
        case .pairingCommit:
            guard let round = Self.round(of: message),
                  let theirCommit = Self.bytes(message, "commit"), theirCommit.count == 32
            else { return fail(.outOfOrder) }
            return receiveCommit(theirCommit, round: round)
        case .pairingReveal:
            guard let round = Self.round(of: message),
                  let nonce = Self.bytes(message, "nonce"), nonce.count == 16
            else { return fail(.outOfOrder) }
            return receiveReveal(nonce, round: round)
        case .pairingCheck:
            guard let mac = Self.bytes(message, "mac") else { return fail(.outOfOrder) }
            return receiveCheck(mac)
        default:
            return .send([])
        }
    }

    /// A refusal to send, with whether the other side may try a new code.
    public static func refusal(retry: Bool) -> WireMessage {
        WireMessage(
            type: .pairingConfirm, ok: false,
            payload: .object(["reason": .string("codeMismatch"), "retry": .bool(retry)])
        )
    }

    // MARK: - Rounds

    private mutating func receiveCommit(_ theirCommit: Data, round: Int) -> Step {
        switch (role, state) {
        case (.shower, .awaitingCommit(let expected)) where round == expected:
            // Their commitment first, then ours: neither side sees the other's
            // nonce before it has committed to its own bit.
            let nonce = makeNonce()
            state = .sentCommit(round: round, nonce: nonce, theirCommit: theirCommit)
            return .send([Self.message(.pairingCommit, round: round, "commit", commitment(round: round, nonce: nonce))])
        case (.enterer, .sentCommit(let expected, let nonce, nil)) where round == expected:
            state = .sentReveal(round: round, theirCommit: theirCommit)
            lastEntererNonce = nonce
            return .send([Self.message(.pairingReveal, round: round, "nonce", nonce)])
        default:
            return fail(.outOfOrder)
        }
    }

    private mutating func receiveReveal(_ theirNonce: Data, round: Int) -> Step {
        switch (role, state) {
        case (.shower, .sentCommit(let expected, let nonce, let theirCommit?)) where round == expected:
            guard theirCommit.constantTimeEquals(
                Self.commitment(by: .enterer, nonce: theirNonce, mine: theirKey, theirs: ours.publicKey,
                                transcript: transcript, round: round, bit: bit(round))
            ) else { return mismatch() }
            let reveal = Self.message(.pairingReveal, round: round, "nonce", nonce)
            if round + 1 < Self.rounds {
                state = .awaitingCommit(round: round + 1)
            } else {
                state = .awaitingCheck(lastOurs: nonce, lastTheirs: theirNonce)
            }
            return .send([reveal])
        case (.enterer, .sentReveal(let expected, let theirCommit)) where round == expected:
            guard theirCommit.constantTimeEquals(
                Self.commitment(by: .shower, nonce: theirNonce, mine: theirKey, theirs: ours.publicKey,
                                transcript: transcript, round: round, bit: bit(round))
            ) else { return mismatch() }
            lastShowerNonce = theirNonce
            if round + 1 < Self.rounds { return .send([commit(round: round + 1)]) }
            let secret = deriveSecret()
            state = .sentCheck(secret: secret)
            return .send([Self.check(secret: secret, by: .enterer, transcript: transcript)])
        default:
            return fail(.outOfOrder)
        }
    }

    private mutating func receiveCheck(_ mac: Data) -> Step {
        switch (role, state) {
        case (.shower, .awaitingCheck(let lastOurs, let lastTheirs)):
            lastShowerNonce = lastOurs
            lastEntererNonce = lastTheirs
            let secret = deriveSecret()
            guard mac.constantTimeEquals(Self.checkMAC(secret: secret, by: .enterer, transcript: transcript))
            else { return fail(.checkFailed) }
            state = .finished
            return .paired(secret: secret, send: [
                Self.check(secret: secret, by: .shower, transcript: transcript),
                WireMessage(type: .pairingConfirm, ok: true)
            ])
        case (.enterer, .sentCheck(let secret)):
            guard mac.constantTimeEquals(Self.checkMAC(secret: secret, by: .shower, transcript: transcript))
            else { return fail(.checkFailed) }
            state = .finished
            return .paired(secret: secret, send: [WireMessage(type: .pairingConfirm, ok: true)])
        default:
            return fail(.outOfOrder)
        }
    }

    /// A bit that did not match. The shower is the one that decides whether
    /// the person may try again, so it sends nothing yet; the enterer finding
    /// one means the shower's own commitment was wrong, which no retyping
    /// mends.
    private mutating func mismatch() -> Step {
        state = .finished
        return .failed(.codeMismatch, send: role == .enterer ? [Self.refusal(retry: false)] : [])
    }

    private mutating func fail(_ failure: Failure) -> Step {
        state = .finished
        return .failed(failure, send: [WireMessage(type: .pairingConfirm, ok: false)])
    }

    private mutating func commit(round: Int) -> WireMessage {
        let nonce = makeNonce()
        state = .sentCommit(round: round, nonce: nonce, theirCommit: nil)
        return Self.message(.pairingCommit, round: round, "commit", commitment(round: round, nonce: nonce))
    }

    private func commitment(round: Int, nonce: Data) -> Data {
        Self.commitment(by: role, nonce: nonce, mine: ours.publicKey, theirs: theirKey,
                        transcript: transcript, round: round, bit: bit(round))
    }

    private func bit(_ round: Int) -> UInt8 {
        UInt8(((code ?? 0) >> round) & 1)
    }

    private func deriveSecret() -> Data {
        var info = transcript
        let value = UInt32(code ?? 0)
        info.append(contentsOf: [UInt8(value >> 24), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)])
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: shared),
            salt: lastEntererNonce + lastShowerNonce,
            info: info,
            outputByteCount: PairingSecret.byteCount
        ).withUnsafeBytes { Data($0) }
    }

    // MARK: - The bytes, as PROTOCOL.md 5.3 spells them

    /// `"Loom pairing v2"` and every field of both parties, each with its
    /// length in front, so that no two different sets of fields run together
    /// into the same bytes.
    public static func transcript(responder: PasskeyParty, initiator: PasskeyParty) -> Data {
        var out = Data("Loom pairing v2".utf8)
        func field(_ bytes: Data) {
            out.append(contentsOf: [UInt8(bytes.count >> 8 & 0xFF), UInt8(bytes.count & 0xFF)])
            out.append(bytes)
        }
        field(responder.fingerprint)
        field(initiator.fingerprint)
        field(responder.publicKey)
        field(initiator.publicKey)
        field(Data(responder.deviceID.utf8))
        field(Data(initiator.deviceID.utf8))
        field(Data(responder.deviceClass.rawValue.utf8))
        field(Data(initiator.deviceClass.rawValue.utf8))
        return out
    }

    /// `HMAC-SHA256(nonce, role ‖ own key ‖ other key ‖ T ‖ round ‖ 0x80|bit)`.
    /// The role is what stops a commitment being reflected back at its sender.
    static func commitment(
        by role: PasskeyRole, nonce: Data, mine: Data, theirs: Data,
        transcript: Data, round: Int, bit: UInt8
    ) -> Data {
        var data = Data([role.tag])
        data.append(mine)
        data.append(theirs)
        data.append(transcript)
        data.append(UInt8(round))
        data.append(0x80 | bit)
        return Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: nonce)))
    }

    static func checkMAC(secret: Data, by role: PasskeyRole, transcript: Data) -> Data {
        var data = Data("check".utf8)
        data.append(role.tag)
        data.append(transcript)
        return Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: secret)))
    }

    private static func check(secret: Data, by role: PasskeyRole, transcript: Data) -> WireMessage {
        WireMessage(type: .pairingCheck, payload: .object([
            "mac": .string(checkMAC(secret: secret, by: role, transcript: transcript).base64EncodedString())
        ]))
    }

    private static func message(_ kind: WireMessage.Kind, round: Int, _ key: String, _ bytes: Data) -> WireMessage {
        WireMessage(type: kind, payload: .object([
            "round": .int(Int64(round)),
            key: .string(bytes.base64EncodedString())
        ]))
    }

    private static func round(of message: WireMessage) -> Int? {
        guard let round = message.payload?["round"]?.intValue, (0..<Int64(rounds)).contains(round)
        else { return nil }
        return Int(round)
    }

    private static func bytes(_ message: WireMessage, _ key: String) -> Data? {
        message.payload?[key]?.stringValue.flatMap { Data(base64Encoded: $0) }
    }
}
