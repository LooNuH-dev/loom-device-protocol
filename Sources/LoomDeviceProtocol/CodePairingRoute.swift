import Crypto
import Foundation

/// Pairing two devices that share no account, by showing the same six digits on
/// both and having a person say whether they match.
///
/// This is not the path the pairing design sketches, and the difference is deliberate.
/// That one has the host show a code and the person type it into the client,
/// which needs a password-authenticated exchange — six digits are a million
/// guesses, and only a PAKE turns that into a key an eavesdropper cannot chase
/// offline. There is no PAKE available here: neither CryptoKit nor swift-crypto
/// exposes the arithmetic one is built from, and writing that arithmetic is
/// precisely what the pairing design forbids.
///
/// So the direction is reversed. Both ends agree a strong key by ordinary key
/// agreement, and the digits are computed *from* that key rather than being the
/// input to it. A person compares two screens instead of typing. The digits
/// carry no secret and are worth nothing to anyone who reads them — what they
/// prove is that the two ends agreed the same key, which is exactly what
/// somebody in the middle cannot arrange: they would have to agree one key with
/// each side, and the two screens would then disagree.
///
/// The same shape as numeric comparison in Bluetooth pairing and the short
/// authentication string in ZRTP, and portable: any client that can do ECDH on
/// P-256 and SHA-256 can implement it.
public struct CodePairingRoute: PairingRoute {

    /// Always. Nothing is needed but the two devices and the person holding
    /// them, which is why this is the path a client outside this ecosystem
    /// uses.
    public var isAvailable: Bool { true }

    public init() {}

    /// One side's half of the exchange, kept only until it finishes.
    public struct Half: Sendable {
        let privateKey: P256.KeyAgreement.PrivateKey
        public let deviceID: String
        public let deviceName: String

        /// What goes to the other side.
        public var publicKey: Data { privateKey.publicKey.rawRepresentation }

        public init(deviceID: String, deviceName: String) {
            self.privateKey = P256.KeyAgreement.PrivateKey()
            self.deviceID = deviceID
            self.deviceName = deviceName
        }
    }

    /// What both ends arrive at, and the digits a person is asked about.
    public struct Agreement: Equatable, Sendable {
        public let sharedSecret: Data
        /// Shown on both screens. Six digits, because that is what a person
        /// will actually compare.
        public let confirmationCode: String
    }

    public enum Failure: Error, Equatable {
        case notAPublicKey
    }

    /// Works out what this side agrees with the other.
    ///
    /// - Parameters:
    ///   - hostFingerprint: the certificate the connection is running over.
    ///     Included so that the agreement is bound to this connection: someone
    ///     relaying a pairing over their own TLS session presents a different
    ///     certificate, and the digits change.
    ///   - hostDeviceID: which of the two is the host, so both sides feed the
    ///     transcript in the same order. Without that the two would derive from
    ///     different orderings and never agree.
    public static func agree(
        ours: Half,
        theirPublicKey: Data,
        theirDeviceID: String,
        hostFingerprint: Data,
        hostDeviceID: String
    ) throws -> Agreement {
        guard let theirs = try? P256.KeyAgreement.PublicKey(rawRepresentation: theirPublicKey)
        else { throw Failure.notAPublicKey }

        let agreed = try ours.privateKey.sharedSecretFromKeyAgreement(with: theirs)

        // Both public keys go into the transcript, host's first. An agreement
        // that did not commit to them could be repeated by someone who had
        // watched one — and the digits would agree while the parties did not.
        let isHost = ours.deviceID == hostDeviceID
        var transcript = Data("Loom pairing v1".utf8)
        transcript.append(hostFingerprint)
        transcript.append(isHost ? ours.publicKey : theirPublicKey)
        transcript.append(isHost ? theirPublicKey : ours.publicKey)
        transcript.append(Data((isHost ? ours.deviceID : theirDeviceID).utf8))
        transcript.append(Data((isHost ? theirDeviceID : ours.deviceID).utf8))

        let secret = agreed.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: transcript,
            outputByteCount: PairingSecret.byteCount
        )
        let sharedSecret = secret.withUnsafeBytes { Data($0) }

        return Agreement(
            sharedSecret: sharedSecret,
            confirmationCode: code(from: sharedSecret, transcript: transcript)
        )
    }

    /// The digits, derived from the agreed key rather than being its input.
    ///
    /// Kept apart from the key itself by a separate derivation, so that showing
    /// them on two screens — and to anyone standing nearby — gives away nothing
    /// about the key underneath.
    private static func code(from secret: Data, transcript: Data) -> String {
        var info = Data("Loom pairing code v1".utf8)
        info.append(transcript)

        let material = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: secret),
            info: info,
            outputByteCount: 8
        ).withUnsafeBytes { Data($0) }

        // Taken from a whole eight bytes and reduced, rather than a digit per
        // byte: a digit per byte would waste most of each one and skew the
        // result towards its low values.
        let number = material.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        return String(format: "%06llu", number % 1_000_000)
    }

    /// What each side keeps once the person has said the digits match.
    public static func pairing(
        with agreement: Agreement,
        hostDeviceID: String,
        hostDeviceName: String,
        hostFingerprint: Data
    ) -> Pairing {
        Pairing(
            hostDeviceID: hostDeviceID,
            hostDeviceName: hostDeviceName,
            certificateFingerprint: hostFingerprint,
            sharedSecret: agreement.sharedSecret
        )
    }
}
