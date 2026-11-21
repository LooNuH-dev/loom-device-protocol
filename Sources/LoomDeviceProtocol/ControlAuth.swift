import Crypto
import Foundation

/// Both ends of a control connection proving they hold the pair's secret.
/// See PROTOCOL.md 3.3.
///
/// TLS proves the side that listens to the side that connected. Nothing
/// proved the other direction: the listener believed whatever `deviceId` the
/// `hello` named, until a signed data request happened to arrive from the same
/// address. `auth` closes that on the control channel itself, with the secret
/// both already keep, so no client certificate is needed — their support on
/// Android and Windows is uneven, and a self-signed one would need checking by
/// hand anyway.
public enum ControlAuth {

    public static let nonceLength = 16

    public static func freshNonce() -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<nonceLength).map { _ in UInt8.random(in: 0...255, using: &generator) })
    }

    /// `HMAC-SHA256(secret, "Loom auth v1" ‖ len16(sender) ‖ len16(receiver)
    /// ‖ nonce_I ‖ nonce_R ‖ len16(fp_R))`.
    ///
    /// The sender comes first, so one side's proof is no use returned to it.
    /// The responder's certificate ties the proof to this TLS session: someone
    /// relaying it over their own sees another certificate.
    public static func proof(
        secret: Data,
        sender: String,
        receiver: String,
        initiatorNonce: Data,
        responderNonce: Data,
        responderFingerprint: Data
    ) -> Data {
        var data = Data("Loom auth v1".utf8)
        func field(_ bytes: Data) {
            data.append(contentsOf: [UInt8(bytes.count >> 8 & 0xFF), UInt8(bytes.count & 0xFF)])
            data.append(bytes)
        }
        field(Data(sender.utf8))
        field(Data(receiver.utf8))
        data.append(initiatorNonce)
        data.append(responderNonce)
        field(responderFingerprint)
        return Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: secret)))
    }

    public static func message(proof: Data) -> WireMessage {
        WireMessage(type: .auth, payload: .object(["proof": .string(proof.base64EncodedString())]))
    }

    /// Whether an `auth` message carries the proof expected of its sender.
    public static func holds(_ message: WireMessage, expected: Data) -> Bool {
        guard message.type == .auth,
              let sent = message.payload?["proof"]?.stringValue.flatMap({ Data(base64Encoded: $0) })
        else { return false }
        return sent.constantTimeEquals(expected)
    }
}
