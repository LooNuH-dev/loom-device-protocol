import Crypto
import Foundation

/// What every way of pairing has to end up producing.
///
/// There are two ways in — an Apple device reading the secret its owner's other
/// devices already have, and a code typed in by hand — and the pairing design is explicit
/// that the cryptography does not differ between them, only where the secret
/// comes from. So the result is one type, and the ways of arriving at it are
/// interchangeable: the second can be added without disturbing anything that
/// reads what the first produced.
public struct Pairing: Equatable, Sendable {
    /// The host being paired with.
    public let peerDeviceID: String
    public let peerDeviceName: String

    /// Older names of `peerDeviceID` and `peerDeviceName`.
    public var hostDeviceID: String { peerDeviceID }
    public var hostDeviceName: String { peerDeviceName }
    /// SHA-256 of the host's certificate, which is what the client will pin.
    ///
    /// Nil on the host's own record of a client: only the host presents a
    /// certificate, so there is nothing on the other side to pin.
    public let certificateFingerprint: Data?
    /// The long-lived secret both ends keep. Never sent after this.
    public let sharedSecret: Data

    public init(
        peerDeviceID: String,
        peerDeviceName: String,
        certificateFingerprint: Data?,
        sharedSecret: Data
    ) {
        self.peerDeviceID = peerDeviceID
        self.peerDeviceName = peerDeviceName
        self.certificateFingerprint = certificateFingerprint
        self.sharedSecret = sharedSecret
    }

    /// The older spelling, from when the other device was always "the host".
    public init(
        hostDeviceID: String,
        hostDeviceName: String,
        certificateFingerprint: Data?,
        sharedSecret: Data
    ) {
        self.init(
            peerDeviceID: hostDeviceID, peerDeviceName: hostDeviceName,
            certificateFingerprint: certificateFingerprint, sharedSecret: sharedSecret
        )
    }

    public func asPairedDevice(at moment: Date = Date()) -> PairedDevice {
        PairedDevice(
            deviceID: peerDeviceID,
            deviceName: peerDeviceName,
            certificateFingerprint: certificateFingerprint,
            sharedSecret: sharedSecret,
            pairedAt: moment
        )
    }
}

/// A way of pairing. Both paths of the pairing design are one of these.
///
/// Deliberately narrow: it says what came out, not how. A route that reads a
/// secret the owner's devices already share reads what is already there; the
/// code path runs an exchange over a connection.
/// Nothing above needs to tell them apart.
public protocol PairingRoute: Sendable {
    /// Whether this route can be used on this device, in this state. A route
    /// that needs a shared account cannot on a device without one; the code
    /// one always can, which is
    /// why it is the only one a non-Apple client will have.
    var isAvailable: Bool { get }
}

/// Turning whatever a route agreed on into the secret that is actually kept.
///
/// Neither path hands over a key directly: a shared account carries a secret that is
/// shared by everything on that account, and an exchange produces a key bound
/// to that one run. Both are put through the same derivation so that what is
/// stored is bound to this pair of devices and to nothing else — and so that
/// the stored secret cannot be replayed as the input to another pairing.
public enum PairingSecret {

    /// Length chosen to match the hash behind it. More would be stored and
    /// never used; less would be the weakest thing in the chain.
    public static let byteCount = 32

    public static func derive(
        from material: Data,
        hostDeviceID: String,
        clientDeviceID: String,
        certificateFingerprint: Data
    ) -> Data {
        // The fingerprint goes into the derivation, not merely alongside it: a
        // secret derived without it would still be valid against a host that
        // had replaced its certificate, which is the one event that should
        // force a fresh pairing.
        var info = Data("Loom pairing v1".utf8)
        info.append(Data(hostDeviceID.utf8))
        info.append(Data(clientDeviceID.utf8))
        info.append(certificateFingerprint)

        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: material),
            info: info,
            outputByteCount: byteCount
        )
        return key.withUnsafeBytes { Data($0) }
    }

    /// A fresh secret for a host that has never paired with anything.
    public static func fresh() -> Data {
        var bytes = Data(count: byteCount)
        bytes.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            for offset in 0..<byteCount {
                base.storeBytes(
                    of: UInt8.random(in: 0...255), toByteOffset: offset, as: UInt8.self
                )
            }
        }
        return bytes
    }
}
