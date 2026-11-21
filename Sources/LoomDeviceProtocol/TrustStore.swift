import Crypto
import Foundation

/// What one device remembers about another it has been paired with.
///.
///
/// Pairing happens once; everything after it rests on this. Two things are
/// kept, and they answer different questions: the fingerprint answers "is this
/// the host I paired with", the secret answers "is this request from the device
/// I paired with".
public struct PairedDevice: Equatable, Sendable {
    public let deviceID: String
    /// What to call it when asking the person about it.
    public let deviceName: String
    /// SHA-256 of the other end's certificate, as presented at pairing time.
    /// Nil on the host's record of a client: only the host presents one.
    public let certificateFingerprint: Data?
    /// Derived at pairing. Never sent anywhere afterwards.
    public let sharedSecret: Data
    public let pairedAt: Date

    public init(
        deviceID: String,
        deviceName: String,
        certificateFingerprint: Data?,
        sharedSecret: Data,
        pairedAt: Date = Date()
    ) {
        self.deviceID = deviceID
        self.deviceName = deviceName
        self.certificateFingerprint = certificateFingerprint
        self.sharedSecret = sharedSecret
        self.pairedAt = pairedAt
    }
}

/// Where paired devices are remembered.
///
/// A protocol because the real one is the Keychain, and the Keychain is not
/// something to be reaching into from a test: it prompts, it persists between
/// runs, and on a build machine it may not be unlocked at all.
public protocol TrustStoring: Sendable {
    func paired() throws -> [PairedDevice]
    func remember(_ device: PairedDevice) throws
    func forget(deviceID: String) throws
}

public extension TrustStoring {
    func paired(deviceID: String) throws -> PairedDevice? {
        try paired().first { $0.deviceID == deviceID }
    }

    /// Whether a host presenting this certificate is the one that was paired
    /// with..6 — this is the pinning, and there is no fallback
    /// to an unchecked connection.
    func isTheDeviceWePairedWith(deviceID: String, presenting certificate: Data) throws -> Bool {
        guard let known = try paired(deviceID: deviceID),
              let expected = known.certificateFingerprint
        else { return false }

        return CertificateFingerprint.of(certificate).constantTimeEquals(expected)
    }
}

public enum CertificateFingerprint {
    /// SHA-256 over the certificate as it was sent — the DER bytes, not a
    /// parsed form of them. Two readers can disagree about how to parse a
    /// certificate; they cannot disagree about its bytes.
    public static func of(_ derBytes: Data) -> Data {
        Data(SHA256.hash(data: derBytes))
    }

    /// The form shown to a person when they are asked to compare two devices by
    /// eye: uppercase hex in pairs.
    public static func readable(_ fingerprint: Data) -> String {
        fingerprint.map { String(format: "%02X", $0) }
            .enumerated()
            .map { $0.offset > 0 && $0.offset % 2 == 0 ? " " + $0.element : $0.element }
            .joined()
    }
}

public extension Data {
    /// Compared without stopping at the first difference: a check that returns
    /// sooner for a closer guess tells the guesser how close they were.
    func constantTimeEquals(_ other: Data) -> Bool {
        guard count == other.count else { return false }

        var difference: UInt8 = 0
        for (mine, theirs) in zip(self, other) { difference |= mine ^ theirs }
        return difference == 0
    }
}

/// Remembers nothing beyond the life of the object. For tests, and for the
/// first run before anything has been paired.
public final class InMemoryTrustStore: TrustStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var devices: [String: PairedDevice] = [:]

    public init(_ devices: [PairedDevice] = []) {
        self.devices = Dictionary(uniqueKeysWithValues: devices.map { ($0.deviceID, $0) })
    }

    public func paired() throws -> [PairedDevice] {
        lock.lock(); defer { lock.unlock() }
        return devices.values.sorted { $0.pairedAt < $1.pairedAt }
    }

    public func remember(_ device: PairedDevice) throws {
        lock.lock(); devices[device.deviceID] = device; lock.unlock()
    }

    public func forget(deviceID: String) throws {
        lock.lock(); devices[deviceID] = nil; lock.unlock()
    }
}
