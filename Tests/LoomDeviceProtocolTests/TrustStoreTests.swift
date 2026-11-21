import XCTest
@testable import LoomDeviceProtocol

/// What is remembered after pairing, and what it is good for.
final class TrustStoreTests: XCTestCase {

    private let certificate = Data("a certificate, in the shape it was sent".utf8)

    /// A fixed moment, so that two records built from the same description are
    /// the same record.
    private let pairedAt = Date(timeIntervalSinceReferenceDate: 0)

    private func paired(id: String = "host-1") -> PairedDevice {
        PairedDevice(
            deviceID: id,
            deviceName: "Example-Laptop",
            certificateFingerprint: CertificateFingerprint.of(certificate),
            sharedSecret: Data(repeating: 0xAB, count: 32),
            pairedAt: pairedAt
        )
    }

    func testAPairedDeviceIsRememberedAndCanBeForgotten() throws {
        let store = InMemoryTrustStore()
        try store.remember(paired())

        XCTAssertEqual(try store.paired(deviceID: "host-1"), paired())

        try store.forget(deviceID: "host-1")
        XCTAssertNil(try store.paired(deviceID: "host-1"))
    }

    func testPairingAgainReplacesRatherThanDuplicates() throws {
        let store = InMemoryTrustStore()
        try store.remember(paired())
        try store.remember(PairedDevice(
            deviceID: "host-1",
            deviceName: "Renamed",
            certificateFingerprint: CertificateFingerprint.of(certificate),
            sharedSecret: Data(repeating: 0xCD, count: 32),
            pairedAt: pairedAt
        ))

        XCTAssertEqual(try store.paired().count, 1)
        XCTAssertEqual(try store.paired(deviceID: "host-1")?.deviceName, "Renamed")
    }

    // MARK: - Pinning

    func testTheHostWePairedWithIsRecognised() throws {
        let store = InMemoryTrustStore([paired()])

        XCTAssertTrue(
            try store.isTheDeviceWePairedWith(deviceID: "host-1", presenting: certificate)
        )
    }

    /// The whole point of pinning: knowing the service name and the device
    /// identifier is not enough to be taken for the host.
    func testAnImpostorPresentingAnotherCertificateIsRefused() throws {
        let store = InMemoryTrustStore([paired()])

        XCTAssertFalse(try store.isTheDeviceWePairedWith(
            deviceID: "host-1",
            presenting: Data("a different certificate entirely".utf8)
        ))
    }

    /// A single flipped bit is a different certificate.
    func testACertificateAlteredByOneByteIsRefused() throws {
        let store = InMemoryTrustStore([paired()])
        var altered = certificate
        altered[0] ^= 0x01

        XCTAssertFalse(
            try store.isTheDeviceWePairedWith(deviceID: "host-1", presenting: altered)
        )
    }

    /// Nothing was paired, so nothing is trusted. There is no state in which an
    /// unknown device is given the benefit of the doubt.
    func testAnUnknownDeviceIsNotTrusted() throws {
        let store = InMemoryTrustStore()

        XCTAssertFalse(
            try store.isTheDeviceWePairedWith(deviceID: "host-1", presenting: certificate)
        )
    }

    // MARK: - Fingerprints

    func testTheFingerprintIsOverTheBytesAsSent() {
        // Known SHA-256 of "abc", so this is pinned against the algorithm
        // rather than against our own implementation of it.
        let digest = CertificateFingerprint.of(Data("abc".utf8))

        XCTAssertEqual(
            digest.map { String(format: "%02x", $0) }.joined(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
    }

    func testAFingerprintCanBeReadOutLoud() {
        let shown = CertificateFingerprint.readable(Data([0x0A, 0xB3, 0xFF, 0x00]))

        XCTAssertEqual(shown, "0AB3 FF00")
    }
}
