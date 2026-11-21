import XCTest
@testable import LoomDeviceProtocol

/// What a host puts in its TXT record..2 and PROTOCOL.md 2.
///
/// These names go out on the network where anything may read them, so they are
/// pinned here rather than left to follow whatever the Swift properties are
/// called this week.
final class PeerAdvertisementTests: XCTestCase {

    private func advertisement(
        playing: Bool = false,
        proto: Int = WireProtocol.version
    ) -> PeerAdvertisement {
        PeerAdvertisement(
            protocolVersion: proto,
            deviceName: "Example-Laptop",
            deviceID: "A3F2",
            trackCount: 9847,
            revision: 41209,
            isPlaying: playing,
            deviceClass: .desktop
        )
    }

    func testTheRecordIsExactlyTheKeysWePublish() {
        XCTAssertEqual(advertisement().txtRecord, [
            "proto": "1",
            "versions": "1",
            "device": "Example-Laptop",
            "deviceid": "A3F2",
            "tracks": "9847",
            "rev": "41209",
            "playing": "0",
            "class": "desktop"
        ])
    }

    func testPlayingIsAFlagRatherThanAWord() {
        XCTAssertEqual(advertisement(playing: true).txtRecord["playing"], "1")
        XCTAssertEqual(advertisement(playing: false).txtRecord["playing"], "0")
    }

    func testTheServiceTypeIsTheOneBothEndsLookFor() {
        XCTAssertEqual(PeerAdvertisement.serviceType, "_loom._tcp")
    }

    func testWhatIsWrittenCanBeReadBack() {
        let sent = advertisement(playing: true)

        XCTAssertEqual(PeerAdvertisement(txtRecord: sent.txtRecord), sent)
    }

    /// A later version will add keys. An older build should still see the host.
    func testKeysWeDoNotKnowAreIgnored() {
        var record = advertisement().txtRecord
        record["somethingLater"] = "42"

        XCTAssertEqual(PeerAdvertisement(txtRecord: record), advertisement())
    }

    /// Not knowing how large a catalogue is does not make a host unreachable.
    func testSizeAndRevisionFallBackRatherThanFailing() {
        let read = PeerAdvertisement(txtRecord: [
            "proto": "1", "device": "Phone", "deviceid": "B1"
        ])

        XCTAssertEqual(read?.trackCount, 0)
        XCTAssertEqual(read?.revision, 0)
        XCTAssertEqual(read?.isPlaying, false)
    }

    func testSomethingElseOnTheNetworkIsNotMistakenForAHost() {
        XCTAssertNil(PeerAdvertisement(txtRecord: [:]))
        XCTAssertNil(PeerAdvertisement(txtRecord: ["device": "Printer"]))
        // Ours in shape, but with nothing to be recognised by later.
        XCTAssertNil(PeerAdvertisement(txtRecord: [
            "proto": "1", "device": "Phone", "deviceid": ""
        ]))
    }

    /// Better to leave a host out of the list than to let someone pick it and
    /// find out at the far end.
    func testAHostSpeakingAnotherVersionIsMarkedIncompatible() {
        XCTAssertTrue(advertisement().isCompatible)
        XCTAssertFalse(advertisement(proto: WireProtocol.version + 1).isCompatible)
    }

    /// A build from before 2026-10 says nothing about its class; that is not
    /// the same as saying "desktop".
    func testAMissingClassIsUnknownRatherThanDesktop() {
        let read = PeerAdvertisement(txtRecord: ["proto": "1", "device": "Old", "deviceid": "C1"])
        XCTAssertNil(read?.deviceClass)
        let phone = PeerAdvertisement(txtRecord: ["proto": "1", "device": "P", "deviceid": "D1", "class": "ios"])
        XCTAssertEqual(phone?.deviceClass, .ios)
    }

    func testAVersionOlderThanTheOldestKeptIsIncompatible() {
        XCTAssertFalse(advertisement(proto: WireProtocol.minimumVersion - 1).isCompatible)
    }

    /// An iPhone mirrors one device as its host the old way (`legacyHost`),
    /// which takes that device to hold the whole library: a Mac, or a build
    /// too old to say its class. Never a phone, which holds only what it
    /// fetched: an iPhone that took a paired Android for its host lost the
    /// paths of every file it kept.
    func testOnlyADesktopOrAnUnnamedClassServesAsTheOldKindOfHost() {
        func of(_ deviceClass: DeviceClass?) -> PeerAdvertisement {
            PeerAdvertisement(
                deviceName: "D", deviceID: "D", trackCount: 1, revision: 1, isPlaying: false, deviceClass: deviceClass
            )
        }
        XCTAssertTrue(of(.desktop).servesAsLegacyHost)
        XCTAssertTrue(of(nil).servesAsLegacyHost)
        XCTAssertFalse(of(.android).servesAsLegacyHost)
        XCTAssertFalse(of(.ios).servesAsLegacyHost)
        XCTAssertFalse(PeerAdvertisement(txtRecord: of(.android).txtRecord)!.servesAsLegacyHost)
    }

    /// The one question every client asks before it mirrors a device as its
    /// host: never itself, and only a device that holds the whole library.
    func testADeviceMayBeTakenForHostOnlyWhenItIsAnotherDesktop() {
        func of(_ id: String, _ deviceClass: DeviceClass?) -> PeerAdvertisement {
            PeerAdvertisement(
                deviceName: id, deviceID: id, trackCount: 1, revision: 1, isPlaying: false, deviceClass: deviceClass
            )
        }
        XCTAssertTrue(of("mac", .desktop).mayBeLegacyHost(of: "phone"))
        XCTAssertTrue(of("old", nil).mayBeLegacyHost(of: "phone"))
        XCTAssertFalse(of("phone", .desktop).mayBeLegacyHost(of: "phone"), "never itself")
        XCTAssertFalse(of("pixel", .android).mayBeLegacyHost(of: "phone"))
        XCTAssertFalse(of("iphone", .ios).mayBeLegacyHost(of: "phone"))
    }
}
