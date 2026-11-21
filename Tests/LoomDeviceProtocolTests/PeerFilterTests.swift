import XCTest
@testable import LoomDeviceProtocol

/// A device may limit which peers it serves (PROTOCOL.md 1.4).
final class PeerFilterTests: XCTestCase {
    func testAbsentServesEveryone() {
        XCTAssertNil(PeerFilter(wire: nil))
        XCTAssertNil(PeerFilter(wire: " "))
        let ad = PeerAdvertisement(deviceName: "A", deviceID: "a", trackCount: 0, revision: 0, isPlaying: false)
        XCTAssertNil(ad.txtRecord["serves"])
        XCTAssertTrue(ad.serves(.android, sameHost: false))
    }

    func testClassesAndLocalAreRead() throws {
        let f = try XCTUnwrap(PeerFilter(wire: "ios,android;local"))
        XCTAssertEqual(f.classes, [.ios, .android])
        XCTAssertTrue(f.sameHostOnly)
        XCTAssertTrue(f.admits(.ios, sameHost: true))
        XCTAssertFalse(f.admits(.ios, sameHost: false))
        XCTAssertFalse(f.admits(.desktop, sameHost: true))
        XCTAssertFalse(f.admits(nil, sameHost: true), "no class reads as desktop")
        let any = try XCTUnwrap(PeerFilter(wire: "*;local"))
        XCTAssertNil(any.classes)
        XCTAssertTrue(any.admits(.desktop, sameHost: true))
        XCTAssertEqual(PeerFilter(wire: any.wire), any)
        XCTAssertEqual(PeerFilter(wire: "ios")?.wire, "ios")
    }

    func testUnknownClassesAreSkipped() throws {
        let f = try XCTUnwrap(PeerFilter(wire: "toaster,ios"))
        XCTAssertEqual(f.classes, [.ios])
        XCTAssertFalse(try XCTUnwrap(PeerFilter(wire: "toaster")).admits(.ios, sameHost: true))
    }

    func testTXTAndHelloCarryIt() throws {
        let filter = PeerFilter(classes: [.ios], sameHostOnly: true)
        let ad = PeerAdvertisement(deviceName: "Box", deviceID: "box", trackCount: 0, revision: 0, isPlaying: false,
                                   deviceClass: .desktop, capabilities: [.acquire], serves: filter)
        XCTAssertEqual(ad.txtRecord["serves"], "ios;local")
        let read = try XCTUnwrap(PeerAdvertisement(txtRecord: ad.txtRecord))
        XCTAssertEqual(read.serves, filter)
        XCTAssertFalse(read.mayAcquire(for: "me", as: .android, sameHost: true))
        XCTAssertFalse(read.mayAcquire(for: "me", as: .ios, sameHost: false))
        XCTAssertTrue(read.mayAcquire(for: "me", as: .ios, sameHost: true))
        XCTAssertFalse(read.mayBeLegacyHost(of: "me", as: .android))
        let hello = PeerHello(deviceID: "box", deviceName: "Box", features: [], capabilities: [], serves: filter)
        let back = try XCTUnwrap(PeerHello(hello.message()))
        XCTAssertEqual(back.serves, filter)
        XCTAssertFalse(back.serves(.desktop, sameHost: true))
    }
}
