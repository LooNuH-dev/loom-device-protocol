import XCTest
@testable import LoomDeviceProtocol

/// Fetch → hand over → confirm → delete, for a device that keeps no library.
final class HandoverTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    func testTheWholeHandover() throws {
        // Asker: serviceFetch. Acquirer: takes it, names the fetch.
        let answer = Handover.accepted(replyingTo: "m1", fetchID: "F1")
        XCTAssertEqual(Handover.fetchID(in: try roundTrip(answer)), "F1")

        // Acquirer: the file is ready, held for the asker only.
        var ledger = Handover.Ledger()
        XCTAssertNil(ledger.hold(fetchID: "F1", fileID: "v-42", for: "phone", at: now))
        let ready = Handover.Ready(fetchID: "F1", fileID: "v-42", bytes: 10, sha256: Data(repeating: 1, count: 32), format: "flac")
        let read = try XCTUnwrap(Handover.Ready(try roundTrip(ready.message(id: "m2"))))
        XCTAssertEqual(read, ready)
        XCTAssertEqual(read.path, "/api/variant/v-42")
        XCTAssertTrue(ledger.mayRead("v-42", by: "phone"))
        XCTAssertFalse(ledger.mayRead("v-42", by: "other"))

        // Asker: has it. Only its own confirmation releases the file.
        let done = Handover.done(fetchID: "F1", fileID: "v-42", kept: true)
        XCTAssertNil(ledger.release(done, from: "other"))
        XCTAssertNil(ledger.release(Handover.done(fetchID: "F9", fileID: "v-42", kept: true), from: "phone"))
        XCTAssertEqual(ledger.release(try roundTrip(done), from: "phone")?.fileID, "v-42")
        XCTAssertTrue(ledger.held.isEmpty)
    }

    func testAFailedFetchSaysWhyAndNamesNoFile() throws {
        let failed = Handover.Ready(fetchID: "F1", fileID: nil, reason: "Not found")
        let read = try XCTUnwrap(Handover.Ready(try roundTrip(failed.message())))
        XCTAssertNil(read.fileID)
        XCTAssertEqual(read.reason, "Not found")
    }

    func testUnsafeFileIDsAreRefused() {
        for id in ["", ".", "..", "../x", "a/b", "a?b", "a b", String(repeating: "a", count: 129)] {
            let message = WireMessage(type: .fetchReady, ok: true, payload: .object(["fetchId": .string("F"), "fileId": .string(id)]))
            XCTAssertNil(Handover.Ready(message), id)
        }
    }

    func testUnclaimedFilesExpireAndTheLedgerIsBounded() {
        var ledger = Handover.Ledger()
        _ = ledger.hold(fetchID: "F", fileID: "a", for: "p", at: now)
        XCTAssertEqual(ledger.expired(at: now.addingTimeInterval(Handover.Ledger.patience)).map(\.fileID), ["a"])
        for index in 0..<Handover.Ledger.capacity {
            _ = ledger.hold(fetchID: "F", fileID: "f\(index)", for: "p", at: now.addingTimeInterval(Double(index)))
        }
        XCTAssertEqual(ledger.hold(fetchID: "F", fileID: "new", for: "p", at: now)?.fileID, "f0")
        XCTAssertEqual(ledger.held.count, Handover.Ledger.capacity)
    }

    private func roundTrip(_ message: WireMessage) throws -> WireMessage {
        var reader = MessageFraming.Reader()
        return try XCTUnwrap(reader.read(try MessageFraming.frame(message)).first)
    }

    func testASuccessWithoutSizeOrDigestIsIgnored() throws {
        let digest = Data(repeating: 1, count: 32)
        for ready in [Handover.Ready(fetchID: "F1", fileID: "v-1", sha256: digest),
                      Handover.Ready(fetchID: "F1", fileID: "v-1", bytes: 10),
                      Handover.Ready(fetchID: "F1", fileID: "v-1", bytes: 10, sha256: Data(count: 8)),
                      Handover.Ready(fetchID: "F1", fileID: "v-1", bytes: -1, sha256: digest)] {
            XCTAssertNil(Handover.Ready(try roundTrip(ready.message())))
        }
        let failed = Handover.Ready(fetchID: "F1", fileID: nil, reason: "Gone")
        XCTAssertNotNil(Handover.Ready(try roundTrip(failed.message())), "a failure needs neither")
    }
}
