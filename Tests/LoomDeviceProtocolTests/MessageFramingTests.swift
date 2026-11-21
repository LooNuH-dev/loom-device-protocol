import XCTest
@testable import LoomDeviceProtocol

/// The wire format.
///
/// These tests are about what goes down the wire rather than about Swift: the
/// other end is meant to be able to be something else entirely, so the byte
/// order, the field names and the framing are the things worth pinning down.
final class MessageFramingTests: XCTestCase {

    private func hello() -> WireMessage {
        WireMessage(
            type: .hello,
            id: "m1",
            payload: .object([
                "proto": .int(Int64(WireProtocol.version)),
                "catalogRevision": .int(41209),
                "deviceId": .string("A3F2")
            ])
        )
    }

    // MARK: - Framing

    func testLengthIsFourBytesBigEndian() throws {
        let framed = try MessageFraming.frame(WireMessage(type: .hello))
        let body = framed.count - 4

        XCTAssertEqual(Array(framed.prefix(4)), [
            UInt8(truncatingIfNeeded: body >> 24),
            UInt8(truncatingIfNeeded: body >> 16),
            UInt8(truncatingIfNeeded: body >> 8),
            UInt8(truncatingIfNeeded: body)
        ])
        // Most significant byte first, whatever this machine would have done
        // left to itself.
        XCTAssertEqual(framed[0], 0)
        XCTAssertEqual(framed[1], 0)
    }

    func testAMessageSurvivesTheRoundTrip() throws {
        let sent = hello()
        var reader = MessageFraming.Reader()

        let received = try reader.read(MessageFraming.frame(sent))

        XCTAssertEqual(received, [sent])
        XCTAssertEqual(reader.pendingBytes, 0)
    }

    /// The case a real network produces rarely and at the worst moment.
    func testAMessageSplitAcrossPacketsIsRebuilt() throws {
        let sent = hello()
        let framed = try MessageFraming.frame(sent)
        var reader = MessageFraming.Reader()

        // One byte at a time: nothing until the last of them.
        for index in framed.indices.dropLast() {
            XCTAssertEqual(try reader.read(framed[index...index]), [])
        }
        let finished = try reader.read(framed[framed.indices.last!...])

        XCTAssertEqual(finished, [sent])
    }

    func testSeveralMessagesInOnePacketAllArrive() throws {
        let first = hello()
        let second = WireMessage(type: WireMessage.Kind(rawValue: "handoffAck"), replyTo: "m1", ok: true)
        var glued = try MessageFraming.frame(first)
        glued.append(try MessageFraming.frame(second))

        var reader = MessageFraming.Reader()

        XCTAssertEqual(try reader.read(glued), [first, second])
    }

    func testHalfOfASecondMessageIsHeldUntilTheRestArrives() throws {
        let first = hello()
        let second = WireMessage(type: WireMessage.Kind(rawValue: "catalogChanged"), payload: .object(["revision": .int(41210)]))
        let secondFramed = try MessageFraming.frame(second)

        var packet = try MessageFraming.frame(first)
        packet.append(secondFramed.prefix(6))

        var reader = MessageFraming.Reader()
        XCTAssertEqual(try reader.read(packet), [first])
        XCTAssertEqual(try reader.read(secondFramed.dropFirst(6)), [second])
    }

    /// A length prefix is four bytes anyone can send.
    func testAnAbsurdLengthIsRefusedWithoutAllocatingForIt() {
        let claimed = MessageFraming.maximumMessageBytes + 1
        var header = Data([
            UInt8(truncatingIfNeeded: claimed >> 24),
            UInt8(truncatingIfNeeded: claimed >> 16),
            UInt8(truncatingIfNeeded: claimed >> 8),
            UInt8(truncatingIfNeeded: claimed)
        ])
        header.append(contentsOf: [0x7b, 0x7d])

        var reader = MessageFraming.Reader()
        XCTAssertThrowsError(try reader.read(header)) { error in
            XCTAssertEqual(error as? MessageFraming.Failure, .messageTooLarge(claimed: claimed))
        }
    }

    func testRubbishInsideAWellFramedMessageIsRejected() {
        let body = Data("not json".utf8)
        var packet = Data([0, 0, 0, UInt8(body.count)])
        packet.append(body)

        var reader = MessageFraming.Reader()
        XCTAssertThrowsError(try reader.read(packet)) { error in
            XCTAssertEqual(error as? MessageFraming.Failure, .notValidJSON)
        }
    }

    // MARK: - What the fields are called

    /// The names are part of the protocol, not an implementation detail. A
    /// property renamed in Swift must not silently rename a field on the wire.
    func testTheFieldNamesAreTheOnesWritten() throws {
        let framed = try MessageFraming.frame(
            WireMessage(type: WireMessage.Kind(rawValue: "handoffRequest"), id: "m2", replyTo: "m1", ok: false,
                        payload: .object(["canonicalPositionMs": .int(102_000)]))
        )
        let json = String(decoding: framed.dropFirst(4), as: UTF8.self)

        XCTAssertEqual(
            json,
            #"{"id":"m2","ok":false,"payload":{"canonicalPositionMs":102000},"replyTo":"m1","type":"handoffRequest"}"#
        )
    }

    /// Absent rather than null: a reply carries `replyTo`, a request does not,
    /// and a wire full of nulls makes every reader check twice.
    func testFieldsThatDoNotApplyAreLeftOut() throws {
        let framed = try MessageFraming.frame(WireMessage(type: .init(rawValue: "stateUpdate")))
        let json = String(decoding: framed.dropFirst(4), as: UTF8.self)

        XCTAssertEqual(json, #"{"type":"stateUpdate"}"#)
    }

    /// A position in milliseconds must not come back as a fraction.
    func testWholeNumbersStayWhole() throws {
        let sent = WireMessage(type: .init(rawValue: "stateUpdate"), payload: .object([
            "canonicalPositionMs": .int(102_000)
        ]))
        var reader = MessageFraming.Reader()

        let back = try reader.read(MessageFraming.frame(sent)).first

        XCTAssertEqual(back?.payload?["canonicalPositionMs"], .int(102_000))
    }

    /// An older build meeting a newer one reads what it can rather than
    /// giving up on the connection.
    func testAnUnknownKindIsCarriedRatherThanRefused() throws {
        let body = Data(#"{"type":"somethingNewer","payload":{"a":1}}"#.utf8)
        var packet = Data([0, 0, 0, UInt8(body.count)])
        packet.append(body)

        var reader = MessageFraming.Reader()
        let read = try reader.read(packet).first

        XCTAssertEqual(read?.type.rawValue, "somethingNewer")
        XCTAssertEqual(read?.payload?["a"], .int(1))
    }

    /// Text is UTF-8, and a title that is not Latin has to survive it.
    func testTextIsCarriedAsUTF8() throws {
        let title = "Пусть будет так — 夜"
        let sent = WireMessage(type: .init(rawValue: "stateUpdate"), payload: .object(["title": .string(title)]))
        var reader = MessageFraming.Reader()

        let back = try reader.read(MessageFraming.frame(sent)).first

        XCTAssertEqual(back?.payload?["title"]?.stringValue, title)
    }
}
