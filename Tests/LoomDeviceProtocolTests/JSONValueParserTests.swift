import Foundation
import XCTest
@testable import LoomDeviceProtocol

/// The one-pass reader gives exactly what `JSONDecoder` gives for
/// `JSONValue` and `WireMessage`, on every platform the tests run on: a
/// peer's message must mean the same whichever way it was read.
final class JSONValueParserTests: XCTestCase {

    private static let texts: [String] = [
        "null", "true", "false", "0", "-0", "1", "-1", "42", "9223372036854775807",
        "-9223372036854775808", "9223372036854775808", "18446744073709551615",
        "1.5", "-2.25", "2.0", "1e3", "1E-2", "1.0e2", "0.1", "123456789012345678901234567890",
        "3.141592653589793", "1e308",
        "\"\"", "\"plain\"", "\"esc \\\" \\\\ \\/ \\b \\f \\n \\r \\t\"", "\"\\u00e9\\u4e2d\"",
        "\"\\ud83c\\udfb5 note\"", "\"Кириллица и 日本語 🎵\"",
        "[]", "{}", "[1,\"a\",null,true,[2,[3]],{\"k\":[]}]",
        "{\"a\":1,\"b\":{\"c\":[1.5,\"x\"]},\"d\":null}",
        "  { \"spaced\" : [ 1 , 2 ] }  ",
        "{\"dup\":1,\"dup\":2}",
        // JSONDecoder lets a trailing comma through; so must this.
        "[1,]", "{\"a\":1,}", "[[1,],{\"b\":[],},]",
    ]

    private static let broken: [String] = [
        "", " ", "nul", "tru", "01", "1.", ".5", "-", "1e", "+1", "[,]", "{,}", "[1,,]", "[1 2]",
        "{\"a\" 1}", "{a:1}", "\"open", "\"bad \\x\"", "\"lone \\ud800\"", "\"ctrl \u{01}\"",
        "[", "{", "1 2", "NaN", "Infinity",
    ]

    private func viaDecoder(_ text: String) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: Data(text.utf8))
    }

    func testSameValuesAsJSONDecoder() throws {
        for text in Self.texts {
            let expected = try viaDecoder(text)
            XCTAssertEqual(try JSONValueParser.parse(Data(text.utf8)), expected, text)
        }
    }

    func testRefusesWhatJSONDecoderRefuses() {
        for text in Self.broken {
            XCTAssertThrowsError(try viaDecoder(text), "JSONDecoder read \(text)")
            XCTAssertThrowsError(try JSONValueParser.parse(Data(text.utf8)), text)
        }
    }

    func testRefusesInvalidUTF8() {
        let bytes = Data([0x22, 0xC3, 0x28, 0x22])
        XCTAssertThrowsError(try JSONDecoder().decode(JSONValue.self, from: bytes))
        XCTAssertThrowsError(try JSONValueParser.parse(bytes))
    }

    func testRefusesHostileDepth() {
        let deep = String(repeating: "[", count: 10_000) + String(repeating: "]", count: 10_000)
        XCTAssertThrowsError(try JSONValueParser.parse(Data(deep.utf8)))
    }

    func testMessagesReadAlike() throws {
        let messages: [WireMessage] = [
            WireMessage(type: .hello),
            WireMessage(type: .init(rawValue: "stateUpdate"), id: "a1", payload: .object([
                "positionMs": .int(41_209), "rate": .double(1.5), "title": .string("Ünïcødé 🎵"),
                "queue": .array([.object(["id": .string("t"), "n": .null])]),
            ])),
            WireMessage(type: WireMessage.Kind(rawValue: "handoffAck"), replyTo: "a1", ok: false),
            WireMessage(type: WireMessage.Kind(rawValue: "fromTheFuture"), payload: .bool(true)),
        ]
        for message in messages {
            let body = try JSONEncoder().encode(message)
            XCTAssertEqual(try JSONValueParser.message(body), try JSONDecoder().decode(WireMessage.self, from: body))
        }
        let nulls = Data(#"{"type":"hello","id":null,"replyTo":null,"ok":null,"payload":null}"#.utf8)
        XCTAssertEqual(try JSONValueParser.message(nulls), try JSONDecoder().decode(WireMessage.self, from: nulls))
        for bad in [#"{"id":"x"}"#, #"{"type":1}"#, #"{"type":"hello","ok":"yes"}"#, #"{"type":"hello","id":7}"#, "[1]"] {
            XCTAssertThrowsError(try JSONDecoder().decode(WireMessage.self, from: Data(bad.utf8)), bad)
            XCTAssertThrowsError(try JSONValueParser.message(Data(bad.utf8)), bad)
        }
    }

    /// Not a check, a number for the record: a sync-sized message both ways.
    func testSpeedOnAMegabyte() throws {
        let entries = (0..<4_000).map { index -> JSONValue in
            .object(["trackId": .string(UUID().uuidString), "clock": .int(Int64(index)),
                     "text": .string(String(repeating: "[00:12.34] a line of lyrics ", count: 8)),
                     "synced": .bool(index % 2 == 0), "offset": .double(0.25)])
        }
        let body = try JSONEncoder().encode(WireMessage(type: WireMessage.Kind(rawValue: "favoriteChanged"), id: "x",
                                                        payload: .object(["lyrics": .array(entries)])))
        let clock = ContinuousClock()
        let viaDecoder = try clock.measure { _ = try JSONDecoder().decode(WireMessage.self, from: body) }
        let viaParser = try clock.measure { _ = try JSONValueParser.message(body) }
        print("JSONValueParser speed: \(body.count) bytes, JSONDecoder \(viaDecoder), parser \(viaParser)")
    }

    /// The reader framing uses: a stream of messages split anywhere still
    /// gives each one whole, as before.
    func testFramingStillReadsSplitStreams() throws {
        let sent = (0..<20).map { WireMessage(type: .init(rawValue: "stateUpdate"), id: "m\($0)", payload: .object(["i": .int(Int64($0))])) }
        var stream = Data()
        for message in sent { stream.append(try MessageFraming.frame(message)) }
        var reader = MessageFraming.Reader()
        var read: [WireMessage] = []
        var offset = 0
        while offset < stream.count {
            let end = min(stream.count, offset + 7)
            read += try reader.read(stream.subdata(in: offset..<end))
            offset = end
        }
        XCTAssertEqual(read, sent)
    }
}
