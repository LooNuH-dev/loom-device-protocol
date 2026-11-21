import Foundation
import XCTest
@testable import LoomDeviceProtocol

/// The data channel's HTTP, which is written here rather than taken from a
/// framework.
final class HTTPMessagesTests: XCTestCase {

    private func read(_ text: String) throws -> HTTPRequest? {
        var reader = HTTPRequestReader()
        return try reader.read(Data(text.utf8))
    }

    // MARK: - Reading a request

    func testAPlainRequestIsUnderstood() throws {
        let request = try read("GET /api/catalog HTTP/1.1\r\nHost: mac\r\n\r\n")

        XCTAssertEqual(request?.method, "GET")
        XCTAssertEqual(request?.path, "/api/catalog")
        XCTAssertEqual(request?.header("host"), "mac")
    }

    func testTheQueryIsSeparatedFromThePath() throws {
        let request = try read("GET /api/catalog?since=41209&full=1 HTTP/1.1\r\n\r\n")

        XCTAssertEqual(request?.path, "/api/catalog")
        XCTAssertEqual(request?.query["since"], "41209")
        XCTAssertEqual(request?.query["full"], "1")
    }

    /// Track identifiers travel in the path and are not all letters.
    func testAnEscapedPathIsUnescaped() throws {
        let request = try read("GET /api/artwork/a%2Fb%20c HTTP/1.1\r\n\r\n")

        XCTAssertEqual(request?.path, "/api/artwork/a/b c")
    }

    /// A header name is case-insensitive, and the other end may well be a
    /// client that capitalises differently.
    func testHeaderNamesAreNotCaseSensitive() throws {
        let request = try read("GET / HTTP/1.1\r\nRANGE: bytes=0-99\r\n\r\n")

        XCTAssertEqual(request?.header("Range"), "bytes=0-99")
        XCTAssertEqual(request?.header("range"), "bytes=0-99")
    }

    /// The same thing TCP does to messages, done to requests.
    func testARequestSplitAcrossPacketsIsRebuilt() throws {
        var reader = HTTPRequestReader()
        let whole = Data("POST /api/settings HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello".utf8)

        for index in whole.indices.dropLast() {
            XCTAssertNil(try reader.read(whole[index...index]))
        }
        let request = try reader.read(whole[whole.indices.last!...])

        XCTAssertEqual(request?.method, "POST")
        XCTAssertEqual(request?.body, Data("hello".utf8))
    }

    func testAHeadWithNoEndIsRefusedRatherThanBuffered() {
        var reader = HTTPRequestReader()
        let flood = Data(repeating: 0x41, count: HTTPRequestReader.maximumHeadBytes + 1)

        XCTAssertThrowsError(try reader.read(flood)) { error in
            XCTAssertEqual(error as? HTTPRequestReader.Failure, .headTooLarge)
        }
    }

    // MARK: - A body that goes to disk

    /// The head of an import is handed over as soon as it is whole, so the
    /// server can open a file before the file arrives. Waiting for the body
    /// would mean holding the whole of it in memory first.
    func testAnImportSurfacesOnItsHeadRatherThanItsBody() throws {
        var reader = HTTPRequestReader()
        let head = Data("POST /api/import HTTP/1.1\r\nContent-Length: 60000000\r\n\r\n".utf8)

        let request = try reader.read(head)

        XCTAssertEqual(request?.method, "POST")
        XCTAssertEqual(request?.path, "/api/import")
        XCTAssertEqual(request?.header("content-length"), "60000000")
        XCTAssertTrue(request?.body.isEmpty ?? false)
    }

    /// Whatever shared a packet with the head is the beginning of the file, and
    /// is handed over with it rather than dropped.
    func testTheFirstOfAnImportsBodyComesWithTheHead() throws {
        var reader = HTTPRequestReader()
        let start = Data("POST /api/import HTTP/1.1\r\nContent-Length: 900000\r\n\r\nfirst".utf8)

        let request = try reader.read(start)

        XCTAssertEqual(request?.body, Data("first".utf8))
    }

    /// The rest of the file is the caller's to pour to disk; nothing of it is
    /// kept here, and nothing further surfaces from this reader.
    func testTheRestOfAnImportIsNotBufferedHere() throws {
        var reader = HTTPRequestReader()
        _ = try reader.read(
            Data("POST /api/import HTTP/1.1\r\nContent-Length: 900000\r\n\r\n".utf8)
        )

        // Nothing of the import is left behind: what comes next is read as the
        // request it is, not as the tail of the one before.
        let next = try reader.read(Data("GET /api/catalog HTTP/1.1\r\n\r\n".utf8))

        XCTAssertEqual(next?.path, "/api/catalog")
        XCTAssertTrue(next?.body.isEmpty ?? false)
    }

    /// A route that does hold its body still holds it — and is refused above a
    /// size no such route has reason to send.
    func testAnOversizedHeldBodyIsRefused() {
        var reader = HTTPRequestReader()
        let length = HTTPRequestReader.maximumBufferedBodyBytes + 1
        let head = Data("POST /api/settings HTTP/1.1\r\nContent-Length: \(length)\r\n\r\n".utf8)

        XCTAssertThrowsError(try reader.read(head)) { error in
            XCTAssertEqual(error as? HTTPRequestReader.Failure, .bodyTooLarge)
        }
    }

    // MARK: - Ranges

    func testAnOrdinaryRangeIsRead() {
        let range = HTTPByteRange(header: "bytes=100-199")

        XCTAssertEqual(range?.start, 100)
        XCTAssertEqual(range?.end, 199)
        XCTAssertEqual(range?.resolved(within: 1000), 100..<200)
    }

    /// The form a resumed download uses: everything from here on.
    func testAnOpenEndedRangeRunsToTheEnd() {
        let range = HTTPByteRange(header: "bytes=900-")

        XCTAssertEqual(range?.resolved(within: 1000), 900..<1000)
    }

    func testASuffixRangeTakesTheLastBytes() {
        let range = HTTPByteRange(header: "bytes=-200")

        XCTAssertNil(range?.start ?? nil)
        XCTAssertEqual(range?.resolved(within: 1000), 800..<1000)
    }

    /// Asking for more than there is gets what there is, not an error.
    func testARangeReachingPastTheEndIsTrimmed() {
        XCTAssertEqual(HTTPByteRange(header: "bytes=900-5000")?.resolved(within: 1000), 900..<1000)
        XCTAssertEqual(HTTPByteRange(header: "bytes=-5000")?.resolved(within: 1000), 0..<1000)
    }

    /// Starting past the end is a different matter, and gets a different answer.
    func testARangeStartingPastTheEndResolvesToNothing() {
        XCTAssertNil(HTTPByteRange(header: "bytes=1000-")?.resolved(within: 1000))
    }

    /// Several ranges at once is legal HTTP answered with a multipart body.
    /// Nothing here asks for it, so it is refused rather than half-supported.
    func testSeveralRangesAtOnceAreRefused() {
        XCTAssertNil(HTTPByteRange(header: "bytes=0-99,200-299"))
    }

    func testRubbishInARangeHeaderIsNotARange() {
        XCTAssertNil(HTTPByteRange(header: "items=0-99"))
        XCTAssertNil(HTTPByteRange(header: "bytes=abc-def"))
        XCTAssertNil(HTTPByteRange(header: "bytes=200-100"))
    }

    // MARK: - Writing a response

    func testAResponseSaysHowLongItIs() {
        let bytes = HTTPResponse.json(Data(#"{"ok":true}"#.utf8)).serialised()
        let text = String(decoding: bytes, as: UTF8.self)

        XCTAssertTrue(text.hasPrefix("HTTP/1.1 200 OK\r\n"))
        XCTAssertTrue(text.contains("Content-Length: 11\r\n"))
        XCTAssertTrue(text.contains("Content-Type: application/json\r\n"))
        XCTAssertTrue(text.hasSuffix(#"{"ok":true}"#))
    }

    /// A client has no way to know it may resume unless it is told.
    func testEveryResponseOffersRanges() {
        let text = String(decoding: HTTPResponse.notFound().serialised(), as: UTF8.self)

        XCTAssertTrue(text.contains("Accept-Ranges: bytes\r\n"))
    }

    /// Without the total, a client resuming a download cannot tell when it is
    /// finished.
    func testPartialContentSaysWhichPartOfWhat() {
        let response = HTTPResponse.partial(
            Data(repeating: 0, count: 100), of: 1000, range: 900..<1000, type: "audio/mpeg"
        )
        let text = String(decoding: response.serialised(includeBody: false), as: UTF8.self)

        XCTAssertTrue(text.hasPrefix("HTTP/1.1 206 Partial Content\r\n"))
        XCTAssertTrue(text.contains("Content-Range: bytes 900-999/1000\r\n"))
    }

    func testARangeThatCannotBeMetSaysHowLongTheThingIs() {
        let text = String(
            decoding: HTTPResponse.rangeNotSatisfiable(of: 1000).serialised(), as: UTF8.self
        )

        XCTAssertTrue(text.hasPrefix("HTTP/1.1 416 "))
        XCTAssertTrue(text.contains("Content-Range: bytes */1000\r\n"))
    }

    /// A body streamed from a file is not held in the response, so the length
    /// cannot be counted from it. Announcing zero and then sending megabytes
    /// is read at the far end as an empty answer followed by rubbish.
    func testALengthGivenByHandIsNotOverwritten() {
        let response = HTTPResponse(
            status: 200, reason: "OK",
            headers: ["Content-Type": "audio/mpeg", "Content-Length": "9600000"]
        )
        let text = String(decoding: response.serialised(includeBody: false), as: UTF8.self)

        XCTAssertTrue(text.contains("Content-Length: 9600000\r\n"))
        XCTAssertFalse(text.contains("Content-Length: 0\r\n"))
    }

    func testPartialContentSaysHowMuchFollows() {
        let response = HTTPResponse.partial(
            Data(), of: 1000, range: 600..<1000, type: "audio/mpeg"
        )
        let text = String(decoding: response.serialised(includeBody: false), as: UTF8.self)

        XCTAssertTrue(text.contains("Content-Length: 400\r\n"))
    }

    /// The channel serves a catalogue, then artwork, then files. Closing after
    /// each would pay for a TLS handshake every time.
    func testTheConnectionIsKeptOpen() {
        let text = String(decoding: HTTPResponse.notFound().serialised(), as: UTF8.self)

        XCTAssertTrue(text.contains("Connection: keep-alive\r\n"))
    }
}
