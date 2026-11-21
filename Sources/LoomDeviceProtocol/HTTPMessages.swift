import Foundation

/// A request as it arrives on the data channel.
///
/// Parsed here rather than by a web framework. What is served is four routes
/// over a connection the two ends have already authenticated to each other —
/// bringing in something built for the public internet would be several
/// thousand lines to answer four questions.
///
/// HTTP is the right shape all the same: `Range` is what makes a half-finished
/// download resumable, and every platform has a client that speaks it.
public struct HTTPRequest: Equatable, Sendable {
    public let method: String
    /// The path with no query on it.
    public let path: String
    public let query: [String: String]
    /// Lowercased, because a header name is case-insensitive and a reader that
    /// forgets is a reader that works until the other end capitalises.
    public let headers: [String: String]
    public let body: Data

    public init(
        method: String,
        path: String,
        query: [String: String] = [:],
        headers: [String: String] = [:],
        body: Data = Data()
    ) {
        self.method = method
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body
    }

    public func header(_ name: String) -> String? { headers[name.lowercased()] }

    /// What the client is asking for, when it is asking for part of something.
    public var requestedRange: HTTPByteRange? {
        header("range").flatMap(HTTPByteRange.init(header:))
    }
}

/// A byte range as `Range:` states it. See RFC 9110 §14.
public struct HTTPByteRange: Equatable, Sendable {
    /// Nil means "the last `length` bytes", which is the suffix form.
    public let start: Int64?
    public let end: Int64?

    public init(start: Int64?, end: Int64?) {
        self.start = start
        self.end = end
    }

    /// Only the single-range form. Multiple ranges in one request are legal
    /// HTTP and answered with a multipart body, which nothing here asks for —
    /// so they are refused rather than half-supported.
    public init?(header: String) {
        let trimmed = header.trimmingCharacters(in: .whitespaces)
        guard trimmed.lowercased().hasPrefix("bytes=") else { return nil }

        let spec = trimmed.dropFirst("bytes=".count)
        guard !spec.contains(",") else { return nil }

        let parts = spec.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }

        let first = parts[0].trimmingCharacters(in: .whitespaces)
        let second = parts[1].trimmingCharacters(in: .whitespaces)

        if first.isEmpty {
            guard let suffix = Int64(second), suffix > 0 else { return nil }
            self.start = nil
            self.end = suffix
        } else {
            guard let from = Int64(first) else { return nil }
            self.start = from
            self.end = second.isEmpty ? nil : Int64(second)
            if let end, end < from { return nil }
        }
    }

    /// Where this range actually falls in something of a given size.
    ///
    /// Nil when it falls outside it altogether, which is a different answer
    /// from an empty range and gets a different status.
    public func resolved(within total: Int64) -> Range<Int64>? {
        guard total > 0 else { return nil }

        if let start {
            guard start < total else { return nil }
            let last = min(end ?? total - 1, total - 1)
            return start..<(last + 1)
        }
        // The suffix form: the last so many bytes, or all of them if it asks
        // for more than there are.
        guard let end else { return nil }
        return max(0, total - end)..<total
    }
}

/// What goes back.
public struct HTTPResponse: Sendable {
    public let status: Int
    public let reason: String
    public var headers: [String: String]
    public let body: Data

    public init(
        status: Int,
        reason: String,
        headers: [String: String] = [:],
        body: Data = Data()
    ) {
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body
    }

    public static func ok(_ body: Data, type: String) -> HTTPResponse {
        HTTPResponse(status: 200, reason: "OK", headers: ["Content-Type": type], body: body)
    }

    public static func json(_ body: Data) -> HTTPResponse {
        ok(body, type: "application/json")
    }

    /// Part of something, with the header that says which part of what.
    ///
    /// The total length matters as much as the range: without it a client
    /// resuming a download has no way to know when it is finished.
    public static func partial(
        _ body: Data,
        of total: Int64,
        range: Range<Int64>,
        type: String
    ) -> HTTPResponse {
        HTTPResponse(
            status: 206,
            reason: "Partial Content",
            headers: [
                "Content-Type": type,
                "Content-Range": "bytes \(range.lowerBound)-\(range.upperBound - 1)/\(total)",
                // How much follows, which for a body streamed from a file is
                // not how much is held here — and here it is nothing at all.
                "Content-Length": String(range.count)
            ],
            body: body
        )
    }

    public static func notFound() -> HTTPResponse {
        HTTPResponse(status: 404, reason: "Not Found")
    }

    /// - Parameter because: which of the several ways a request can fail to
    ///   prove itself. Said out loud rather than swallowed: "401" alone leaves
    ///   a person guessing between a device that was never paired, a clock that
    ///   is wrong and a secret that does not match, and those are three
    ///   different things to go and fix.
    public static func unauthorised(because reason: String) -> HTTPResponse {
        HTTPResponse(
            status: 401,
            reason: "Unauthorized",
            headers: ["Content-Type": "application/json"],
            body: Data(#"{"reason":"\#(reason)"}"#.utf8)
        )
    }

    /// Asked for a range that is not in the thing at all.
    public static func rangeNotSatisfiable(of total: Int64) -> HTTPResponse {
        HTTPResponse(
            status: 416,
            reason: "Range Not Satisfiable",
            headers: ["Content-Range": "bytes */\(total)"]
        )
    }

    /// The bytes as they go on the wire.
    public func serialised(includeBody: Bool = true) -> Data {
        var head = "HTTP/1.1 \(status) \(reason)\r\n"
        var all = headers
        // Only when nobody has said. A body read off a disk as it goes is not
        // in `body` at all, and a length taken from what is held here would
        // announce zero bytes and then send megabytes — which the far end
        // reads as an empty answer followed by rubbish.
        if all["Content-Length"] == nil {
            all["Content-Length"] = String(body.count)
        }
        // Every response says how long it is and the connection stays open:
        // this channel serves several requests in a row — a catalogue, then
        // artwork, then files — and closing after each would pay for a TLS
        // handshake every time.
        all["Connection"] = "keep-alive"
        // Ranges are the whole reason this is HTTP; a client has no way to know
        // it may ask for one unless it is told.
        if all["Accept-Ranges"] == nil { all["Accept-Ranges"] = "bytes" }

        for name in all.keys.sorted() {
            head += "\(name): \(all[name]!)\r\n"
        }
        head += "\r\n"

        var bytes = Data(head.utf8)
        if includeBody { bytes.append(body) }
        return bytes
    }
}

/// Collects bytes until there is a whole request, the way the control channel's
/// reader does for messages. TCP gives no more respect to request boundaries
/// than it does to message ones.
public struct HTTPRequestReader {
    /// Enough for the head of any request this serves. An import's body
    /// streams to disk rather than through here; every other body is held.
    public static let maximumHeadBytes = 64 * 1024

    /// As much of a held body as an ordinary route has reason to take.
    ///
    /// This bound is applied to a declared `Content-Length` before anything has
    /// proved who is asking, so it is what an unpaired peer can make this host
    /// hold per connection. Small, and raised only where a route needs it.
    public static let maximumBufferedBodyBytes = 1024 * 1024

    /// What the catalogue offer route is allowed instead, so that a body
    /// between the two bounds is not refused here — where the reason can only
    /// be "malformed" — before reaching the route that has a size to say.
    public static let maximumOfferedBodyBytes = 16 * 1024 * 1024

    public enum Failure: Error, Equatable {
        case headTooLarge
        case bodyTooLarge
        case malformed
    }

    private var buffered = Data()

    public init() {}

    /// Whether nothing of a next request has arrived yet: the connection is
    /// between requests, holding no buffer.
    public var isEmpty: Bool { buffered.isEmpty }

    /// Whether this request's body goes to disk rather than through here.
    ///
    /// Import, and only import. Its head is handed over the moment it is
    /// complete so the server can open a file and let the rest of the bytes
    /// pour into it — waiting for the body first would mean holding a whole
    /// album in memory to prove it was worth writing down.
    public static func bodyStreams(method: String, path: String) -> Bool {
        method == "POST" && path == "/api/import"
    }

    /// How much body this request may hold before it is refused.
    ///
    /// Decided by route, the way streaming is: the two offer routes are the
    /// only ones with a reason to be large, and every other route stays where
    /// it was so that their appetite is not extended to all of them.
    ///
    /// Applied to the declared `Content-Length` before the signature has been
    /// checked, so naming the routes exactly is what keeps an unpaired peer to
    /// the small bound everywhere else.
    public static func bufferedBodyBound(method: String, path: String) -> Int {
        method == "POST" && (path == "/api/catalog" || path == "/api/edits")
            ? maximumOfferedBodyBytes
            : maximumBufferedBodyBytes
    }

    /// - Returns: a request once one has fully arrived, nil while it is still
    ///   coming.
    public mutating func read(_ bytes: Data) throws -> HTTPRequest? {
        buffered.append(bytes)

        guard let headEnd = buffered.range(of: Data("\r\n\r\n".utf8)) else {
            guard buffered.count <= Self.maximumHeadBytes else { throw Failure.headTooLarge }
            return nil
        }

        let head = String(decoding: buffered[buffered.startIndex..<headEnd.lowerBound], as: UTF8.self)
        var lines = head.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { throw Failure.malformed }

        let requestLine = lines.removeFirst().split(separator: " ")
        guard requestLine.count >= 2 else { throw Failure.malformed }

        var headers: [String: String] = [:]
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[line.startIndex..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            // Two lengths that disagree are two readings of where this
            // request ends, and the second reading is somebody else's request.
            if name == "content-length", let earlier = headers[name], earlier != value {
                throw Failure.malformed
            }
            headers[name] = value
        }

        let method = String(requestLine[0]).uppercased()
        let (path, query) = Self.split(String(requestLine[1]))

        // Digits only. `Int("-5")` reads, and a negative length made the body
        // a range whose end came before its start — a trap, from anyone who
        // could reach the port, before a signature was looked at.
        let wanted: Int
        if let declared = headers["content-length"] {
            guard !declared.isEmpty, declared.utf8.count <= 18,
                  declared.utf8.allSatisfy({ (0x30...0x39).contains($0) }),
                  let number = Int(declared)
            else { throw Failure.malformed }
            wanted = number
        } else {
            wanted = 0
        }
        let bodyStart = headEnd.upperBound
        let body: Data

        if Self.bodyStreams(method: method, path: path) {
            // Everything that came alongside the head, which is however much of
            // the file happened to share a packet with it. The rest of it never
            // reaches this reader: the caller takes the stream over from here.
            body = Data(buffered[bodyStart...])
            buffered.removeAll(keepingCapacity: false)
        } else {
            guard wanted <= Self.bufferedBodyBound(method: method, path: path) else {
                throw Failure.bodyTooLarge
            }
            guard buffered.count - bodyStart >= wanted else { return nil }

            body = Data(buffered[bodyStart..<(bodyStart + wanted)])
            buffered.removeSubrange(buffered.startIndex..<(bodyStart + wanted))
        }

        return HTTPRequest(
            method: method,
            path: path,
            query: query,
            headers: headers,
            body: body
        )
    }

    private static func split(_ target: String) -> (String, [String: String]) {
        guard let mark = target.firstIndex(of: "?") else {
            return (target.removingPercentEncoding ?? target, [:])
        }

        let path = String(target[target.startIndex..<mark])
        var query: [String: String] = [:]
        for pair in target[target.index(after: mark)...].split(separator: "&") {
            let halves = pair.split(separator: "=", maxSplits: 1)
            guard let name = halves.first else { continue }
            let value = halves.count > 1 ? String(halves[1]) : ""
            query[String(name)] = value.removingPercentEncoding ?? value
        }
        return (path.removingPercentEncoding ?? path, query)
    }
}
