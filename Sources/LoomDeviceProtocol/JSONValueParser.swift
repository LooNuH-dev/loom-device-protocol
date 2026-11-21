import Foundation

/// Reads JSON text straight into a `JSONValue`, in one pass.
///
/// `JSONValue.init(from:)` cannot ask a decoder what kind of value comes
/// next: it tries Bool, then Int64, then Double, then String, array and
/// object, and every miss throws a `DecodingError` with its coding path. A
/// string costs three errors, an object five. On a slow phone a megabyte of
/// sync took over a second to read that way; this reads the bytes once.
///
/// It gives what that path gives (pinned by `JSONValueParserTests`):
/// `true`/`false` as `.bool`; a number as `.int` when it is whole and fits
/// an Int64, `.double` otherwise; strings checked as UTF-8; the first of
/// duplicate keys; a trailing comma let through, as JSONDecoder lets it;
/// and an error for anything else that is not JSON.
public enum JSONValueParser {

    public struct Failure: Error, Equatable {
        public let offset: Int
    }

    /// Deeper than any message this protocol has, shallow enough that a
    /// hostile one cannot run the stack out.
    static let maximumDepth = 512

    public static func parse(_ data: Data) throws -> JSONValue {
        try data.withUnsafeBytes { raw -> JSONValue in
            var reader = Reader(bytes: raw.bindMemory(to: UInt8.self))
            reader.skipSpace()
            let value = try reader.value(depth: 0)
            reader.skipSpace()
            guard reader.atEnd else { throw reader.failure }
            return value
        }
    }

    /// A `WireMessage` from the text of one, as `JSONDecoder` would read it:
    /// a missing or null field is nil, a field of the wrong kind is an error.
    public static func message(_ data: Data) throws -> WireMessage {
        guard case .object(let fields) = try parse(data) else { throw Failure(offset: 0) }
        func string(_ key: String) throws -> String? {
            switch fields[key] {
            case nil, .null?: return nil
            case .string(let value)?: return value
            default: throw Failure(offset: 0)
            }
        }
        guard let type = try string("type") else { throw Failure(offset: 0) }
        let ok: Bool?
        switch fields["ok"] {
        case nil, .null?: ok = nil
        case .bool(let value)?: ok = value
        default: throw Failure(offset: 0)
        }
        let payload: JSONValue?
        if case .null? = fields["payload"] { payload = nil } else { payload = fields["payload"] }
        return WireMessage(
            type: WireMessage.Kind(rawValue: type), id: try string("id"),
            replyTo: try string("replyTo"), ok: ok, payload: payload
        )
    }

    private struct Reader {
        let bytes: UnsafeBufferPointer<UInt8>
        var index = 0

        var atEnd: Bool { index >= bytes.count }
        var failure: Failure { Failure(offset: index) }

        mutating func skipSpace() {
            while index < bytes.count {
                switch bytes[index] {
                case 0x20, 0x09, 0x0A, 0x0D: index += 1
                default: return
                }
            }
        }

        mutating func value(depth: Int) throws -> JSONValue {
            guard depth < JSONValueParser.maximumDepth, index < bytes.count else { throw failure }
            switch bytes[index] {
            case UInt8(ascii: "{"): return try object(depth: depth)
            case UInt8(ascii: "["): return try array(depth: depth)
            case UInt8(ascii: "\""): return .string(try string())
            case UInt8(ascii: "t"): try literal("true"); return .bool(true)
            case UInt8(ascii: "f"): try literal("false"); return .bool(false)
            case UInt8(ascii: "n"): try literal("null"); return .null
            case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"): return try number()
            default: throw failure
            }
        }

        mutating func literal(_ word: StaticString) throws {
            let count = word.utf8CodeUnitCount
            guard index + count <= bytes.count else { throw failure }
            let start = word.utf8Start
            for offset in 0..<count where bytes[index + offset] != start[offset] { throw failure }
            index += count
        }

        mutating func object(depth: Int) throws -> JSONValue {
            index += 1
            var fields: [String: JSONValue] = [:]
            skipSpace()
            if index < bytes.count, bytes[index] == UInt8(ascii: "}") { index += 1; return .object(fields) }
            while true {
                skipSpace()
                guard index < bytes.count, bytes[index] == UInt8(ascii: "\"") else { throw failure }
                let key = try string()
                skipSpace()
                guard index < bytes.count, bytes[index] == UInt8(ascii: ":") else { throw failure }
                index += 1
                skipSpace()
                let item = try value(depth: depth + 1)
                if fields[key] == nil { fields[key] = item }
                skipSpace()
                guard index < bytes.count else { throw failure }
                if bytes[index] == UInt8(ascii: ",") {
                    index += 1
                    skipSpace()
                    if index < bytes.count, bytes[index] == UInt8(ascii: "}") { index += 1; return .object(fields) }
                    continue
                }
                if bytes[index] == UInt8(ascii: "}") { index += 1; return .object(fields) }
                throw failure
            }
        }

        mutating func array(depth: Int) throws -> JSONValue {
            index += 1
            var items: [JSONValue] = []
            skipSpace()
            if index < bytes.count, bytes[index] == UInt8(ascii: "]") { index += 1; return .array(items) }
            while true {
                skipSpace()
                items.append(try value(depth: depth + 1))
                skipSpace()
                guard index < bytes.count else { throw failure }
                if bytes[index] == UInt8(ascii: ",") {
                    index += 1
                    skipSpace()
                    if index < bytes.count, bytes[index] == UInt8(ascii: "]") { index += 1; return .array(items) }
                    continue
                }
                if bytes[index] == UInt8(ascii: "]") { index += 1; return .array(items) }
                throw failure
            }
        }

        mutating func string() throws -> String {
            index += 1
            let start = index
            // Most strings have no escapes: take their bytes as they are.
            while index < bytes.count {
                let byte = bytes[index]
                if byte == UInt8(ascii: "\"") {
                    let text = try utf8(UnsafeBufferPointer(rebasing: bytes[start..<index]))
                    index += 1
                    return text
                }
                if byte == UInt8(ascii: "\\") { break }
                guard byte >= 0x20 else { throw failure }
                index += 1
            }
            var out = Array(UnsafeBufferPointer(rebasing: bytes[start..<index]))
            while index < bytes.count {
                let byte = bytes[index]
                switch byte {
                case UInt8(ascii: "\""):
                    index += 1
                    return try out.withUnsafeBufferPointer { try utf8($0) }
                case UInt8(ascii: "\\"):
                    index += 1
                    guard index < bytes.count else { throw failure }
                    let escape = bytes[index]
                    index += 1
                    switch escape {
                    case UInt8(ascii: "\""): out.append(0x22)
                    case UInt8(ascii: "\\"): out.append(0x5C)
                    case UInt8(ascii: "/"): out.append(0x2F)
                    case UInt8(ascii: "b"): out.append(0x08)
                    case UInt8(ascii: "f"): out.append(0x0C)
                    case UInt8(ascii: "n"): out.append(0x0A)
                    case UInt8(ascii: "r"): out.append(0x0D)
                    case UInt8(ascii: "t"): out.append(0x09)
                    case UInt8(ascii: "u"): appendScalar(try unicodeEscape(), to: &out)
                    default: throw failure
                    }
                default:
                    guard byte >= 0x20 else { throw failure }
                    out.append(byte)
                    index += 1
                }
            }
            throw failure
        }

        func utf8(_ buffer: UnsafeBufferPointer<UInt8>) throws -> String {
            guard let text = String(validatingUTF8Bytes: buffer) else { throw failure }
            return text
        }

        mutating func hex4() throws -> UInt32 {
            guard index + 4 <= bytes.count else { throw failure }
            var value: UInt32 = 0
            for _ in 0..<4 {
                let byte = bytes[index]
                let digit: UInt32
                switch byte {
                case UInt8(ascii: "0")...UInt8(ascii: "9"): digit = UInt32(byte - UInt8(ascii: "0"))
                case UInt8(ascii: "a")...UInt8(ascii: "f"): digit = UInt32(byte - UInt8(ascii: "a") + 10)
                case UInt8(ascii: "A")...UInt8(ascii: "F"): digit = UInt32(byte - UInt8(ascii: "A") + 10)
                default: throw failure
                }
                value = value << 4 | digit
                index += 1
            }
            return value
        }

        /// A `\u` escape, a surrogate pair joined; a lone surrogate is not
        /// a character, and JSONDecoder refuses it too.
        mutating func unicodeEscape() throws -> Unicode.Scalar {
            let first = try hex4()
            if (0xD800...0xDBFF).contains(first) {
                guard index + 6 <= bytes.count, bytes[index] == UInt8(ascii: "\\"),
                      bytes[index + 1] == UInt8(ascii: "u") else { throw failure }
                index += 2
                let second = try hex4()
                guard (0xDC00...0xDFFF).contains(second),
                      let scalar = Unicode.Scalar(0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00))
                else { throw failure }
                return scalar
            }
            guard let scalar = Unicode.Scalar(first) else { throw failure }
            return scalar
        }

        func appendScalar(_ scalar: Unicode.Scalar, to out: inout [UInt8]) {
            out.append(contentsOf: UTF8.encode(scalar)!)
        }

        mutating func number() throws -> JSONValue {
            let start = index
            if bytes[index] == UInt8(ascii: "-") { index += 1 }
            guard index < bytes.count else { throw failure }
            if bytes[index] == UInt8(ascii: "0") {
                index += 1
            } else if (UInt8(ascii: "1")...UInt8(ascii: "9")).contains(bytes[index]) {
                while index < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[index]) { index += 1 }
            } else {
                throw failure
            }
            var whole = true
            if index < bytes.count, bytes[index] == UInt8(ascii: ".") {
                whole = false
                index += 1
                let digits = index
                while index < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[index]) { index += 1 }
                guard index > digits else { throw failure }
            }
            if index < bytes.count, bytes[index] == UInt8(ascii: "e") || bytes[index] == UInt8(ascii: "E") {
                whole = false
                index += 1
                if index < bytes.count, bytes[index] == UInt8(ascii: "+") || bytes[index] == UInt8(ascii: "-") { index += 1 }
                let digits = index
                while index < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[index]) { index += 1 }
                guard index > digits else { throw failure }
            }
            let text = String(decoding: UnsafeBufferPointer(rebasing: bytes[start..<index]), as: UTF8.self)
            if whole, let int = Int64(text) { return .int(int) }
            guard let double = Double(text), double.isFinite else { throw failure }
            // A whole number written with a point or an exponent ("2.0",
            // "1e3") reads as an integer, as JSONDecoder reads it.
            if let int = Int64(exactly: double) { return .int(int) }
            return .double(double)
        }
    }
}

private extension String {
    /// The bytes as a string when they are valid UTF-8; nil otherwise.
    init?(validatingUTF8Bytes bytes: UnsafeBufferPointer<UInt8>) {
        var decoder = UTF8()
        var iterator = bytes.makeIterator()
        var valid = true
        loop: while true {
            switch decoder.decode(&iterator) {
            case .scalarValue: continue
            case .emptyInput: break loop
            case .error: valid = false; break loop
            }
        }
        guard valid else { return nil }
        self = String(decoding: bytes, as: UTF8.self)
    }
}
