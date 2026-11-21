import Foundation

/// A value as JSON has it, and nothing more.
///
/// The payload of a message is not known until its `type` has been read, so the
/// envelope has to carry something it can decode without knowing what it is.
/// This is that something: the six kinds JSON defines, and no way to express
/// anything a JSON reader on another platform could not read back. See
/// PROTOCOL.md 3.2.
public enum JSONValue: Codable, Equatable, Sendable {
    case null
    case bool(Bool)
    /// Whole numbers are kept apart from fractional ones so that a revision or
    /// a position in milliseconds survives the trip as the integer it is,
    /// rather than coming back as `41209.0`.
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: any Decoder) throws {
        let value = try decoder.singleValueContainer()

        if value.decodeNil() {
            self = .null
        } else if let bool = try? value.decode(Bool.self) {
            self = .bool(bool)
        } else if let int = try? value.decode(Int64.self) {
            self = .int(int)
        } else if let double = try? value.decode(Double.self) {
            self = .double(double)
        } else if let string = try? value.decode(String.self) {
            self = .string(string)
        } else if let array = try? value.decode([JSONValue].self) {
            self = .array(array)
        } else if let object = try? value.decode([String: JSONValue].self) {
            self = .object(object)
        } else {
            throw DecodingError.dataCorruptedError(
                in: value, debugDescription: "not JSON this side understands"
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .int(let value): try container.encode(value)
        case .double(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }
}

public extension JSONValue {
    /// Reading a field off a payload, for the cases where a whole type would be
    /// more ceremony than the two fields are worth.
    subscript(key: String) -> JSONValue? {
        guard case .object(let fields) = self else { return nil }
        return fields[key]
    }

    var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    var intValue: Int64? {
        if case .int(let value) = self { return value }
        return nil
    }

    var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }
}
