import Foundation

/// A fetched track handed to the device that asked for it. See PROTOCOL.md 7.5.
///
/// `serviceFetch` → answer with `fetchId` → `fetchReady` with the file's
/// `fileId` → `GET /api/variant/{fileId}` → `fetchDone` → the acquiring device
/// may delete the file. A device that keeps no library of its own holds each
/// file only for this.
public enum Handover {

    /// The acquiring device's answer to `serviceFetch` when it took the fetch.
    public static func accepted(replyingTo id: String, fetchID: String) -> WireMessage {
        WireMessage(type: .serviceFetch, replyTo: id, ok: true, payload: .object(["fetchId": .string(fetchID)]))
    }

    /// The `fetchId` in an answer to `serviceFetch`; nil from a device that
    /// does not hand files over (the file then reaches the asker another way).
    public static func fetchID(in answer: WireMessage) -> String? {
        guard answer.type == .serviceFetch, answer.ok == true else { return nil }
        return answer.payload?["fetchId"]?.stringValue
    }

    /// What `fetchReady` says.
    public struct Ready: Equatable, Sendable {
        public var fetchID: String
        /// Nil when the fetch failed; `reason` then says why.
        public var fileID: String?
        public var bytes: Int64?
        /// SHA-256 of the file, to check it once it has arrived.
        public var sha256: Data?
        public var format: String?
        public var reason: String?

        public init(fetchID: String, fileID: String?, bytes: Int64? = nil, sha256: Data? = nil,
                    format: String? = nil, reason: String? = nil) {
            self.fetchID = fetchID
            self.fileID = fileID
            self.bytes = bytes
            self.sha256 = sha256
            self.format = format
            self.reason = reason
        }

        public init?(_ message: WireMessage) {
            guard message.type == .fetchReady,
                  let fetchID = message.payload?["fetchId"]?.stringValue, !fetchID.isEmpty else { return nil }
            let fileID = message.payload?["fileId"]?.stringValue
            // A file id goes into a path: only what cannot climb or split it.
            if let fileID, !Handover.isSafe(fileID) { return nil }
            self.init(
                fetchID: fetchID, fileID: message.ok == false ? nil : fileID,
                bytes: message.payload?["bytes"]?.intValue,
                sha256: message.payload?["sha256"]?.stringValue.flatMap { Data(base64Encoded: $0) },
                format: message.payload?["format"]?.stringValue,
                reason: message.payload?["reason"]?.stringValue
            )
            if self.fileID == nil, message.ok != false { return nil }
            // A file the requester cannot check is not offered (PROTOCOL.md 7.5).
            if self.fileID != nil {
                guard let bytes, bytes >= 0, sha256?.count == 32 else { return nil }
            }
        }

        public func message(id: String = UUID().uuidString) -> WireMessage {
            var fields: [String: JSONValue] = ["fetchId": .string(fetchID)]
            if let fileID { fields["fileId"] = .string(fileID) }
            if let bytes { fields["bytes"] = .int(bytes) }
            if let sha256 { fields["sha256"] = .string(sha256.base64EncodedString()) }
            if let format { fields["format"] = .string(format) }
            if let reason { fields["reason"] = .string(reason) }
            return WireMessage(type: .fetchReady, id: id, ok: fileID != nil, payload: .object(fields))
        }

        /// The path the asker reads the file from.
        public var path: String? { fileID.map { "/api/variant/\($0)" } }
    }

    /// The asker's `fetchDone`: it holds the file (`kept`), or gives up on it.
    public static func done(fetchID: String, fileID: String, kept: Bool, id: String = UUID().uuidString) -> WireMessage {
        WireMessage(type: .fetchDone, id: id, ok: kept, payload: .object([
            "fetchId": .string(fetchID), "fileId": .string(fileID)
        ]))
    }

    /// `[A-Za-z0-9._-]`, 1…128, not "." or "..".
    public static func isSafe(_ fileID: String) -> Bool {
        guard (1...128).contains(fileID.utf8.count), fileID != ".", fileID != ".." else { return false }
        return fileID.utf8.allSatisfy { byte in
            (0x30...0x39).contains(byte) || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
                || byte == 0x2E || byte == 0x2D || byte == 0x5F
        }
    }

    /// The files an acquiring device holds only until they are handed over:
    /// which asker each is for, and when to give up waiting. Value type; the
    /// device deletes what `release` and `expired` return.
    public struct Ledger: Equatable, Sendable {
        public struct Held: Equatable, Sendable {
            public let fetchID: String
            public let fileID: String
            public let forDevice: String
            public let until: Date
        }

        /// How long a ready file waits for its asker before it is deleted.
        public static let patience: TimeInterval = 24 * 60 * 60
        /// At most this many files wait at once; the oldest goes first.
        public static let capacity = 256

        public private(set) var held: [String: Held] = [:]

        public init() {}

        /// A file is ready for `device`. Returns a file pushed out by the cap.
        public mutating func hold(fetchID: String, fileID: String, for device: String,
                                  at now: Date = Date()) -> Held? {
            var evicted: Held?
            if held.count >= Self.capacity, let oldest = held.values.min(by: { $0.until < $1.until }) {
                evicted = held.removeValue(forKey: oldest.fileID)
            }
            held[fileID] = Held(fetchID: fetchID, fileID: fileID, forDevice: device,
                                until: now.addingTimeInterval(Self.patience))
            return evicted
        }

        /// Whether `device` may read `fileID`: only the device it was fetched for.
        public func mayRead(_ fileID: String, by device: String) -> Bool {
            held[fileID]?.forDevice == device
        }

        /// The asker's `fetchDone`. Returns the file to delete; nil when it is
        /// not held, or not for that device.
        public mutating func release(_ message: WireMessage, from device: String) -> Held? {
            guard message.type == .fetchDone,
                  let fileID = message.payload?["fileId"]?.stringValue,
                  let entry = held[fileID], entry.forDevice == device,
                  entry.fetchID == message.payload?["fetchId"]?.stringValue
            else { return nil }
            return held.removeValue(forKey: fileID)
        }

        /// Files whose asker never came back; delete them.
        public mutating func expired(at now: Date = Date()) -> [Held] {
            let gone = held.values.filter { $0.until <= now }
            gone.forEach { held[$0.fileID] = nil }
            return gone
        }
    }
}
