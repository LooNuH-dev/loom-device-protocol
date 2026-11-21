import Foundation

/// Turns messages into bytes and bytes back into messages.
///
/// TCP is a stream, not a sequence of messages: what one side writes in one go
/// can arrive in three pieces, or glued to the message behind it. The length in
/// front of each message is what tells the two apart.
///
/// The length is big-endian on purpose. Swift on ARM would write it the other
/// way round, and a client written against a byte order that "just happened to
/// work" is a protocol break waiting for the first different machine. See
/// PROTOCOL.md 3.1.
public enum MessageFraming {

    /// Refuses anything absurd before allocating for it: a length prefix is
    /// four bytes anyone can send, and a claim of four gigabytes should cost
    /// nothing to reject.
    public static let maximumMessageBytes = 8 * 1024 * 1024

    public enum Failure: Error, Equatable {
        /// The sender claims a message larger than anyone has business sending.
        case messageTooLarge(claimed: Int)
        case notValidJSON
    }

    /// How many bytes `message` takes on the wire, its length prefix left out.
    /// What a receiver counts against what it holds for a sender it has not
    /// yet believed.
    public static func encodedSize(of message: WireMessage) -> Int {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return (try? encoder.encode(message).count) ?? maximumMessageBytes
    }

    /// Length in front, then the message as UTF-8 JSON.
    public static func frame(_ message: WireMessage) throws -> Data {
        let encoder = JSONEncoder()
        // Stable across builds and platforms, and diffable when read by eye
        // during a fault. The cost is a sort per message, which is nothing
        // beside the round trip it is about to take.
        encoder.outputFormatting = [.sortedKeys]
        let body = try encoder.encode(message)

        guard body.count <= maximumMessageBytes else {
            throw Failure.messageTooLarge(claimed: body.count)
        }

        var framed = Data(capacity: 4 + body.count)
        framed.append(contentsOf: bigEndianBytes(UInt32(body.count)))
        framed.append(body)
        return framed
    }

    private static func bigEndianBytes(_ value: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value)
        ]
    }

    /// Collects bytes as they arrive and hands back whole messages.
    ///
    /// Kept apart from any particular connection so that it can be driven a
    /// byte at a time by a test — which is the only way to be sure it survives
    /// a message split across packets, and that is exactly the case a real
    /// network delivers rarely and at the worst moment.
    public struct Reader {
        private var buffered = Data()
        /// The largest message this reader takes; never more than
        /// `maximumMessageBytes`.
        public let limit: Int

        public init(limit: Int = MessageFraming.maximumMessageBytes) {
            self.limit = min(max(limit, 0), MessageFraming.maximumMessageBytes)
        }

        /// - Returns: every complete message the new bytes finished off, in
        ///   the order they were sent. Empty while a message is still arriving.
        public mutating func read(_ bytes: Data) throws -> [WireMessage] {
            buffered.append(bytes)

            var finished: [WireMessage] = []
            while true {
                guard buffered.count >= 4 else { break }

                let length = Int(
                    UInt32(buffered[buffered.startIndex]) << 24
                    | UInt32(buffered[buffered.startIndex + 1]) << 16
                    | UInt32(buffered[buffered.startIndex + 2]) << 8
                    | UInt32(buffered[buffered.startIndex + 3])
                )

                guard length <= limit else {
                    throw Failure.messageTooLarge(claimed: length)
                }
                guard buffered.count >= 4 + length else { break }

                let body = buffered.subdata(in: (buffered.startIndex + 4)..<(buffered.startIndex + 4 + length))
                buffered.removeSubrange(buffered.startIndex..<(buffered.startIndex + 4 + length))

                do {
                    // One pass over the bytes; JSONDecoder reads JSONValue by
                    // trying each kind in turn, a thrown error per miss.
                    finished.append(try JSONValueParser.message(body))
                } catch {
                    throw Failure.notValidJSON
                }
            }
            return finished
        }

        /// How much of a message is sitting here half-arrived. For tests and
        /// for deciding a connection has gone quiet mid-message.
        public var pendingBytes: Int { buffered.count }
    }
}
