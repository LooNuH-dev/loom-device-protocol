import Foundation

/// One message on the control channel.
///
/// Every field is spelled out rather than left to Swift's own idea of what a
/// property is called: the other end of this connection is meant to be able to
/// be an Android or a Windows client, and a name that changes because a Swift
/// property was renamed is a protocol break nobody sees coming.
public struct WireMessage: Codable, Equatable, Sendable {

    /// What kind of message this is. A string on the wire, so an older build
    /// meeting a newer one can say "I do not know this one" rather than failing
    /// to parse the connection at all.
    public struct Kind: RawRepresentable, Codable, Equatable, Hashable, Sendable {
        public let rawValue: String
        public init(rawValue: String) { self.rawValue = rawValue }

        public static let hello = Kind(rawValue: "hello")
        /// One side's half of a pairing exchange.
        public static let pairingOffer = Kind(rawValue: "pairingOffer")
        /// Sent once a person has said the digits match on both screens.
        public static let pairingConfirm = Kind(rawValue: "pairingConfirm")
        /// One side's commitment to one bit of the pairing code, in version 2
        /// of the code path. See `PasskeyExchange` and PROTOCOL.md 5.3.
        public static let pairingCommit = Kind(rawValue: "pairingCommit")
        /// The nonce behind a `pairingCommit`, sent once the other side has
        /// committed too.
        public static let pairingReveal = Kind(rawValue: "pairingReveal")
        /// Proof, after the last round, that both ends hold the same secret.
        public static let pairingCheck = Kind(rawValue: "pairingCheck")
        /// Proof of the pair's secret, sent by both ends after the other's
        /// `hello`. See `ControlAuth` and PROTOCOL.md 3.3.
        public static let auth = Kind(rawValue: "auth")
        /// A free-text search sent to a device that announces `acquire`,
        /// and that device's answer with what it found. See PROTOCOL.md 7.
        /// Older builds ignore it.
        public static let serviceSearch = Kind(rawValue: "serviceSearch")
        /// A pick among those results, for the answering device to fetch,
        /// and its answer. See PROTOCOL.md 7.
        public static let serviceFetch = Kind(rawValue: "serviceFetch")
        /// A link sent to a device that announces `acquire`, read by it, and
        /// its answer with what the link holds. See PROTOCOL.md 7.
        public static let linkLookup = Kind(rawValue: "linkLookup")
        /// What to do with that link (fetch, import as a list, keep for
        /// later), and the answering device's answer. See PROTOCOL.md 7.
        public static let linkAction = Kind(rawValue: "linkAction")
        /// A fetch asked for with `serviceFetch` has a file ready, with its
        /// id, or has failed. Sent by the acquiring device. See PROTOCOL.md 7.5.
        public static let fetchReady = Kind(rawValue: "fetchReady")
        /// The asker has the file; the acquiring device may let it go. See
        /// PROTOCOL.md 7.5.
        public static let fetchDone = Kind(rawValue: "fetchDone")

        /// Every kind the open protocol defines. Anything else on the wire
        /// is a Loom-internal kind or a later one; a device ignores both.
        public static let open: Set<Kind> = [
            .hello, .pairingOffer, .pairingConfirm, .pairingCommit, .pairingReveal, .pairingCheck,
            .auth, .serviceSearch, .serviceFetch, .linkLookup, .linkAction, .fetchReady, .fetchDone
        ]
    }

    public let type: Kind
    /// Identifies this message so that a reply can point back at it. Present on
    /// anything that expects an answer.
    public let id: String?
    /// The `id` of the message being answered.
    public let replyTo: String?
    /// Whether the thing being answered succeeded. Only on replies.
    public let ok: Bool?
    public let payload: JSONValue?

    public init(
        type: Kind,
        id: String? = nil,
        replyTo: String? = nil,
        ok: Bool? = nil,
        payload: JSONValue? = nil
    ) {
        self.type = type
        self.id = id
        self.replyTo = replyTo
        self.ok = ok
        self.payload = payload
    }

    enum CodingKeys: String, CodingKey {
        case type
        case id
        case replyTo
        case ok
        case payload
    }
}

/// The wire version (`proto`) this build speaks. Announced in the TXT record
/// and again in `hello`. Moves only on a break; see `DeviceProtocol` for the
/// open protocol's own versions and their negotiation.
public enum WireProtocol {
    public static let version = 1
    /// The oldest version this build still talks to.
    public static let minimumVersion = 1
}
