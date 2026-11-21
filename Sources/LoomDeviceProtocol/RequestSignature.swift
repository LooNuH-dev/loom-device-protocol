import Crypto
import Foundation

/// Proves a request came from a device that was paired with.
///
/// On top of TLS rather than instead of it. TLS says the client is talking to
/// the right host; this says the host is talking to the right client. Pinning
/// alone cannot: it is the client that checks the certificate, and a host has
/// nothing to check back with.
///
/// A signature rather than a token sent along: a token is a secret that travels
/// on every request, and the whole point of the pairing secret is that it never
/// leaves either device after the day it was agreed.
public enum RequestSignature {

    /// How far apart the two clocks may be.
    ///
    /// Wide enough that nobody has to keep time, narrow enough that a request
    /// somebody recorded is worthless by the time they play it back. There is
    /// no clock synchronisation between these devices and there is not going to
    /// be one.
    public static let tolerance: TimeInterval = 5 * 60

    public static let deviceHeader = "X-Loom-Device"
    public static let dateHeader = "X-Loom-Date"
    public static let signatureHeader = "X-Loom-Signature"
    /// What the body will hash to, said in advance by a sender whose body is
    /// too big to hold. See `headers(bodyDigest:)`.
    public static let digestHeader = "X-Loom-Content-SHA256"

    public enum Refusal: Error, Equatable {
        case unsigned
        case notFromAPairedDevice
        case tooOldOrTooNew
        case wrongSignature
        /// A request that changes something, signed exactly as one already
        /// taken. See `ReplayGuard`.
        case replayed
    }

    /// What is signed.
    ///
    /// The method and the target, so a signature for reading artwork cannot be
    /// replayed as one for importing a file. The moment, so it expires. And the
    /// body's digest, so what was sent cannot be swapped for something else of
    /// the same length.
    private static func transcript(
        method: String,
        target: String,
        milliseconds: Int64,
        digest: Data
    ) -> Data {
        var bytes = Data("Loom request v1\n".utf8)
        bytes.append(Data(method.uppercased().utf8))
        bytes.append(0x0A)
        bytes.append(Data(target.utf8))
        bytes.append(0x0A)
        bytes.append(Data(String(milliseconds).utf8))
        bytes.append(0x0A)
        bytes.append(digest)
        return bytes
    }

    /// The headers a client adds to a request.
    ///
    /// - Parameter target: the path with its query, exactly as it goes in the
    ///   request line. Signing the path alone would leave the query free to be
    ///   altered — and the query is what says which revision to send.
    /// - Parameter bodyDigest: the SHA-256 of a body that is not in hand — a
    ///   file being sent up, which is streamed to disk at the other end rather
    ///   than held in memory. Signing the digest instead of the bytes lets the
    ///   request be checked before the file has finished arriving, and the file
    ///   itself be checked against the same digest once it has. Without it the
    ///   two ends sign different things: the sender has the whole file, the
    ///   receiver has whichever fragment came alongside the head.
    public static func headers(
        method: String,
        target: String,
        body: Data = Data(),
        bodyDigest: Data? = nil,
        deviceID: String,
        secret: Data,
        at moment: Date = Date()
    ) -> [String: String] {
        let milliseconds = Int64(moment.timeIntervalSince1970 * 1000)
        let digest = bodyDigest ?? Data(SHA256.hash(data: body))
        let mac = HMAC<SHA256>.authenticationCode(
            for: transcript(
                method: method, target: target, milliseconds: milliseconds, digest: digest
            ),
            using: SymmetricKey(data: secret)
        )

        var headers = [
            deviceHeader: deviceID,
            dateHeader: String(milliseconds),
            signatureHeader: Data(mac).base64EncodedString()
        ]
        if let bodyDigest {
            headers[digestHeader] = bodyDigest.base64EncodedString()
        }
        return headers
    }

    /// What the sender says its body will hash to, if it said.
    ///
    /// The claim is signed, so it cannot be altered on the way — but a signed
    /// claim about a body is not a signature over that body, and on its own it
    /// settles nothing. It is worth something only where somebody holds the
    /// bytes to it: `DataChannelServer` hashes an import as it pours to disk and
    /// throws the file away if the two disagree. Nowhere else does, which is why
    /// `check` hashes the body itself unless the caller says the body is still
    /// on its way.
    public static func declaredDigest(of request: HTTPRequest) -> Data? {
        request.header(digestHeader).flatMap { Data(base64Encoded: $0) }
    }

    /// Checks a request against the devices this host has paired with.
    ///
    /// - Parameter bodyArrivesSeparately: true only where the bytes genuinely
    ///   are not here yet — the streamed import, whose head must be checked
    ///   before a byte is written to disk. Said by the caller rather than
    ///   guessed from the presence of a header, because the header is written by
    ///   the sender: letting it decide would let any sender opt out of having
    ///   its body covered by declaring a digest and sending something else.
    /// - Returns: which paired device sent it.
    public static func check(
        _ request: HTTPRequest,
        against store: any TrustStoring,
        bodyArrivesSeparately: Bool = false,
        replays: ReplayGuard? = nil,
        at moment: Date = Date()
    ) throws -> PairedDevice {
        guard let deviceID = request.header(deviceHeader),
              let stamp = request.header(dateHeader).flatMap(Int64.init),
              let offered = request.header(signatureHeader).flatMap({ Data(base64Encoded: $0) })
        else { throw Refusal.unsigned }

        guard let device = try store.paired(deviceID: deviceID) else {
            throw Refusal.notFromAPairedDevice
        }

        let sent = Date(timeIntervalSince1970: Double(stamp) / 1000)
        guard abs(sent.timeIntervalSince(moment)) <= tolerance else {
            throw Refusal.tooOldOrTooNew
        }

        // The target is rebuilt rather than taken from a header: what was
        // signed is what was asked for, and a header saying otherwise proves
        // nothing.
        let target = request.query.isEmpty
            ? request.path
            : request.path + "?" + request.query.keys.sorted()
                .map { "\($0)=\(request.query[$0]!)" }
                .joined(separator: "&")

        // The bytes whenever they are in hand, so the signature covers the body
        // and not a claim about it: a declared digest that does not match what
        // arrived builds a different transcript here and the request is refused.
        // Only the streamed import has nothing to hash yet, and there the claim
        // is settled against the file as it lands.
        let digest = bodyArrivesSeparately
            ? (declaredDigest(of: request) ?? Data(SHA256.hash(data: request.body)))
            : Data(SHA256.hash(data: request.body))
        let expected = HMAC<SHA256>.authenticationCode(
            for: transcript(
                method: request.method, target: target, milliseconds: stamp, digest: digest
            ),
            using: SymmetricKey(data: device.sharedSecret)
        )

        guard Data(expected).constantTimeEquals(offered) else { throw Refusal.wrongSignature }
        // Only after the signature holds, so nobody unpaired can fill the
        // guard. A read may be asked twice; a write is taken once.
        if let replays, !ReplayGuard.isRead(request.method),
           !replays.first(deviceID: deviceID, signature: offered, at: moment) {
            throw Refusal.replayed
        }
        return device
    }

    /// The target as a client must build it, so both ends sign the same string.
    ///
    /// The query is sorted, because a dictionary has no order and two ends
    /// sorting differently would disagree about a request they both understood.
    public static func target(path: String, query: [String: String] = [:]) -> String {
        guard !query.isEmpty else { return path }
        return path + "?" + query.keys.sorted()
            .map { "\($0)=\(query[$0]!)" }
            .joined(separator: "&")
    }
}

/// Signatures of requests that change something, remembered for as long as
/// their signature could still be accepted (`RequestSignature.tolerance`),
/// so the same signed request is taken once.
///
/// TLS already keeps a request from being recorded off the network; this is
/// for what TLS cannot see: a sender, or a proxy in front of the listener,
/// that sends one import or one offer twice. Bounded: past
/// `capacity` the oldest are forgotten, which can only let an old replay
/// through, never refuse a fresh request.
public final class ReplayGuard: @unchecked Sendable {
    public static let capacity = 4096

    private let lock = NSLock()
    private var seen: [Data: Date] = [:]
    private var order: [(key: Data, at: Date)] = []

    public init() {}

    static func isRead(_ method: String) -> Bool {
        let upper = method.uppercased()
        return upper == "GET" || upper == "HEAD"
    }

    /// True the first time a device's signature is offered within the window,
    /// false for every repeat.
    public func first(deviceID: String, signature: Data, at moment: Date = Date()) -> Bool {
        var key = Data(deviceID.utf8)
        key.append(0)
        key.append(signature)
        lock.lock(); defer { lock.unlock() }
        let horizon = moment.addingTimeInterval(-2 * RequestSignature.tolerance)
        while let oldest = order.first, oldest.at < horizon || order.count >= Self.capacity {
            order.removeFirst()
            if seen[oldest.key] == oldest.at { seen[oldest.key] = nil }
        }
        if let when = seen[key], when >= horizon { return false }
        seen[key] = moment
        order.append((key, moment))
        return true
    }

    /// How many signatures are remembered now; for the tests.
    public var count: Int { lock.lock(); defer { lock.unlock() }; return seen.count }
}
