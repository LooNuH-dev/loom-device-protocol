import Foundation

/// The six digits shown on the host while another device is being paired to it.
///.
///
/// The code is deliberately weak — six digits is a million guesses, which is
/// nothing. What makes that safe is the exchange it feeds, which is built to
/// turn a weak password into a strong key without letting an eavesdropper try
/// those million guesses offline. What is here is the other half of that: a
/// code that does not sit on screen indefinitely, and a limit on how many times
/// it can be got wrong.
public struct PairingCode: Equatable, Sendable {

    /// Long enough to read across a room, short enough to type without
    /// resenting it.
    public static let digits = 6
    /// How long a code stands. Long enough to walk to the other device.
    public static let lifetime: TimeInterval = 60
    /// How many times it may be got wrong before it is thrown away.
    public static let allowedAttempts = 3

    public let value: String
    public let issuedAt: Date

    public init(value: String, issuedAt: Date) {
        self.value = value
        self.issuedAt = issuedAt
    }

    /// - Parameter randomness: given so a test can be certain of what it gets.
    public static func generate<G: RandomNumberGenerator>(
        at moment: Date = Date(),
        using randomness: inout G
    ) -> PairingCode {
        // Every digit independently, so that every code in the range is as
        // likely as every other. Taking a random number modulo a million would
        // favour the low end by a hair, and there is no reason to accept even
        // that.
        let value = (0..<digits).map { _ in
            String(Int.random(in: 0...9, using: &randomness))
        }.joined()

        return PairingCode(value: value, issuedAt: moment)
    }

    public static func generate(at moment: Date = Date()) -> PairingCode {
        var randomness = SystemRandomNumberGenerator()
        return generate(at: moment, using: &randomness)
    }

    public func hasExpired(at moment: Date) -> Bool {
        moment.timeIntervalSince(issuedAt) >= Self.lifetime
    }
}

/// Runs one pairing attempt on the host: shows a code, counts what is tried
/// against it, and gives up on it when it is old or has been guessed at enough.
///
/// Kept apart from anything to do with the network so that the rules can be
/// tested without one.
public struct PairingSession: Sendable {

    public enum Outcome: Equatable, Sendable {
        case accepted
        /// Wrong, and the code still stands.
        case wrong(attemptsLeft: Int)
        /// The code is gone — expired, or guessed at too often. A new one is
        /// issued and the person is asked to read it again.
        case codeWithdrawn
    }

    public private(set) var code: PairingCode
    public private(set) var attemptsUsed = 0

    public init(code: PairingCode) {
        self.code = code
    }

    public init(at moment: Date = Date()) {
        self.code = PairingCode.generate(at: moment)
    }

    /// - Parameter offered: what was typed on the other device.
    public mutating func offer(_ offered: String, at moment: Date = Date()) -> Outcome {
        if code.hasExpired(at: moment) {
            reissue(at: moment)
            return .codeWithdrawn
        }

        guard constantTimeEquals(offered, code.value) else {
            attemptsUsed += 1
            let left = Self.attemptsLeft(after: attemptsUsed)
            if left == 0 {
                reissue(at: moment)
                return .codeWithdrawn
            }
            return .wrong(attemptsLeft: left)
        }

        return .accepted
    }

    /// Whether the code on screen is still the one being asked for.
    public func isCurrent(at moment: Date) -> Bool {
        !code.hasExpired(at: moment) && attemptsUsed < PairingCode.allowedAttempts
    }

    public mutating func reissue(at moment: Date = Date()) {
        code = PairingCode.generate(at: moment)
        attemptsUsed = 0
    }

    private static func attemptsLeft(after used: Int) -> Int {
        max(0, PairingCode.allowedAttempts - used)
    }
}

/// Compared without giving away how much of it was right. The comparison is
/// cheap and the code is short, but a check that returns sooner for a closer
/// guess turns six digits into six separate digits.
///
/// At file scope because both sides of a pairing need it: the host checking
/// what was sent to it, and the client checking what was typed into it.
public func constantTimeEquals(_ left: String, _ right: String) -> Bool {
    let a = Array(left.utf8)
    let b = Array(right.utf8)
    guard a.count == b.count else { return false }

    var difference: UInt8 = 0
    for index in a.indices { difference |= a[index] ^ b[index] }
    return difference == 0
}
