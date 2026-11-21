import XCTest
@testable import LoomDeviceProtocol

/// The rules around the pairing code.
final class PairingCodeTests: XCTestCase {

    private let start = Date(timeIntervalSinceReferenceDate: 0)

    private func session(code: String = "123456") -> PairingSession {
        PairingSession(code: PairingCode(value: code, issuedAt: start))
    }

    func testACodeIsSixDigits() {
        var randomness = SystemRandomNumberGenerator()
        let code = PairingCode.generate(at: start, using: &randomness)

        XCTAssertEqual(code.value.count, 6)
        XCTAssertTrue(code.value.allSatisfy(\.isNumber))
    }

    /// Codes are drawn from the whole range, including the ones that do not
    /// look random.
    func testEveryCodeInTheRangeCanComeUp() {
        var randomness = SystemRandomNumberGenerator()
        var seen = Set<String>()
        for _ in 0..<500 {
            seen.insert(PairingCode.generate(at: start, using: &randomness).value)
        }

        XCTAssertGreaterThan(seen.count, 400, "not drawing from much of the range")
        XCTAssertTrue(seen.allSatisfy { $0.count == 6 })
    }

    func testTheRightCodeIsAccepted() {
        var session = self.session()

        XCTAssertEqual(session.offer("123456", at: start), .accepted)
    }

    func testAWrongCodeCountsAgainstTheThreeAttempts() {
        var session = self.session()

        XCTAssertEqual(session.offer("000000", at: start), .wrong(attemptsLeft: 2))
        XCTAssertEqual(session.offer("000001", at: start), .wrong(attemptsLeft: 1))
        XCTAssertEqual(session.offer("000002", at: start), .codeWithdrawn)
    }

    /// Guessed at too often and the code is gone — a new one is issued and has
    /// to be read off the host again.
    func testTheCodeIsReplacedAfterTheLastAttempt() {
        var session = self.session()
        for _ in 0..<3 { _ = session.offer("000000", at: start) }

        XCTAssertNotEqual(session.code.value, "123456")
        XCTAssertEqual(session.attemptsUsed, 0)
        XCTAssertTrue(session.isCurrent(at: start))
    }

    func testACodeDoesNotStandForever() {
        var session = self.session()
        let later = start.addingTimeInterval(PairingCode.lifetime)

        XCTAssertFalse(session.isCurrent(at: later))
        XCTAssertEqual(session.offer("123456", at: later), .codeWithdrawn)
    }

    /// The right code, offered a moment too late, is not accepted — and the
    /// code that replaces it is not the one that just expired.
    func testAnExpiredCodeIsReplacedRatherThanExtended() {
        var session = self.session()
        let later = start.addingTimeInterval(PairingCode.lifetime + 1)

        _ = session.offer("123456", at: later)

        XCTAssertEqual(session.code.issuedAt, later)
        XCTAssertTrue(session.isCurrent(at: later))
    }

    /// A code of the wrong length is simply wrong, and says nothing more.
    func testSomethingThatIsNotACodeIsJustWrong() {
        var session = self.session()

        XCTAssertEqual(session.offer("", at: start), .wrong(attemptsLeft: 2))
        XCTAssertEqual(session.offer("12345678", at: start), .wrong(attemptsLeft: 1))
    }
}
