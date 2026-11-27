import Foundation

/// The open device protocol's own versions, and how two devices agree on one.
/// See PROTOCOL.md 1 and CHANGELOG.md.
///
/// Two numbers live here, and neither is `proto`:
///
/// - `libraryVersion` is this package's semantic version, the one in
///   CHANGELOG.md and on the specification. Its major is the protocol major.
/// - `supportedVersions` are the protocol majors this build speaks. Every
///   device says them in `hello` (`versions`) and in its TXT record, and the
///   two ends use the highest one both name.
///
/// `proto` (`WireProtocol`) is older than this and stays where it is: builds
/// from before 2026-10 compare it for equality, so it moves only on a break
/// nobody could talk across. Minor additions within a major are announced as
/// `features` and never move either number.
public enum DeviceProtocol {
    /// This package's semantic version. Kept equal to the newest entry in
    /// CHANGELOG.md.
    public static let libraryVersion = "1.3.0"

    /// Version 1 is published as a draft: it may still change before it is
    /// declared stable, and the specification says so.
    public static let isDraft = true

    /// The protocol majors this build speaks, lowest first.
    public static let supportedVersions: [Int] = [1]

    /// The key in `hello` that carries the versions, as an array of integers.
    public static let helloKey = "versions"

    /// The TXT key that carries them, comma-separated ("1" or "1,2").
    public static let txtKey = "versions"

    /// More than this many versions in one message is not a device being
    /// generous but a message built to cost something; the rest are dropped.
    public static let maximumDeclaredVersions = 16

    /// The highest version both lists name; nil when they share none.
    public static func negotiate(ours: [Int] = supportedVersions, theirs: [Int]) -> Int? {
        Set(ours).intersection(theirs).max()
    }

    /// Reads a `versions` value from `hello`: positive integers, at most
    /// `maximumDeclaredVersions`, without repeats, lowest first. Anything else
    /// in the array is skipped rather than refused, so a later build's
    /// additions do not cost the versions both ends know.
    public static func versions(in value: JSONValue?) -> [Int] {
        guard case .array(let items)? = value else { return [] }
        return clean(items.prefix(maximumDeclaredVersions).compactMap { item -> Int? in
            guard let number = item.intValue, number > 0, number <= Int64(Int32.max) else { return nil }
            return Int(number)
        })
    }

    /// Reads the TXT form, "1,2". The same rules as `versions(in:)`.
    public static func versions(txt: String?) -> [Int] {
        guard let txt else { return [] }
        return clean(txt.split(separator: ",").prefix(maximumDeclaredVersions).compactMap { part in
            Int(part.trimmingCharacters(in: .whitespaces)).flatMap { $0 > 0 ? $0 : nil }
        })
    }

    /// The TXT form of `versions`.
    public static func txt(_ versions: [Int]) -> String {
        versions.map(String.init).joined(separator: ",")
    }

    private static func clean(_ versions: [Int]) -> [Int] {
        Array(Set(versions)).sorted()
    }
}
