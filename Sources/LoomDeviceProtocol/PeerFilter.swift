import Foundation

/// Which peers a device serves (PROTOCOL.md 1.4). Absent means everyone.
///
/// On the wire (`serves` in `hello` and in the TXT record): device classes
/// separated by `,`, then optionally `;local` — `ios`, `ios,android;local`,
/// `*;local`. Unknown class names are ignored; `local` means a peer on the
/// same physical device.
public struct PeerFilter: Equatable, Sendable {
    /// Nil: any class.
    public var classes: Set<DeviceClass>?
    public var sameHostOnly: Bool

    public init(classes: Set<DeviceClass>? = nil, sameHostOnly: Bool = false) {
        self.classes = classes
        self.sameHostOnly = sameHostOnly
    }

    /// Whether a peer of `peerClass` (nil reads as `desktop`, as everywhere)
    /// is served; `sameHost` is the caller's to know.
    public func admits(_ peerClass: DeviceClass?, sameHost: Bool) -> Bool {
        if sameHostOnly && !sameHost { return false }
        guard let classes else { return true }
        return classes.contains(peerClass ?? .desktop)
    }

    public var wire: String {
        let names = classes.map { $0.map(\.rawValue).sorted().joined(separator: ",") } ?? "*"
        return sameHostOnly ? names + ";local" : names
    }

    /// Nil for an absent or empty value: serves everyone.
    public init?(wire: String?) {
        guard let wire = wire?.trimmingCharacters(in: .whitespaces), !wire.isEmpty,
              wire.utf8.count <= PeerAdvertisement.maximumValueBytes else { return nil }
        let parts = wire.split(separator: ";", omittingEmptySubsequences: false)
        let names = parts[0].split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let local = parts.dropFirst().contains { $0.trimmingCharacters(in: .whitespaces) == "local" }
        let known = names.compactMap { DeviceClass(rawValue: $0) }
        // `*` or nothing before `;`: any class. Only unknown names: nobody
        // this build knows of, which a later class may still be.
        let any = names.isEmpty || names == [""] || names.contains("*")
        self.init(classes: any ? nil : Set(known), sameHostOnly: local)
    }
}
