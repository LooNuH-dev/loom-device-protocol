import Foundation

/// What a device says about itself before anyone connects to it.
///
/// This travels in the TXT record of the Bonjour service, which is a flat set
/// of string pairs — no nesting, no types. Everything here is therefore written
/// out and read back by hand, in the exact spelling `PROTOCOL.md` gives, rather
/// than through anything that would derive the names from Swift.
///
/// It is worth the trouble because of what it saves: `revision` says whether
/// there is anything to sync without opening a connection, and `isPlaying` puts
/// the handoff notice on screen before one is opened.
public struct PeerAdvertisement: Equatable, Sendable {

    public let protocolVersion: Int
    /// What to call this device on screen.
    public let deviceName: String
    /// The same across restarts, renames and address changes.
    public let deviceID: String
    public let trackCount: Int
    /// The catalogue revision.
    public let revision: Int64
    public let isPlaying: Bool
    /// Which of the two pairing roles it plays. Nil from a
    /// build from before 2026-10, which does not say.
    public let deviceClass: DeviceClass?
    /// The open-protocol versions it speaks (TXT `versions`). Empty from a
    /// build before they were said.
    public let versions: [Int]
    /// What it can do for others (TXT `caps`), as sent, unknown names kept.
    /// Empty from a build before they were said, or one that offers nothing.
    public let capabilities: Set<String>

    public init(
        protocolVersion: Int = WireProtocol.version,
        deviceName: String,
        deviceID: String,
        trackCount: Int,
        revision: Int64,
        isPlaying: Bool,
        deviceClass: DeviceClass? = DeviceClass.this,
        versions: [Int] = DeviceProtocol.supportedVersions,
        capabilities: Set<Capability> = []
    ) {
        self.protocolVersion = protocolVersion
        self.deviceName = deviceName
        self.deviceID = deviceID
        self.trackCount = trackCount
        self.revision = revision
        self.isPlaying = isPlaying
        self.deviceClass = deviceClass
        self.versions = versions
        self.capabilities = Set(capabilities.map(\.rawValue))
    }

    /// The Bonjour service type both ends look for.
    public static let serviceType = "_loom._tcp"

    /// The keys, spelled once. Lower case and short because a TXT record is
    /// read by every implementation on the network, and these are the names
    /// `PROTOCOL.md` publishes.
    public enum Key {
        public static let proto = "proto"
        public static let device = "device"
        public static let deviceID = "deviceid"
        public static let tracks = "tracks"
        public static let revision = "rev"
        public static let playing = "playing"
        public static let deviceClass = "class"
        public static let versions = DeviceProtocol.txtKey
        public static let capabilities = "caps"
    }

    /// The longest value a TXT key may carry: a TXT string is one length
    /// byte and the "key=" in front of the value.
    public static let maximumValueBytes = 200

    public var txtRecord: [String: String] {
        var record = [
            Key.proto: String(protocolVersion),
            Key.device: Self.fitted(deviceName),
            Key.deviceID: deviceID,
            Key.tracks: String(trackCount),
            Key.revision: String(revision),
            // One character rather than "true": a TXT record is small on
            // purpose, and every other implementation reads a flag this way.
            Key.playing: isPlaying ? "1" : "0"
        ]
        if let deviceClass { record[Key.deviceClass] = deviceClass.rawValue }
        if !versions.isEmpty { record[Key.versions] = DeviceProtocol.txt(versions) }
        if !capabilities.isEmpty { record[Key.capabilities] = capabilities.sorted().joined(separator: ",") }
        return record
    }

    /// A name cut, on a character boundary, to what a reader takes.
    public static func fitted(_ value: String) -> String {
        guard value.utf8.count > maximumValueBytes else { return value }
        var cut = ""
        for character in value {
            guard cut.utf8.count + String(character).utf8.count <= maximumValueBytes else { break }
            cut.append(character)
        }
        return cut
    }

    /// Reads what another device is advertising.
    ///
    /// Nil when the record is not one of ours or is missing something there is
    /// no sensible default for. Keys that are not known are ignored rather than
    /// refused: a later version will add some, and an older build meeting it
    /// should still be able to see the host.
    public init?(txtRecord: [String: String]) {
        guard let proto = txtRecord[Key.proto].flatMap(Int.init),
              let name = txtRecord[Key.device],
              let id = txtRecord[Key.deviceID],
              !id.isEmpty,
              // Anyone on the network can publish a record; one whose name or
              // id is longer than a TXT string can hold was not made by a
              // device and is not shown.
              name.utf8.count <= Self.maximumValueBytes,
              id.utf8.count <= Self.maximumValueBytes
        else { return nil }

        self.protocolVersion = proto
        self.deviceName = name
        self.deviceID = id
        // A host that has not said how much it holds is not a host that cannot
        // be talked to; it is a host with nothing worth saying about size yet.
        self.trackCount = txtRecord[Key.tracks].flatMap(Int.init) ?? 0
        self.revision = txtRecord[Key.revision].flatMap(Int64.init) ?? 0
        self.isPlaying = txtRecord[Key.playing] == "1"
        self.deviceClass = txtRecord[Key.deviceClass].map { DeviceClass(wire: $0) }
        self.versions = DeviceProtocol.versions(txt: txtRecord[Key.versions])
        self.capabilities = Set(
            (txtRecord[Key.capabilities] ?? "").split(separator: ",").prefix(16)
                .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        )
    }

    public func has(_ capability: Capability) -> Bool {
        capabilities.contains(capability.rawValue)
    }

    /// Whether this device may be offered as a place to play. See
    /// `Capability.noPlayback`.
    public var mayPlay: Bool { !has(.noPlayback) }

    /// Whether this device speaks an open-protocol version this build does,
    /// by what it advertises. A build before `versions` is not counted: it
    /// may still be found as a legacy host (`mayBeLegacyHost(of:)`).
    public var speaksOpenProtocol: Bool {
        DeviceProtocol.negotiate(theirs: versions) != nil
    }

    /// Whether this build can talk to that one.
    ///
    /// Checked before a connection rather than after: showing a host that
    /// cannot be paired with is worse than not showing it, because the failure
    /// arrives later and with less explanation.
    ///
    /// A range rather than equality: additions are announced in `hello`
    /// (`WireFeature`) and leave `proto` alone, and `proto` moves only on a
    /// break neither side could talk across. Builds before 2026-10 compare for
    /// equality, which is why `proto` must not move for anything less.
    public var isCompatible: Bool {
        (WireProtocol.minimumVersion...WireProtocol.version).contains(protocolVersion)
    }

    /// Whether an iPhone may mirror this device as its host the old way
    /// (`ConnectionMode.legacyHost`), which takes it to hold the whole
    /// library: a desktop, or a build too old to say its class. A phone holds
    /// only what it fetched; an iPhone that took a paired Android for its
    /// host lost the paths of every file it kept.
    public var servesAsLegacyHost: Bool {
        deviceClass == nil || deviceClass == .desktop
    }

    /// Whether the device `ourDeviceID` may mirror this one as its host: the
    /// one check every client makes before it does, so no
    /// platform keeps a list of its own. Never itself, and only a device
    /// that `servesAsLegacyHost`.
    public func mayBeLegacyHost(of ourDeviceID: String) -> Bool {
        deviceID != ourDeviceID && servesAsLegacyHost
    }

    /// Whether the device `ourDeviceID` may send this one searches, links
    /// and fetches: by what it can do, not what class it is. Any device —
    /// a desktop, a phone, another iPhone, a device that is not one of
    /// Loom's apps — that speaks the open protocol (whose version 1 is
    /// equal devices, `peer1`) and announces `acquire`. Never itself.
    ///
    /// Only for whom to ask. Mirroring a whole library stays with
    /// `mayBeLegacyHost(of:)`, desktops alone.
    public func mayAcquire(for ourDeviceID: String) -> Bool {
        deviceID != ourDeviceID && isCompatible && speaksOpenProtocol && has(.acquire)
    }
}

