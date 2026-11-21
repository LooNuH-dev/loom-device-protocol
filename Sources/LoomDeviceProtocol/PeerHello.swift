import Foundation

/// Something a platform or a store may withhold from a device.
///
/// A missing capability is a forced limit — App Store rules, the iOS sandbox,
/// a listener iOS closes in the background — and never a role. A device
/// without one may ask a peer that has it.
public enum Capability: String, Sendable, CaseIterable {
    /// The device answers a search, reads links, and provides the track
    /// files it fetches for them. See PROTOCOL.md 7.
    case acquire
    /// Loom-internal: folders watched for new music. Informational only.
    case watchFolders
    /// A data channel (PROTOCOL.md 4) is up now.
    case serveData
    /// Said by a device that plays nothing and takes no transport control.
    /// A marker rather than something withheld, so a device that says nothing keeps playing as before.
    /// See PROTOCOL.md 1.3.
    case noPlayback
}

/// Additions a build understands beyond `proto`, announced in `hello`.
/// See PROTOCOL.md 3.3.
///
/// Only what is actually built is announced. The open protocol names the
/// tokens below; Loom's own apps announce more of their own, which any other
/// device ignores as it ignores every token it does not know.
public enum WireFeature {
    /// Pairing by a typed code, version 2 (PROTOCOL.md 5.3). Also offered
    /// inside `pairingOffer`; listed here so a peer can tell before pairing.
    public static let pairing2 = "pairing2"
    /// Equal devices: no host and no client, only who dialled whom.
    public static let peer1 = "peer1"
    /// Both ends prove the pair's secret on the control channel (`auth`).
    public static let auth1 = "auth1"
    /// The open device protocol, at the major version `DeviceProtocol`
    /// names: `open1` for version 1. Said beside `versions` in `hello`, so
    /// a build that reads only `features` still sees it.
    public static func open(_ major: Int) -> String { "open\(major)" }
    /// Version 1 of the open device protocol.
    public static let open1 = open(1)

    /// What a device that implements only the open protocol announces.
    public static let openAnnounced: [String] =
        [pairing2, auth1, peer1] + DeviceProtocol.supportedVersions.map(open)
}

/// The first message on a control connection, read or written the same way
/// everywhere. See PROTOCOL.md 3.3.
public struct PeerHello: Equatable, Sendable {
    public let protocolVersion: Int
    public let deviceID: String
    public let deviceName: String?
    public let catalogRevision: Int64?
    /// Zero or absent: no data channel there now.
    public let dataPort: UInt16?
    /// Nil from a build that did not say — any build from before 2026-10.
    public let deviceClass: DeviceClass?
    public let features: Set<String>
    /// Capability names as sent, unknown ones kept, so a later build's are
    /// not lost on the way through.
    public let capabilities: Set<String>
    /// Sixteen fresh bytes, from a build that speaks `auth1`.
    public let nonce: Data?
    /// The open-protocol versions the sender speaks (`versions`), as sent.
    /// Empty from a build before they were said; see `protocolVersions`.
    public let declaredVersions: [Int]
    /// Loom-internal: where the sender's catalogue streams stand. A device
    /// that is not one of Loom's apps neither sends nor reads these.
    public let syncEpoch: String?
    /// Loom-internal, beside `syncEpoch`.
    public let syncTracks: String?

    public init(
        protocolVersion: Int = WireProtocol.version,
        deviceID: String,
        deviceName: String?,
        catalogRevision: Int64? = nil,
        dataPort: UInt16? = nil,
        deviceClass: DeviceClass? = DeviceClass.this,
        features: Set<String>,
        capabilities: Set<Capability>,
        versions: [Int] = DeviceProtocol.supportedVersions,
        nonce: Data? = nil,
        syncEpoch: String? = nil,
        syncTracks: String? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.deviceID = deviceID
        self.deviceName = deviceName
        self.catalogRevision = catalogRevision
        self.dataPort = dataPort
        self.deviceClass = deviceClass
        self.features = features
        self.capabilities = Set(capabilities.map(\.rawValue))
        self.declaredVersions = versions
        self.nonce = nonce
        self.syncEpoch = syncEpoch
        self.syncTracks = syncTracks
    }

    /// Whether both this build and the sender of this `hello` prove the
    /// pair's secret on the control channel.
    public var speaksAuth: Bool {
        features.contains(WireFeature.auth1) && nonce?.count == ControlAuth.nonceLength
    }

    /// The open-protocol versions to negotiate with: what the sender
    /// declared, or, from a Loom build before `versions`, version 1, which
    /// is what every such build speaks.
    public var protocolVersions: [Int] {
        declaredVersions.isEmpty ? [1] : declaredVersions
    }

    /// The open-protocol version both ends use: the highest both speak. Nil
    /// when they share none, and then the link carries nothing but this
    /// `hello`.
    public func negotiatedVersion(ours: [Int] = DeviceProtocol.supportedVersions) -> Int? {
        DeviceProtocol.negotiate(ours: ours, theirs: protocolVersions)
    }

    public func has(_ capability: Capability) -> Bool {
        capabilities.contains(capability.rawValue)
    }

    /// Whether this device may be offered as a place to play, steered from
    /// afar, or made a member of a shared listening session. See `noPlayback`.
    public var mayPlay: Bool { !has(.noPlayback) }

    /// Whether this is a build from before capabilities were said: no
    /// `features` and no `class`. A new build without capabilities (a phone)
    /// sends both and an empty `caps`.
    public var predatesCapabilities: Bool { features.isEmpty && deviceClass == nil }

    /// Whether the device can search services and download for others. An
    /// older Loom build is a desktop that can. See PROTOCOL.md 3.3.
    public var mayAcquire: Bool { has(.acquire) || predatesCapabilities }

    /// Reads a `hello`. Nil for anything else, or one without a device id.
    public init?(_ message: WireMessage) {
        guard message.type == .hello,
              let payload = message.payload,
              let id = payload["deviceId"]?.stringValue, !id.isEmpty,
              id.utf8.count <= Self.maximumIDBytes
        else { return nil }
        protocolVersion = payload["proto"]?.intValue.map(Int.init) ?? 0
        deviceID = id
        deviceName = payload["deviceName"]?.stringValue.map { PeerAdvertisement.fitted($0) }
        catalogRevision = payload["catalogRevision"]?.intValue
        dataPort = payload["dataPort"]?.intValue
            .flatMap { $0 > 0 && $0 <= Int64(UInt16.max) ? UInt16($0) : nil }
        deviceClass = payload["class"]?.stringValue.map { DeviceClass(wire: $0) }
        features = Self.strings(payload["features"])
        capabilities = Self.strings(payload["caps"])
        nonce = payload["nonce"]?.stringValue.flatMap { Data(base64Encoded: $0) }
        syncEpoch = payload["syncEpoch"]?.stringValue.flatMap { $0.isEmpty ? nil : $0 }
        syncTracks = payload["syncTracks"]?.stringValue
        declaredVersions = DeviceProtocol.versions(in: payload[DeviceProtocol.helloKey])
    }

    /// The message itself. Older builds read the keys they know and skip the
    /// rest, so nothing here needs a second, older form.
    public func message(id: String = UUID().uuidString) -> WireMessage {
        var fields: [String: JSONValue] = [
            "proto": .int(Int64(protocolVersion)),
            "deviceId": .string(deviceID),
            "features": .array(features.sorted().map(JSONValue.string)),
            "caps": .array(capabilities.sorted().map(JSONValue.string))
        ]
        if let deviceName { fields["deviceName"] = .string(deviceName) }
        if let catalogRevision { fields["catalogRevision"] = .int(catalogRevision) }
        // Said as 0 when there is none, as builds before this one always did:
        // they read a missing port and a zero one alike.
        fields["dataPort"] = .int(Int64(dataPort ?? 0))
        if let deviceClass { fields["class"] = .string(deviceClass.rawValue) }
        if let nonce { fields["nonce"] = .string(nonce.base64EncodedString()) }
        if let syncEpoch { fields["syncEpoch"] = .string(syncEpoch) }
        if let syncTracks { fields["syncTracks"] = .string(syncTracks) }
        if !declaredVersions.isEmpty {
            fields[DeviceProtocol.helloKey] = .array(declaredVersions.map { .int(Int64($0)) })
        }
        return WireMessage(type: .hello, id: id, payload: .object(fields))
    }

    /// A device id longer than this is not one; ids are UUIDs or close.
    public static let maximumIDBytes = 200
    /// At most this many feature or capability names are read, each at most
    /// `maximumNameBytes`: a `hello` is read before its sender has proved
    /// anything, and a set of a million names is not a feature list.
    public static let maximumNames = 64
    public static let maximumNameBytes = 64

    private static func strings(_ value: JSONValue?) -> Set<String> {
        guard case .array(let items) = value else { return [] }
        return Set(items.prefix(maximumNames).compactMap(\.stringValue)
            .filter { !$0.isEmpty && $0.utf8.count <= maximumNameBytes })
    }
}
