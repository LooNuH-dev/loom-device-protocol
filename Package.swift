// swift-tools-version:5.9
import PackageDescription

// The open part of Loom's device protocol: what a device that is not one of
// Loom's own apps needs to be found, pair, prove itself and ask for search,
// links and track files. See PROTOCOL.md beside this file.
//
// Its own package with its own version (`DeviceProtocol.libraryVersion`, and
// CHANGELOG.md), so it can be published on its own: Foundation and
// swift-crypto only, nothing of the app's library, player or storage.
let package = Package(
    name: "LoomDeviceProtocol",
    platforms: [.macOS(.v14), .iOS(.v17), .watchOS(.v10)],
    products: [
        .library(name: "LoomDeviceProtocol", targets: ["LoomDeviceProtocol"])
    ],
    dependencies: [
        // CryptoKit's API on every platform (HMAC, HKDF, P-256, AES-CMAC);
        // on Apple it re-exports CryptoKit. Apache-2.0.
        .package(url: "https://github.com/apple/swift-crypto", "3.0.0"..<"6.0.0")
    ],
    targets: [
        .target(
            name: "LoomDeviceProtocol",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]
        ),
        .testTarget(
            name: "LoomDeviceProtocolTests",
            dependencies: ["LoomDeviceProtocol", .product(name: "Crypto", package: "swift-crypto")]
        )
    ]
)
