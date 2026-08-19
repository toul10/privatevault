// swift-tools-version: 6.2
// PrivateVault — local-only, zero-knowledge macOS secrets manager.
// Build: swift build -c release   |  App bundle: Scripts/build-app.sh   |  Tests: Scripts/run-tests.sh
import PackageDescription

let package = Package(
    name: "PrivateVault",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "VaultCore", targets: ["VaultCore"]),
        .executable(name: "PrivateVaultApp", targets: ["PrivateVaultApp"]),
    ],
    targets: [
        // Vendored PHC reference Argon2 (see Sources/CArgon2/VENDOR.md). The ONLY third-party code.
        .target(
            name: "CArgon2",
            path: "Sources/CArgon2",
            exclude: ["VENDOR.md", "LICENSE"],
            cSettings: [
                .headerSearchPath("."),
                .unsafeFlags(["-O2"]),
            ]
        ),
        // Tiny C shim exposing memset_s / timingsafe_bcmp / mlock to Swift.
        .target(
            name: "CSecureMemory",
            path: "Sources/CSecureMemory",
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        // All cryptography, storage, models, backup — no UI, fully testable.
        .target(
            name: "VaultCore",
            dependencies: ["CArgon2", "CSecureMemory"],
            path: "Sources/VaultCore",
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ],
            linkerSettings: [
                .linkedLibrary("sqlite3"),
                .linkedFramework("Security"),
                .linkedFramework("CryptoKit"),
                .linkedFramework("LocalAuthentication"),
            ]
        ),
        // Thin SwiftUI app.
        .executableTarget(
            name: "PrivateVaultApp",
            dependencies: ["VaultCore"],
            path: "Sources/PrivateVaultApp",
            swiftSettings: [
                .defaultIsolation(MainActor.self),
            ],
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("SwiftUI"),
                .linkedFramework("LocalAuthentication"),
            ]
        ),
        // Run with Scripts/run-tests.sh (Command Line Tools keep Swift Testing outside the default search path).
        .testTarget(
            name: "VaultCoreTests",
            dependencies: ["VaultCore", "CArgon2"],
            path: "Tests/VaultCoreTests",
            resources: [.copy("Fixtures")]
        ),
    ]
)
