// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "AliasReleaseConsumer",
    platforms: [.iOS(.v13)],
    products: [
        .library(name: "AliasReleaseConsumer", targets: ["AliasReleaseConsumer"]),
    ],
    dependencies: [
        .package(name: "BitwardenSdk", path: "../sdk"),
    ],
    targets: [
        .target(
            name: "AliasReleaseConsumer",
            dependencies: [
                .product(name: "BitwardenSdk", package: "BitwardenSdk"),
            ]
        ),
    ]
)
