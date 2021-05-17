// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "grpc-swift-fuzz",
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(name: "grpc-swift", path: ".."),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "grpc-swift-fuzz",
            dependencies: [
                .target(name: "EchoImplementation"),
                .product(name: "GRPC", package: "grpc-swift")
            ]),

        .target(
            name: "EchoImplementation",
            dependencies: [
                .target(name: "EchoModel"),
                .product(name: "GRPC", package: "grpc-swift"),
                ],
            path: "Sources/Echo/Implementation"
        ),

        .target(
            name: "EchoModel",
            dependencies: [
                .product(name: "GRPC", package: "grpc-swift"),
                ],
            path: "Sources/Echo/Model"
        ),
    ]
)
