// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Fuzz targets for the OCI parsing code in apple/containerization.
// Each entry point decodes arbitrary bytes as one of the untrusted JSON
// documents (or reference strings) the library consumes, then walks the
// decoded structure and re-encodes it to exercise the full Codable path.

import ContainerizationOCI
import Foundation

private let decoder = JSONDecoder()
private let encoder = JSONEncoder()

private let maxInput = 1_000_000

@_cdecl("ociManifestFuzzer")
public func ociManifestFuzzer(_ data: UnsafePointer<UInt8>, _ size: Int) -> Int32 {
    guard size > 0, size <= maxInput else { return 0 }
    let input = Data(bytes: data, count: size)
    guard let manifest = try? decoder.decode(Manifest.self, from: input) else { return 0 }
    _ = manifest.schemaVersion
    _ = manifest.mediaType
    _ = manifest.config.digest
    _ = manifest.config.size
    _ = manifest.layers.map(\.digest)
    _ = manifest.annotations?.count
    _ = manifest.subject?.digest
    _ = manifest.artifactType
    if let encoded = try? encoder.encode(manifest) { _ = encoded.count }
    return 0
}

@_cdecl("ociIndexFuzzer")
public func ociIndexFuzzer(_ data: UnsafePointer<UInt8>, _ size: Int) -> Int32 {
    guard size > 0, size <= maxInput else { return 0 }
    let input = Data(bytes: data, count: size)
    guard let index = try? decoder.decode(Index.self, from: input) else { return 0 }
    _ = index.schemaVersion
    _ = index.mediaType
    for descriptor in index.manifests {
        _ = descriptor.digest
        _ = descriptor.mediaType
        _ = descriptor.size
        _ = descriptor.platform?.architecture
        _ = descriptor.platform?.os
    }
    _ = index.annotations?.count
    _ = index.subject?.digest
    if let encoded = try? encoder.encode(index) { _ = encoded.count }
    return 0
}

@_cdecl("ociImageConfigFuzzer")
public func ociImageConfigFuzzer(_ data: UnsafePointer<UInt8>, _ size: Int) -> Int32 {
    guard size > 0, size <= maxInput else { return 0 }
    let input = Data(bytes: data, count: size)
    guard let image = try? decoder.decode(Image.self, from: input) else { return 0 }
    _ = image.created
    _ = image.author
    _ = image.architecture
    _ = image.os
    _ = image.osVersion
    _ = image.variant
    _ = image.config?.user
    _ = image.config?.env?.count
    _ = image.config?.entrypoint?.count
    _ = image.config?.cmd?.count
    _ = image.config?.workingDir
    _ = image.config?.labels?.count
    _ = image.config?.stopSignal
    _ = image.rootfs.type
    _ = image.rootfs.diffIDs
    for entry in image.history ?? [] {
        _ = entry.created
        _ = entry.createdBy
    }
    if let encoded = try? encoder.encode(image) { _ = encoded.count }
    return 0
}

@_cdecl("ociSpecFuzzer")
public func ociSpecFuzzer(_ data: UnsafePointer<UInt8>, _ size: Int) -> Int32 {
    guard size > 0, size <= maxInput else { return 0 }
    let input = Data(bytes: data, count: size)
    guard let spec = try? decoder.decode(Spec.self, from: input) else { return 0 }
    _ = spec.version
    _ = spec.hostname
    if let process = spec.process {
        _ = process.args
        _ = process.cwd
        _ = process.env
        _ = process.user.uid
        _ = process.user.gid
    }
    _ = spec.root?.path
    for mount in spec.mounts {
        _ = mount.destination
        _ = mount.type
        _ = mount.source
        _ = mount.options
    }
    _ = spec.annotations?.count
    if let encoded = try? encoder.encode(spec) { _ = encoded.count }
    return 0
}

@_cdecl("ociReferenceFuzzer")
public func ociReferenceFuzzer(_ data: UnsafePointer<UInt8>, _ size: Int) -> Int32 {
    guard size > 0, size <= 4096 else { return 0 }
    let input = UnsafeBufferPointer(start: data, count: size)
    let string = String(decoding: input, as: UTF8.self)
    guard let reference = try? Reference.parse(string) else { return 0 }
    _ = reference.domain
    _ = reference.resolvedDomain
    _ = reference.path
    _ = reference.tag
    _ = reference.digest
    _ = reference.name
    _ = reference.description
    return 0
}
