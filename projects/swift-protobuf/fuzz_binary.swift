import Foundation
import SwiftProtobuf

@_cdecl("LLVMFuzzerTestOneInput")
public func test(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
  let bytes = UnsafeRawBufferPointer(start: start, count: count)
  var options = BinaryDecodingOptions()
  options.messageDepthLimit = 256
  do {
    let _ = try ProtobufUnittest_NestedTestAllTypes(serializedData: Data(bytes),
                                             options: options)
  } catch let e {
  }
  return 0
}

