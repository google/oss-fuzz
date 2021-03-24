import Foundation
import SwiftProtobuf

@_cdecl("LLVMFuzzerTestOneInput")
public func test(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
  let bytes = UnsafeRawBufferPointer(start: start, count: count)
  var options = BinaryDecodingOptions()
  options.messageDepthLimit = 256
  do {
    let _ = try ProtobufUnittest_NestedTestAllTypes.self.init(serializedData: Data(bytes),
                                             options: options)
  } catch BinaryDecodingError.messageDepthLimit {
  } catch let e {
    print("Unexpected error: \(e)");
    return 1
  }
  return 0
}

