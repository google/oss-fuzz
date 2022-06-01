import NIOHTTP1
import NIO

@_cdecl("LLVMFuzzerTestOneInput")
public func test(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let bytes = UnsafeRawBufferPointer(start: start, count: count)
    let channel = EmbeddedChannel()
    var buffer = channel.allocator.buffer(capacity: count)
    buffer.writeBytes(bytes)
    do {
        try channel.pipeline.addHandler(ByteToMessageHandler(HTTPRequestDecoder())).wait()
        try channel.writeInbound(buffer)
        channel.embeddedEventLoop.run()
    } catch {
    }
    do {
        try channel.finish(acceptAlreadyClosed: true)
    } catch {
    }
    return 0
}
