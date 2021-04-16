import GRPC
import NIO
import EchoImplementation

@_cdecl("LLVMFuzzerTestOneInput")
public func test(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let bytes = UnsafeRawBufferPointer(start: start, count: count)

    let channel = EmbeddedChannel()
    let configuration = Server.Configuration(
        target: .unixDomainSocket("/ignored"),
        eventLoopGroup: channel.eventLoop,
        serviceProviders: [EchoProvider()]
    )
    let handler = GRPCServerPipelineConfigurator(configuration: configuration)

    var buffer = channel.allocator.buffer(capacity: count)
    buffer.writeBytes(bytes)
    do {
        try channel.pipeline.addHandler(handler).wait()
        try channel.writeInbound(buffer)
        channel.embeddedEventLoop.run()
    } catch {
    }
    do {
        try _ = channel.finish(acceptAlreadyClosed: true)
    } catch {
    }
    return 0
}
