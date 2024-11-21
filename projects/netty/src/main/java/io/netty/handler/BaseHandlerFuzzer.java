package io.netty.handler;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;

/**
 * Base class for fuzzing the input of an inbound handler. Will report exceptions thrown by the handler.
 */
public abstract class BaseHandlerFuzzer {
    protected final EmbeddedChannel channel = new EmbeddedChannel();

    public void test(FuzzedDataProvider provider) {
        byte[] bytes = provider.consumeRemainingAsBytes();
        channel.writeInbound(Unpooled.wrappedBuffer(bytes));
        channel.finishAndReleaseAll();
        channel.checkException();
    }
}
