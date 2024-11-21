package io.netty.handler.codec.http;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.netty.handler.BaseHandlerFuzzer;

public class HttpRequestDecoderFuzzer extends BaseHandlerFuzzer {
    {
        channel.pipeline().addLast(new HttpRequestDecoder());
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        new HttpRequestDecoderFuzzer().test(fuzzedDataProvider);
    }
}
