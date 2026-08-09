package org.xnio.http;

import java.io.IOException;
import java.nio.ByteBuffer;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;


public class HttpParserFuzzer {

    private FuzzedDataProvider fuzzedDataProvider;

    public HttpParserFuzzer(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        this.fuzzedDataProvider = fuzzedDataProvider;
    }

    void test() {
        byte b[] = new byte[]{ 1 };
        int n = fuzzedDataProvider.remainingBytes();
        if(n != 0) {
            b = fuzzedDataProvider.consumeBytes(n);
        }
        HttpUpgradeParser parser = new HttpUpgradeParser();
        ByteBuffer buffer = ByteBuffer.wrap(b);
        
        try {
            /*
             * read everything, like HttpParserTestCase.testOneCharacterAtATime does,
             * but read junk after that, too
             */
            for(int i=0; i!=n; ++i) {
                buffer.limit(i);
                parser.parse(buffer);
            }
        } catch (IOException exception) {
            /* ignore */
        } catch (IllegalArgumentException excepion) {
            /* ignore */
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider)  throws Exception {

        HttpParserFuzzer fixture = new HttpParserFuzzer(fuzzedDataProvider);
        fixture.test();
    }
}