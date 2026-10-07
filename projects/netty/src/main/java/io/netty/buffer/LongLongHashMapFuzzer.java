package io.netty.buffer;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


public class LongLongHashMapFuzzer {
    
    private FuzzedDataProvider fuzzedDataProvider;

    public LongLongHashMapFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        this.fuzzedDataProvider = fuzzedDataProvider;
    }

    void test() {
        Map<Long, Long> expected = new HashMap<Long, Long>();
        LongLongHashMap actual = new LongLongHashMap(-1);
        while (fuzzedDataProvider.remainingBytes() >= 9 /* sizeof(long) + sizeof(byte) */) {
            long value = fuzzedDataProvider.consumeLong();
            if (expected.containsKey(value)) {
                if (fuzzedDataProvider.consumeBoolean()) {
                    actual.remove(value);
                    expected.remove(value);
                } else {
                    long v = expected.get(value);
                    actual.put(value, -v);
                    expected.put(value, -v);
                }
            } else {
                actual.put(value, value);
                expected.put(value, value);
            }
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        LongLongHashMapFuzzer fixture = new LongLongHashMapFuzzer(fuzzedDataProvider);
        fixture.test();
    }
}