import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.springframework.security.crypto.util.EncodingUtils;

public class EncodingUtilsConcatenateFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        final byte[][] arrayOfByteArrays = getArrayOfByteArrays(data);

        EncodingUtils.concatenate(arrayOfByteArrays);
    }

    // Constants to reduce cases of fuzzer running out of memory
    private final static int MIN_OUTER_LENGTH = 500;
    private final static int MAX_OUTER_LENGTH = 1000;
    private final static int MIN_INNER_LENGTH = 320;
    private final static int MAX_INNER_LENGTH = 700;

    private static byte[][] getArrayOfByteArrays(FuzzedDataProvider data) {
        final int numberOfArrays = data.consumeInt(MIN_OUTER_LENGTH, MAX_OUTER_LENGTH);
        byte[][] arrayOfArrays = new byte[numberOfArrays][];

        for (int i=0; i<numberOfArrays; i++) {
            arrayOfArrays[i] = data.consumeBytes(data.consumeInt(MIN_INNER_LENGTH, MAX_INNER_LENGTH));
        }

        return arrayOfArrays;
    }
}
