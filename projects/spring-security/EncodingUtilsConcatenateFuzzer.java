// Copyright 2022 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////

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
