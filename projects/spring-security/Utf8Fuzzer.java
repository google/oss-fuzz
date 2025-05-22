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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

import java.lang.CharSequence;

import org.springframework.security.crypto.codec.Utf8;

public class Utf8Fuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        final String initialString = data.consumeString(Integer.MAX_VALUE);
        final byte[] encodedBytes;

        try {
            encodedBytes = Utf8.encode(initialString);

            if (! initialString.equals(Utf8.decode(encodedBytes))) {
                throw new FuzzerSecurityIssueLow("Utf8 value has changed during encoding and decoding");
            }
        } catch (IllegalArgumentException err) {
            // ignore expected exceptions
        }
    }
}
