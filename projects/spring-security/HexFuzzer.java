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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

import java.lang.CharSequence;

import org.springframework.security.crypto.codec.Hex;

public class HexFuzzer {
    public static void fuzzerTestOneInput(byte[] data) {
        final byte[] initialByteArray = data;
        final char[] encodedChars;

        try {
            encodedChars = Hex.encode(initialByteArray);

            if (! initialByteArray.toString().equals(Hex.decode(encodedChars.toString()))) {
                throw new FuzzerSecurityIssueLow("Hex value has changed during encoding and decoding");
            }
        } catch (IllegalArgumentException err) {
            // ignore expected exceptions
        }
    }
}
