// Copyright 2025 Google LLC
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
/// /////////////////////////////////////////////////////////////////////////////

package com.example;

import java.io.IOException;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.apache.fontbox.type1.Type1Font;

/**
 * This attempts to parse type1 fonts that are extracted as *.pfa by mutool.
 * In the PDF, there are entries for where to split the font file.
 * We're just grepping for eexec and splitting there.
 */
public class PFAParserFuzzer {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        byte[] bytes = data.consumeRemainingAsBytes();
        int split = findSplit(bytes);
        if (split < 0) {
            //split in the middle if there are sufficient bytes
            if (bytes.length < 10) {
                return;
            }
            split = bytes.length / 2;
        }
        byte[] seg1 = new byte[split];
        byte[] seg2 = new byte[bytes.length - split];
        System.arraycopy(bytes, 0, seg1, 0, split);
        System.arraycopy(bytes, split, seg2, 0, bytes.length - split);
        try {
            Type1Font.createWithSegments(seg1, seg2);
        } catch (IOException e) {
        }

    }

    private static int findSplit(byte[] bytes) {
        for (int i = 0; i < bytes.length - 6; i++) {
            if ('e' == (char) bytes[i] &&
                    'e' == (char) bytes[i + 1] &&
                    'x' == (char) bytes[i + 2] &&
                    'e' == (char) bytes[i + 3] &&
                    'c' == (char) bytes[i + 4]
                //TODO -- check for new lines?
            ) {
                return i + 6;
            }
        }
        return -1;
    }
}