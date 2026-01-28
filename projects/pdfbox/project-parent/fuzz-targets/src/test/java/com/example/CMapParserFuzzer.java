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

import org.apache.fontbox.cmap.CMapParser;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
/**
 * the .cid files extracted my mutool aren't pure character maps
 * On a random selection, it looks like the CMapParser can parse ~30%
 * without an exception. We should figure out why the other cid files
 * aren't parsing, but they are a close enough fit for seeds for now.
 */
public class CMapParserFuzzer {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        byte[] bytes = data.consumeRemainingAsBytes();
        try (RandomAccessRead buffer = new RandomAccessReadBuffer(bytes)) {
            new CMapParser().parse(buffer);
        } catch (IOException e) {
        }

    }
}