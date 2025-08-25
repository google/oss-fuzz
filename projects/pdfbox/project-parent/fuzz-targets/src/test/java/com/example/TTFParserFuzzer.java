// Copyright 2023 Google LLC
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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import java.io.IOException;
import java.util.logging.LogManager;

import org.apache.fontbox.ttf.TTFParser;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
import org.junit.jupiter.api.BeforeAll;

class TTFParserFuzzer {

    @BeforeAll
    static void setUp() {
        LogManager.getLogManager().reset();
    }

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        TTFParser parser = new TTFParser();
        byte[] bytes = data.consumeRemainingAsBytes();
        try {
            parser.parse(new RandomAccessReadBuffer(bytes));
        } catch (IOException | IllegalArgumentException e) {
        }
    }
}