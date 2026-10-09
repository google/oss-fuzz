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
////////////////////////////////////////////////////////////////////////////////

package com.example;

import java.io.IOException;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;

class PDFExtractTextFuzzer {


    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        byte [] bytes = data.consumeRemainingAsBytes();

        try (RandomAccessRead buffer = new RandomAccessReadBuffer(bytes)) {
            PDDocument pdDocument = Loader.loadPDF(buffer);
            String txt = new PDFTextStripper().getText(pdDocument);
        } catch (IOException | IllegalArgumentException e) {
        }
    }
}