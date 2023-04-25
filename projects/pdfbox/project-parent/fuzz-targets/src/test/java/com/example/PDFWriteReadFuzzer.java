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

import java.io.File;
import java.io.IOException;
import java.util.logging.LogManager;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import static org.apache.pdfbox.pdmodel.font.Standard14Fonts.FontName;


class PDFWriteReadFuzzer {
    static String fileName = "fuzz.pdf";
    static File myFile = new File(fileName);

    @BeforeAll
    static void setUp() {
        LogManager.getLogManager().reset();
    }

    @AfterAll
    static void cleanUp() {
        myFile.delete();
    }

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        try {
            PDDocument doc = new PDDocument();

            for (int i = 0; i < data.consumeInt(0, 50); ++i) {
                PDPage myPage = new PDPage();
                doc.addPage(myPage);
                try (PDPageContentStream cont = new PDPageContentStream(doc, myPage)) {
                    cont.beginText();

                    cont.setFont(new PDType1Font(data.pickValue(FontName.values())), data.consumeInt());
                    cont.setLeading(data.consumeFloat());
                    cont.newLineAtOffset(data.consumeInt(), data.consumeInt());
                    String line = data.consumeString(10000);
                    cont.showText(line);
                    cont.newLine();

                    cont.endText();
                }
            }
            doc.save(fileName);

            doc = Loader.loadPDF(myFile);
            PDFTextStripper stripper = new PDFTextStripper();
            String text = stripper.getText(doc);
        } catch (IOException | IllegalArgumentException e) {
        }
    }
}