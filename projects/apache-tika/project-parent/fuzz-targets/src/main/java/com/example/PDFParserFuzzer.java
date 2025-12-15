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
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;

import org.apache.tika.exception.TikaException;
import org.apache.tika.parser.pdf.PDFParser;
import org.apache.tika.parser.pdf.PDFParserConfig;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.parser.Parser;


class PDFParserFuzzer {

    public static void fuzzerTestOneInput(byte[] bytes) throws Throwable {
        Parser p = new PDFParser();
        PDFParserConfig config = new PDFParserConfig();
        //what else do we want to exercise?
        config.setExtractActions(true);
        ParseContext parseContext = new ParseContext();
        parseContext.set(PDFParserConfig.class, config);
        try {
            ParserFuzzer.parseOne(p, bytes, parseContext);
        } catch (TikaException | SAXException | IOException e) {
            //swallow
        }
    }
}
