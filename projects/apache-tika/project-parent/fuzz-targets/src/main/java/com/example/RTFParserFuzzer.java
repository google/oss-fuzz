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
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.parser.Parser;
import org.apache.tika.parser.microsoft.rtf.RTFParser;
import org.apache.tika.sax.ToTextContentHandler;


class RTFParserFuzzer {

    public static void fuzzerTestOneInput(byte[] bytes) throws Exception {
        try {
            parseOne(bytes);
        } catch (AssertionError | TikaException | SAXException | IOException | org.apache.tika.metadata.PropertyTypeException e) {
            //swallow
        }
    }

    private static void parseOne(byte[] bytes) throws TikaException, IOException, SAXException {
        Parser p = new RTFParser();
        ContentHandler handler = new ToTextContentHandler();
        ParseContext parseContext = new ParseContext();
        //make sure that other parsers cannot be invoked
        parseContext.set(Parser.class, p);
        try (InputStream is = TikaInputStream.get(bytes)) {
            p.parse(is, handler, new Metadata(), parseContext);
        }
    }
}
