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
import org.apache.tika.exception.TikaException;
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.parser.Parser;
import org.apache.tika.parser.html.JSoupParser;
import org.apache.tika.sax.ToTextContentHandler;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;

final class HtmlParserFuzzer {

  private HtmlParserFuzzer() {
  }

  public static void fuzzerTestOneInput(final byte[] bytes) throws Exception {

    try {
      parseOne(bytes);
    } catch (TikaException | SAXException | IOException e) {
      // swallow
    }
  }

  private static void parseOne(final byte[] bytes)
      throws TikaException, IOException, SAXException {
    Parser p = new JSoupParser();
    ContentHandler handler = new ToTextContentHandler();
    ParseContext parseContext = new ParseContext();
    // make sure that other parsers cannot be invoked
    parseContext.set(Parser.class, p);
    try (InputStream is = TikaInputStream.get(bytes)) {
      p.parse(is, handler, new Metadata(), parseContext);
    }
  }
}
