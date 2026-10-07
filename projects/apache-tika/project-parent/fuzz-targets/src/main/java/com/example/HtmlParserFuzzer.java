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
import org.apache.tika.parser.Parser;
import org.apache.tika.parser.html.JSoupParser;
import org.xml.sax.SAXException;

final class HtmlParserFuzzer {

    public static void fuzzerTestOneInput(final byte[] bytes) throws Throwable {
        Parser p = new JSoupParser();
        try {
            ParserFuzzer.parseOne(p, bytes);
        } catch (TikaException | SAXException | IOException e) {
          // swallow
        }
    }
}
