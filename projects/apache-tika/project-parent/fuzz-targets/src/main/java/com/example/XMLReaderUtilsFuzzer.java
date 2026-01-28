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
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.stream.Stream;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.w3c.dom.Document;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import org.apache.tika.exception.TikaException;
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.sax.ToTextContentHandler;
import org.apache.tika.utils.XMLReaderUtils;


class XMLReaderUtilsFuzzer {

    public static void fuzzerTestOneInput(byte[] bytes) throws Exception {
        try {
            parseOne(bytes);
        } catch (java.io.FileNotFoundException e) {
            //this should be rethrown because it could signal an XMLParser looking for a DTD
            throw e;
        } catch (TikaException | IOException | SAXException e) {
            e.printStackTrace();
        }
    }

    private static void parseOne(byte[] bytes) throws TikaException, IOException, SAXException {

        //dom
        try (InputStream is = TikaInputStream.get(bytes)) {
            Document doc = XMLReaderUtils.buildDOM(is, new ParseContext());
        } catch (SAXParseException e) {
            //swallow
        }
        //sax
        try (InputStream is = TikaInputStream.get(bytes)) {
            ToTextContentHandler toTextContentHandler = new ToTextContentHandler();
            XMLReaderUtils.parseSAX(is, toTextContentHandler, new ParseContext());
        } catch (SAXException e) {
            //swallow
        }

        //stax
        try (InputStream is = TikaInputStream.get(bytes)) {
            XMLStreamReader reader = XMLReaderUtils.getXMLInputFactory(new ParseContext())
                .createXMLStreamReader(is);
            while (reader.hasNext()) {
                reader.next();
            }
        } catch (java.util.MissingResourceException | XMLStreamException e) {
            //MissingResourceException can be thrown when an internal DTD has an InvalidCharInDTD
            //throw new TikaException("xml stream", e);
        }
    }
}
