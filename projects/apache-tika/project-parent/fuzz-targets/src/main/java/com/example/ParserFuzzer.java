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

import java.io.InputStream;

import org.xml.sax.ContentHandler;

import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.parser.Parser;
import org.apache.tika.parser.RecursiveParserWrapper;
import org.apache.tika.sax.BasicContentHandlerFactory;
import org.apache.tika.sax.RecursiveParserWrapperHandler;
import org.apache.tika.sax.ToTextContentHandler;


class ParserFuzzer {

    public static void parseOne(Parser parser, byte[] bytes, ParseContext parseContext) throws Throwable {
        parseBytes(parser, bytes, parseContext);
        parseFile(parser, bytes, parseContext);
    }


    public static void parseOne(Parser parser, byte[] bytes) throws Throwable {
        parseBytes(parser, bytes, new ParseContext());
        parseFile(parser, bytes, new ParseContext());
    }

    public static void parseRMetaFile(Parser parser, byte[] bytes) throws Throwable {
        RecursiveParserWrapper wrapper = new RecursiveParserWrapper(parser);
        RecursiveParserWrapperHandler rpwh = new RecursiveParserWrapperHandler(
                new BasicContentHandlerFactory(BasicContentHandlerFactory.HANDLER_TYPE.XML, -1));
        try (TikaInputStream tis = TikaInputStream.get(bytes)) {
            tis.getPath();
            wrapper.parse(tis, rpwh, new Metadata(), new ParseContext());
        }
    }

    public static void parseBytes(Parser parser, byte[] bytes, ParseContext parseContext) throws Throwable {
        ContentHandler handler = new ToTextContentHandler();
        //make sure that other parsers cannot be invoked
        parseContext.set(Parser.class, parser);
        //try first with bytes
        try (InputStream is = TikaInputStream.get(bytes)) {
            parser.parse(is, handler, new Metadata(), parseContext);
        }
    }

    public static void parseFile(Parser parser, byte[] bytes, ParseContext parseContext) throws Throwable {
        ContentHandler handler = new ToTextContentHandler();
        //make sure that other parsers cannot be invoked
        parseContext.set(Parser.class, parser);
        try (TikaInputStream tis = TikaInputStream.get(bytes)) {
            //force writing to tmp file
            tis.getPath();
            parser.parse(tis, handler, new Metadata(), parseContext);
        }
    }
}
