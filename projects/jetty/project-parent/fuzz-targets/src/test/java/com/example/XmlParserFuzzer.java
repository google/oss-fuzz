// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in co  mpliance with the License.
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
//////////////////////////////////////////////////////////////////////////////////


package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.eclipse.jetty.xml.XmlParser;

import org.xml.sax.SAXParseException;

import java.io.ByteArrayInputStream;


class XmlParserFuzzer
{
    @FuzzTest
    void testXmlParser(FuzzedDataProvider data) throws Exception
    {
        XmlParser parser = new XmlParser();
        try {
            parser.parse(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
        } catch (SAXParseException e) {}
    }
}
