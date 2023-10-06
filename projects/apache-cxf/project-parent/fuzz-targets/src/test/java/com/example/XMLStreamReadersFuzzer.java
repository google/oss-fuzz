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
//////////////////////////////////////////////////////////////////////////////////

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import org.apache.cxf.staxutils.*;

import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.w3c.dom.Document;

public class XMLStreamReadersFuzzer {

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        int i1 = data.consumeInt();
        int i2 = data.consumeInt();
        int i3 = data.consumeInt();
        String str1 = data.consumeString(250);
        String str2 = data.consumeString(250);
        String str3 = data.consumeString(250);
        String str4 = data.consumeString(250);
        String str5 = data.consumeString(250);
        String str6 = data.consumeString(250);
        String str7 = data.consumeString(250);

        Map<String, String> map = new HashMap<>();
        map.put(str3, str4);
        map.put(str5, str6);

        try {
            XMLStreamReader reader = StaxUtils.createXMLStreamReader(new StringReader(str7));
            XMLStreamReader xmlStreamReaders [] = {
                    reader,
                    new DepthRestrictingStreamReader(reader, i1, i2, i3),
                    new DepthXMLStreamReader(reader),
                    new PartialXMLStreamReader(reader, new QName(str1, str2)),
                    new FragmentStreamReader(reader),
                    new PropertiesExpandingStreamReader(reader, map)
            };

            DepthRestrictingStreamReader depthRestrictingStreamReader = new DepthRestrictingStreamReader(data.pickValue(xmlStreamReaders), i1, i2, i3);
            Document doc = StaxUtils.read(depthRestrictingStreamReader);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            XMLStreamWriter writer = StaxUtils.createXMLStreamWriter(bos);
            StaxUtils.copy(doc, writer);
            writer.flush();

            DepthXMLStreamReader depthXMLStreamReader = new DepthXMLStreamReader(data.pickValue(xmlStreamReaders));
            doc = StaxUtils.read(depthXMLStreamReader);
            bos = new ByteArrayOutputStream();
            writer = StaxUtils.createXMLStreamWriter(bos);
            StaxUtils.copy(doc, writer);
            writer.flush();

            FragmentStreamReader fragmentStreamReader = new FragmentStreamReader(data.pickValue(xmlStreamReaders));
            doc = StaxUtils.read(depthXMLStreamReader);
            bos = new ByteArrayOutputStream();
            writer = StaxUtils.createXMLStreamWriter(bos);
            StaxUtils.copy(doc, writer);
            writer.flush();

            PartialXMLStreamReader partialXMLStreamReader = new PartialXMLStreamReader(data.pickValue(xmlStreamReaders), new QName(str1, str2));
            doc = StaxUtils.read(partialXMLStreamReader);
            bos = new ByteArrayOutputStream();
            writer = StaxUtils.createXMLStreamWriter(bos);
            StaxUtils.copy(doc, writer);
            writer.flush();

            PropertiesExpandingStreamReader propertiesExpandingStreamReader = new PropertiesExpandingStreamReader(data.pickValue(xmlStreamReaders), map);
            doc = StaxUtils.read(partialXMLStreamReader);
            bos = new ByteArrayOutputStream();
            writer = StaxUtils.createXMLStreamWriter(bos);
            StaxUtils.copy(doc, writer);
            writer.flush();
        } catch (XMLStreamException | RuntimeException e) {

        }


    }
}
