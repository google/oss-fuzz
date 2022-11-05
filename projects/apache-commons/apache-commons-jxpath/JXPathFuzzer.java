// Copyright 2022 Google LLC
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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.StringReader;
import java.io.IOException;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.jxpath.JXPathContext;
import org.apache.commons.jxpath.JXPathException;


public class JXPathFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        DocumentBuilder builder = null;
        Document doc = null;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setValidating(data.consumeBoolean());
            factory.setNamespaceAware(data.consumeBoolean());
            factory.setExpandEntityReferences(data.consumeBoolean());
            builder = factory.newDocumentBuilder();
        } catch (Exception parserConfigurationException) {
        }

        try {
            doc = builder.parse(new InputSource(new StringReader(data.consumeString(2000))));
        } catch (SAXException | IOException e) {
        }

        JXPathContext context = JXPathContext.newContext(doc);
        try {
            context.selectNodes(data.consumeRemainingAsString());
        } catch (JXPathException e) {
        }
    }
}
