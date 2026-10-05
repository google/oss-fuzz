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
    
    // Method to create and return a Document from a fuzzed input string
    private static Document createDocument(FuzzedDataProvider data) {
        DocumentBuilder builder = null;
        Document doc = null;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            
            // Setting factory attributes for additional coverage and security
            factory.setValidating(data.consumeBoolean());
            factory.setNamespaceAware(data.consumeBoolean());
            factory.setExpandEntityReferences(data.consumeBoolean());
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);  // Disable DTD declarations for security
            
            builder = factory.newDocumentBuilder();
        } catch (ParserConfigurationException | FactoryConfigurationError e) {
            System.err.println("Error creating DocumentBuilder: " + e.getMessage());
            return null;
        }

        // Consuming a random length for XML input (between 100 and 500 characters)
        String xmlInput = data.consumeString(data.consumeInt(100, 500));
        if (xmlInput.isEmpty()) {
            xmlInput = "<root></root>"; 
        }

        try {
            doc = builder.parse(new InputSource(new StringReader(xmlInput)));
        } catch (SAXException | IOException e) {
            System.err.println("Parsing error: " + e.getMessage());
        }
        
        return doc;
    }

    // Method to perform XPath query on the document using fuzzed input
    private static void performXPathQuery(Document doc, FuzzedDataProvider data) {
        if (doc == null) {
            System.err.println("Document is null, skipping XPath query.");
            return;
        }
        
        JXPathContext context = JXPathContext.newContext(doc);
        
        // Fuzzed XPath query, handling invalid cases
        String xpathQuery = data.consumeRemainingAsString();
        if (xpathQuery.length() < 5) { 
            xpathQuery = "//invalid_xpath";
        }
        
        try {
            context.selectNodes(xpathQuery);
        } catch (JXPathException e) {
            // Log any errors related to XPath execution
            System.err.println("XPath selection error: " + e.getMessage());
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // Create and parse the document from fuzzed data
        Document doc = createDocument(data);
        
        // Perform XPath query on the parsed document
        performXPathQuery(doc, data);
    }
}
