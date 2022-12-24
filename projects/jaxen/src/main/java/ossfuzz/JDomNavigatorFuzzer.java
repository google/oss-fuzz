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

package ossfuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.*;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

import org.jaxen.Navigator;
import org.jaxen.XPath;
import org.jaxen.jdom.JDOMXPath;
import org.jaxen.JaxenException;
import org.jaxen.saxpath.XPathSyntaxException;

public class JDomNavigatorFuzzer {

    private FuzzedDataProvider fuzzedDataProvider;

    public JDomNavigatorFuzzer(FuzzedDataProvider fuzzedDataProvider) {

        this.fuzzedDataProvider = fuzzedDataProvider;

    }

    void test() throws Exception {
        try {
            InputStream in = getClass().getResourceAsStream("/test.xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(in);
            doc.getDocumentElement().normalize();
            XPath nullNamespacePath = new JDOMXPath(fuzzedDataProvider.consumeRemainingAsString());
            nullNamespacePath.selectNodes(doc);

        } catch (JaxenException e) {

        }

    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {

        JDomNavigatorFuzzer testFixture = new JDomNavigatorFuzzer(fuzzedDataProvider);
        testFixture.test();
    }
}