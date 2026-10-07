// Copyright 2024 Google LLC
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
import org.xmlunit.diff.*;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import javax.xml.transform.dom.DOMSource;

class DiffExpecter implements ComparisonListener {
         int invoked = 0;
         final int expectedInvocations;
         final ComparisonType type;
         final boolean withXPath;
         final String controlXPath;
         final String testXPath;
         boolean withParentXPath;
         String controlParentXPath;
         String testParentXPath;
         DiffExpecter(ComparisonType type) {
            this(type, 1);
        }
         DiffExpecter(ComparisonType type, int expected) {
            this(type, expected, false, null, null);
        }
         DiffExpecter(ComparisonType type, String controlXPath,
                             String testXPath) {
            this(type, 1, true, controlXPath, testXPath);
        }
         DiffExpecter(ComparisonType type, int expected,
                             boolean withXPath, String controlXPath,
                             String testXPath) {
            this.type = type;
            this.expectedInvocations = expected;
            this.withXPath = withXPath;
            this.controlXPath = controlXPath;
            this.testXPath = testXPath;
            withParentXPath = withXPath;
            controlParentXPath = getParentXPath(controlXPath);
            testParentXPath = getParentXPath(testXPath);
        }

        public DiffExpecter withParentXPath(String controlParentXPath, String testParentXPath) {
            withParentXPath = true;
            this.controlParentXPath = controlParentXPath;
            this.testParentXPath = testParentXPath;
            return this;
        }

        @Override
        public void comparisonPerformed(Comparison comparison,
                                        ComparisonResult outcome) {
            invoked++;
        }

         String getParentXPath(String xPath) {
            if (xPath == null) {
                return null;
            }
            if (xPath.equals("/") || xPath.equals("")) {
                return "";
            }
            int i = xPath.lastIndexOf('/');
            if (i == xPath.indexOf('/')) {
                return "/";
            }
            return i >= 0 ? xPath.substring(0, i) : xPath;
        }
    }

public class DOMDifferenceEngineCompareFuzzer {

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try{
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        DOMDifferenceEngine d = new DOMDifferenceEngine();
        DiffExpecter ex = new DiffExpecter(ComparisonType.NODE_TYPE, 0);
        d.addDifferenceListener(ex);
        d.setComparisonController(ComparisonControllers.StopWhenDifferent);
        d.compare(new DOMSource(doc.createElement(data.consumeString(100))),
                    new DOMSource(doc.createElement(data.consumeString(100))));
    }
    catch (org.w3c.dom.DOMException e) {}
    catch (javax.xml.parsers.ParserConfigurationException e) {}
  }
}