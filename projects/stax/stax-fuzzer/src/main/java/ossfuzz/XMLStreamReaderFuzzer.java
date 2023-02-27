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
////////////////////////////////////////////////////////////////////////////////

package ossfuzz;

import java.io.ByteArrayInputStream;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;


public class XMLStreamReaderFuzzer {

    private FuzzedDataProvider fuzzedDataProvider;

    public XMLStreamReaderFuzzer(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        this.fuzzedDataProvider = fuzzedDataProvider;
    }

    void test() {
        try {
            ByteArrayInputStream stream = new ByteArrayInputStream(fuzzedDataProvider.consumeRemainingAsBytes());
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(stream);
            while(reader.hasNext()) {
                reader.next();
            }
        } catch (XMLStreamException exception) {
            /* ignore */
        } catch (IllegalArgumentException exception) {
            /* ignore */
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider)  throws Exception {

        XMLStreamReaderFuzzer fixture = new XMLStreamReaderFuzzer(fuzzedDataProvider);
        fixture.test();
    }
}