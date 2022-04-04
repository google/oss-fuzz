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

import java.io.ByteArrayInputStream;
import javax.xml.stream.*;
import com.ctc.wstx.stax.WstxInputFactory;

public class XmlFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        WstxInputFactory STAX_F = new WstxInputFactory();
        try {
            XMLStreamReader sr = STAX_F.createXMLStreamReader(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
            streamThrough(sr);
            sr.close();
        } catch (XMLStreamException e) {
        }
    }

    public static int streamThrough(XMLStreamReader sr) throws XMLStreamException {
        int result = 0;

        while (sr.hasNext()) {
            int type = sr.next();
            result += type;
            if (sr.hasText()) {
                result += getText(sr).hashCode();
            }
            if (sr.hasName()) {
                result += sr.getName().hashCode();
            }
        }

        return result;
    }

    public static String getText(XMLStreamReader sr) {
        int type = sr.getEventType();
        int expLen = sr.getTextLength();
        String text = sr.getText();
        char[] textChars = sr.getTextCharacters();
        int start = sr.getTextStart();

        return text;
    }
}