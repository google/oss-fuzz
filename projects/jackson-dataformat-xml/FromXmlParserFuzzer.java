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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import tools.jackson.dataformat.xml.XmlFactory;
import tools.jackson.dataformat.xml.XmlMapper;
import tools.jackson.dataformat.xml.XmlReadFeature;
import tools.jackson.dataformat.xml.deser.FromXmlParser;
import java.util.EnumSet;

/** This fuzzer targets the methods of the FromXmlParser object */
public class FromXmlParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer choice = data.consumeInt(1, 19);

      // Retrieve set of XmlReadFeature
      EnumSet<XmlReadFeature> featureSet = EnumSet.allOf(XmlReadFeature.class);

      // Create and configure XmlMapper
      XmlMapper mapper = null;
      if (data.consumeBoolean()) {
        mapper =
            XmlMapper.builder(
                XmlFactory.builder()
                    .enable(data.pickValue(featureSet))
                    .disable(data.pickValue(featureSet))
                    .build())
                .build();
      } else {
        mapper = XmlMapper.builder().build();
      }

      // Create and configure FromXmlParser
      FromXmlParser parser =
          (FromXmlParser) mapper.createParser(data.consumeRemainingAsString());

      // Fuzz methods of FromXmlParser
      switch (choice) {
        case 1:
          parser.currentName();
          break;
        case 2:
          parser.currentTokenLocation();
          break;
        case 3:
          parser.currentLocation();
          break;
        case 4:
          parser.isExpectedStartArrayToken();
          break;
        case 5:
          parser.isExpectedNumberIntToken();
          break;
        case 6:
          parser.nextToken();
          break;
        case 7:
          parser.nextToken();
          parser.getText();
          break;
        case 8:
          parser.getText();
          break;
        case 9:
          parser.getTextCharacters();
          break;
        case 10:
          parser.getTextLength();
          break;
        case 11:
          parser.getTextOffset();
          break;
        case 12:
          parser.getNumberType();
          break;
        case 13:
          parser.getNumberValue();
          break;
        case 14:
          parser.getIntValue();
          break;
        case 15:
          parser.getLongValue();
          break;
        case 16:
          parser.getBigIntegerValue();
          break;
        case 17:
          parser.getFloatValue();
          break;
        case 18:
          parser.getDoubleValue();
          break;
        case 19:
          parser.getDecimalValue();
          break;
      }

      parser.close();
    } catch (RuntimeException e) {
      // Known exception
    }
  }
}
