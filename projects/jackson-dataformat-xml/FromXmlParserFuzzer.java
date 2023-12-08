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
import com.fasterxml.jackson.dataformat.xml.JacksonXmlModule;
import com.fasterxml.jackson.dataformat.xml.XmlFactory;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.dataformat.xml.deser.FromXmlParser;
import java.io.IOException;
import java.util.EnumSet;

/** This fuzzer targets the methods of the FromXmlParser object */
public class FromXmlParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer choice = data.consumeInt(1, 19);

      // Retrieve set of FromXmlParser.Feature
      EnumSet<FromXmlParser.Feature> featureSet = EnumSet.allOf(FromXmlParser.Feature.class);

      // Create and configure XmlMapper
      XmlMapper mapper = null;
      if (data.consumeBoolean()) {
        mapper =
            new XmlMapper(
                XmlFactory.builder()
                    .enable(data.pickValue(featureSet))
                    .disable(data.pickValue(featureSet))
                    .build());
      } else {
        mapper = new XmlMapper(new JacksonXmlModule());
      }

      // Create and configure FromXmlParser
      boolean[] featureChoice = data.consumeBooleans(featureSet.size());
      FromXmlParser parser =
          (FromXmlParser) mapper.getFactory().createParser(data.consumeRemainingAsString());

      int counter = 0;
      for (FromXmlParser.Feature feature : featureSet) {
        parser.configure(feature, featureChoice[counter++]);
      }

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
          parser.nextTextValue();
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
    } catch (IOException | IllegalArgumentException | IllegalStateException e) {
      // Known exception
    }
  }
}
