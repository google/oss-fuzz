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
import com.amazon.ion.IonException;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.dataformat.ion.IonFactory;
import com.fasterxml.jackson.dataformat.ion.IonFactoryBuilder;
import com.fasterxml.jackson.dataformat.ion.IonObjectMapper;
import com.fasterxml.jackson.dataformat.ion.IonParser;
import java.io.IOException;
import java.util.EnumSet;

/** This fuzzer targets the methods of IonParser */
public class IonParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      int[] choices = data.consumeInts(data.consumeInt(1, 100));

      // Retrieve set of IonParser.Feature
      EnumSet<IonParser.Feature> featureSet = EnumSet.allOf(IonParser.Feature.class);

      // Create and configure IonObjectMapper
      IonFactoryBuilder ionFactoryBuilder;
      if (data.consumeBoolean()) {
        ionFactoryBuilder = IonFactory.builderForBinaryWriters();
      } else {
        ionFactoryBuilder = IonFactory.builderForTextualWriters();
      }
      IonObjectMapper mapper =
          new IonObjectMapper(
              ionFactoryBuilder
                  .enable(data.pickValue(featureSet))
                  .disable(data.pickValue(featureSet))
                  .build());

      // Failsafe logic
      if (mapper == null) {
        return;
      }

      // Create and configure IonParser
      byte[] byteArray = data.consumeRemainingAsBytes();
      if ((byteArray == null) || (byteArray.length <= 0)) {
        return;
      }
      JsonParser parser = ((IonObjectMapper) mapper).getFactory().createParser(byteArray);

      // Fuzz methods of IonParser
      for (Integer choice : choices) {
        switch (Math.abs(choice) % 19) {
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
          default:
            parser.getDecimalValue();
            break;
        }
      }

      parser.close();
    } catch (IOException | IllegalArgumentException | IllegalStateException | IonException e) {
      // Known exception
    }
  }
}
