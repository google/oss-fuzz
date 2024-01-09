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
import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.dataformat.avro.AvroFactory;
import com.fasterxml.jackson.dataformat.avro.AvroFactoryBuilder;
import com.fasterxml.jackson.dataformat.avro.AvroMapper;
import com.fasterxml.jackson.dataformat.avro.AvroParser;
import com.fasterxml.jackson.dataformat.avro.schema.AvroSchemaGenerator;
import java.io.IOException;
import java.util.EnumSet;
import java.util.List;

/** This fuzzer targets the methods of AvroParser */
public class AvroParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      int[] choices = data.consumeInts(data.consumeInt(1, 100));

      // Retrieve set of AvroMapper.Feature
      EnumSet<AvroParser.Feature> featureSet = EnumSet.allOf(AvroParser.Feature.class);

      // Create and configure AvroMapper
      AvroFactoryBuilder avroFactoryBuilder;
      if (data.consumeBoolean()) {
        avroFactoryBuilder = AvroFactory.builderWithApacheDecoder();
      } else {
        avroFactoryBuilder = AvroFactory.builderWithNativeDecoder();
      }
      AvroMapper mapper =
          new AvroMapper(
              avroFactoryBuilder
                  .enable(data.pickValue(featureSet))
                  .disable(data.pickValue(featureSet))
                  .build());

      // Failsafe logic
      if (mapper == null) {
        return;
      }

      // Create and configure AvroParser
      AvroParser parser =
          ((AvroMapper) mapper).getFactory().createParser(data.consumeRemainingAsBytes());

      AvroSchemaGenerator schemaGenerator = new AvroSchemaGenerator();
      mapper.acceptJsonFormatVisitor(RootType.class, schemaGenerator);

      parser.setSchema(schemaGenerator.getGeneratedSchema());

      // Fuzz methods of AvroParser
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
    } catch (IOException | IllegalArgumentException | IllegalStateException e) {
      // Known exception
    }
  }

  private static class RootType {
    @JsonAlias({"nm", "Name"})
    public String name;

    public int value;

    List<String> other;
  }
}
