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
import com.fasterxml.jackson.core.io.SerializedString;
import com.fasterxml.jackson.dataformat.xml.JacksonXmlModule;
import com.fasterxml.jackson.dataformat.xml.XmlFactory;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.dataformat.xml.ser.ToXmlGenerator;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.EnumSet;
import javax.xml.namespace.QName;

/** This fuzzer targets the methods of the ToXmlGenerator object */
public class ToXmlGeneratorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Retrieve set of ToXmlGenerator.Feature
      EnumSet<ToXmlGenerator.Feature> featureSet = EnumSet.allOf(ToXmlGenerator.Feature.class);

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

      // Failsafe logic
      if (mapper == null) {
        return;
      }

      // Create and configure ToXmlGenerator
      ToXmlGenerator generator =
          ((XmlMapper) mapper).getFactory().createGenerator(new ByteArrayOutputStream());
      for (ToXmlGenerator.Feature feature : EnumSet.allOf(ToXmlGenerator.Feature.class)) {
        generator.configure(feature, data.consumeBoolean());
      }
      generator.initGenerator();
      generator.setNextName(new QName("OSS-Fuzz"));
      generator.writeStartObject();

      // Fuzz methods of ToXmlGenerator
      String value = null;
      switch (data.consumeInt(1, 18)) {
        case 1:
          generator.writeStringField(
              data.consumeString(data.remainingBytes()), data.consumeRemainingAsString());
          break;
        case 2:
          generator.writeFieldName(new SerializedString(data.consumeRemainingAsString()));
          break;
        case 3:
          value = data.consumeRemainingAsString();
          generator.writeString(value.toCharArray(), 0, value.length());
          break;
        case 4:
          generator.writeString(new SerializedString(data.consumeRemainingAsString()));
          break;
        case 5:
          generator.writeRawValue(data.consumeRemainingAsString());
          break;
        case 6:
          value = data.consumeRemainingAsString();
          generator.writeRawValue(value, 0, value.length());
          break;
        case 7:
          value = data.consumeRemainingAsString();
          generator.writeRawValue(value.toCharArray(), 0, value.length());
          break;
        case 8:
          value = data.consumeRemainingAsString();
          generator.writeRaw(value, 0, value.length());
          break;
        case 9:
          value = data.consumeRemainingAsString();
          generator.writeRaw(value.toCharArray(), 0, value.length());
          break;
        case 10:
          generator.writeBoolean(data.consumeBoolean());
          break;
        case 11:
          generator.writeNull();
          break;
        case 12:
          generator.writeNumber(data.consumeInt());
          break;
        case 13:
          generator.writeNumber(data.consumeLong());
          break;
        case 14:
          generator.writeNumber(data.consumeDouble());
          break;
        case 15:
          generator.writeNumber(data.consumeFloat());
          break;
        case 16:
          generator.writeNumber(new BigDecimal(data.consumeLong()));
          break;
        case 17:
          generator.writeNumber(BigInteger.valueOf(data.consumeLong()));
          break;
        case 18:
          generator.writeNumber(data.consumeRemainingAsString());
          break;
      }

      generator.writeEndObject();
      generator.flush();
      generator.close();
    } catch (IOException | IllegalArgumentException | IllegalStateException e) {
      // Known exception
    }
  }
}
