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
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.EnumSet;

/** This fuzzer targets the methods of CBORGenerator */
public class CborGeneratorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Retrieve set of CBORGenerator.Feature
      EnumSet<CBORGenerator.Feature> featureSet = EnumSet.allOf(CBORGenerator.Feature.class);

      // Create and configure CBORMapper
      CBORMapper mapper =
          new CBORMapper(
              CBORFactory.builder()
                  .enable(data.pickValue(featureSet))
                  .disable(data.pickValue(featureSet))
                  .build());

      // Failsafe logic
      if (mapper == null) {
        return;
      }

      // Create and configure CBORGenerator
      CBORGenerator generator =
          ((CBORMapper) mapper).getFactory().createGenerator(new ByteArrayOutputStream());
      for (CBORGenerator.Feature feature : featureSet) {
        generator.configure(feature, data.consumeBoolean());
      }
      generator.writeStartObject();

      // Fuzz methods of CBORGenerator
      String value = null;
      byte[] byteArray = null;
      generator.writeFieldName("OSS-Fuzz");
      switch (data.consumeInt(1, 18)) {
        case 1:
          generator.writeBoolean(data.consumeBoolean());
          break;
        case 2:
          generator.writeNull();
          break;
        case 3:
          int[] intArray = data.consumeInts(data.consumeInt(1, 5));
          generator.writeArray(intArray, 0, intArray.length);
          break;
        case 4:
          long[] longArray = data.consumeLongs(data.consumeInt(1, 5));
          generator.writeArray(longArray, 0, longArray.length);
          break;
        case 5:
          double[] doubleArray = new double[data.consumeInt(1, 5)];
          for (int i = 0; i < doubleArray.length; i++) {
            doubleArray[i] = data.consumeDouble();
          }
          generator.writeArray(doubleArray, 0, doubleArray.length);
          break;
        case 6:
          generator.writeString(data.consumeRemainingAsString());
          break;
        case 7:
          value = data.consumeRemainingAsString();
          generator.writeString(value.toCharArray(), 0, value.length());
          break;
        case 8:
          generator.writeString(new SerializedString(data.consumeRemainingAsString()));
          break;
        case 9:
          byteArray = data.consumeRemainingAsBytes();
          generator.writeRawUTF8String(byteArray, 0, byteArray.length);
          break;
        case 10:
          byteArray = data.consumeRemainingAsBytes();
          generator.writeUTF8String(byteArray, 0, byteArray.length);
          break;
        case 11:
          byteArray = data.consumeRemainingAsBytes();
          generator.writeBinary(new ByteArrayInputStream(byteArray), byteArray.length);
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
