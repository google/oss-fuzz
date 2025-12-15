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

import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.InputStream;
import java.math.BigDecimal;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import tools.jackson.core.Base64Variant;
import tools.jackson.core.Base64Variants;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.UTF8JsonGenerator;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.StreamWriteFeature;
import tools.jackson.core.SerializableString;
import tools.jackson.core.io.SerializedString;

import tools.jackson.core.JacksonException;

public class UTF8GeneratorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    JsonFactory jf = new JsonFactory();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    String fuzzString;
    JsonGenerator g;
    int offset;
    byte[] b;
    Base64Variant b64v;

    StreamWriteFeature[] features = new StreamWriteFeature[]{
        StreamWriteFeature.AUTO_CLOSE_TARGET,
        StreamWriteFeature.AUTO_CLOSE_CONTENT,
        StreamWriteFeature.FLUSH_PASSED_TO_STREAM,
        StreamWriteFeature.WRITE_BIGDECIMAL_AS_PLAIN,
        StreamWriteFeature.STRICT_DUPLICATE_DETECTION,
        StreamWriteFeature.IGNORE_UNKNOWN,
    };

    try {
      g = jf.createGenerator(out);
      for (int i = 0; i < features.length; i++) {
        if (data.consumeBoolean()) {
          g.configure(features[i], true);
        } else {
          g.configure(features[i], false);
        }
      }
    } catch (JacksonException ignored) {
      return;
    }

    int numberOfOps = data.consumeInt();
    for (int i = 0; i < numberOfOps%20; i++) {
      try {      
        int apiType = data.consumeInt();
        switch(apiType%13) {
        case 0:
          fuzzString = data.consumeString(1000000);
          StringReader targetReader = new StringReader(fuzzString);
          g.writeStartArray();
          g.writeString(targetReader, fuzzString.length());
          g.writeEndArray();
        case 1:
          fuzzString = data.consumeString(1000000);
          g.writeStartArray();
          g.writeString(fuzzString);
          g.writeEndArray();
        case 2:
          fuzzString = data.consumeString(1000000);
          SerializableString ss = new SerializedString(fuzzString);
          g.writeStartArray();
          g.writeString(ss);
          g.writeEndArray();
        case 3:
          fuzzString = data.consumeString(1000000);
          g.writeStartArray();
          g.writeRaw(fuzzString);
          g.writeEndArray();
        case 4:
          fuzzString = data.consumeString(1000000);
          offset = data.consumeInt();
          g.writeStartArray();
          g.writeRaw(fuzzString, offset, fuzzString.length());
          g.writeEndArray();
        case 5:
          String key = data.consumeString(1000000);
          String value = data.consumeString(1000000);
          g.writeStartObject();
          g.writeStringProperty(key, value);
          g.writeEndObject();
        case 6:
          b64v = Base64Variants.getDefaultVariant();
          b = data.consumeBytes(1000000);
           offset = data.consumeInt();
          g.writeStartArray();
          g.writeBinary(b64v, b, offset, b.length);
          g.writeEndArray();
        case 7:
          b = data.consumeBytes(1000000);
          offset = data.consumeInt();
          g.writeStartObject();
          g.writeUTF8String(b, offset, b.length);
          g.writeEndObject();
        case 8:
          b64v = Base64Variants.getDefaultVariant();
          b = data.consumeBytes(1000000);
          int l = data.consumeInt();
          InputStream targetStream = new ByteArrayInputStream(b);
          g.writeStartArray();
          g.writeBinary(b64v, targetStream, l);
          g.writeEndArray();
        case 9:
          String dcString = data.consumeString(10);
          BigDecimal BD = new BigDecimal(dcString);
          g.writeNumber(BD);
        case 10:
          int fuzzInt = data.consumeInt();
          g.writeNumber(fuzzInt);
        case 11:
          float fuzzFloat = data.consumeFloat();
          g.writeNumber(fuzzFloat);
        case 12:
          fuzzString = data.consumeString(100000);
          g.writeNumber(fuzzString);
        }
      } catch (JacksonException | IllegalArgumentException ignored) {
      }
    }

    try {
      g.close();
    } catch (JacksonException ignored) {
    }
    
  }
}
