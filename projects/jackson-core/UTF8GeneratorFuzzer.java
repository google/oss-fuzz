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
import java.io.StringReader;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.fasterxml.jackson.core.Base64Variant;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.json.UTF8JsonGenerator;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.SerializableString;
import com.fasterxml.jackson.core.io.SerializedString;

import java.io.IOException;

public class UTF8GeneratorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    JsonFactory jf = new JsonFactory();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    String fuzzString;
    JsonGenerator g;

    try {
      g = jf.createGenerator(out);
    } catch (IOException ignored) {
      return;
    }

    try {      
      int apiType = data.consumeInt();
      switch(apiType%7) {
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
        g.writeStartArray();
        g.writeRaw(fuzzString, 0, fuzzString.length());
        g.writeEndArray();
      case 5:
        String key = data.consumeString(50000);
        String value = data.consumeString(50000);
        g.writeStartObject();
        g.writeStringField(key, value);
        g.writeEndObject();
      case 6:
        Base64Variant b64v = Base64Variants.getDefaultVariant();
        byte[] b = data.consumeRemainingAsBytes();
        g.writeStartArray();
        g.writeBinary(b64v, b, 0, b.length);
        g.writeEndArray();
      }
    } catch (IOException | IllegalArgumentException ignored) {
    }

    try {
      g.close();
    } catch (IOException ignored) {
      return;
    }
    
  }
}
