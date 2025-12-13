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

import tools.jackson.core.json.*;
import tools.jackson.core.io.ContentReference;
import tools.jackson.core.io.IOContext;
import tools.jackson.core.util.BufferRecycler;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.json.JsonFactory;

import tools.jackson.core.JacksonException;
import java.io.*;
import tools.jackson.core.io.SerializedString;
import tools.jackson.core.SerializableString;

public class WriterBasedJsonGeneratorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    JsonFactory jf = new JsonFactory();
    StringWriter w;
    JsonGenerator jg;

    try {
      w = new StringWriter();
      jg = jf.createGenerator(w);
    } catch (JacksonException e) {
      return;
    }

    try {
      int numberOfOps = data.consumeInt();
      for (int i=0;i<numberOfOps%20;i++) {
        int opType = data.consumeInt();
        switch (opType%5) {
        case 0:
          jg.writeStartObject();
          jg.writeName(data.consumeString(100000));
          jg.writeString(data.consumeString(100000));
          jg.writeEndObject();
        case 1:
          jg.writeStartObject();
          jg.writeStringProperty(data.consumeString(100000), data.consumeString(100000));
          jg.writeEndObject();
        case 2:
          jg.writeStartObject();
          SerializableString NAME = new SerializedString(data.consumeString(100000));
          jg.writeName(NAME);
          jg.writeString(data.consumeString(100000));
          jg.writeEndObject();
        case 3:
          jg.writeStartArray();
          jg.writeRaw(data.consumeString(100000));
          jg.writeEndArray();
        case 4:
          jg.writeStartArray();
          jg.writeRawValue(data.consumeString(100000));
          jg.writeEndArray();
        }
      }      
    } catch (JacksonException e) { }

    try {
      jg.close();
    } catch (JacksonException e) { }
    
  }
}
