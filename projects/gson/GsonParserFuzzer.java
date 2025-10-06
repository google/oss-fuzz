// Copyright 2025 Google LLC
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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import java.io.StringReader;

public class GsonParserFuzzer {
    private static final Gson gson = new Gson();

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            String jsonInput = data.consumeRemainingAsString();
            testJsonParsing(jsonInput);
            testStreamParsing(jsonInput);
        } catch (Exception e) {}
    }

    private static void testJsonParsing(String jsonInput) {
        try {
            JsonElement element = JsonParser.parseString(jsonInput);
            if (element.isJsonObject()) element.getAsJsonObject();
            else if (element.isJsonArray()) element.getAsJsonArray();
        } catch (Exception e) {}
    }

    private static void testStreamParsing(String jsonInput) {
        try {
            JsonReader reader = new JsonReader(new StringReader(jsonInput));
            reader.setLenient(true);
            while (reader.hasNext()) {
                switch (reader.peek()) {
                    case BEGIN_ARRAY: reader.beginArray(); break;
                    case END_ARRAY: reader.endArray(); break;
                    case BEGIN_OBJECT: reader.beginObject(); break;
                    case END_OBJECT: reader.endObject(); break;
                    case NAME: reader.nextName(); break;
                    case STRING: reader.nextString(); break;
                    case NUMBER: reader.nextLong(); break;
                    case BOOLEAN: reader.nextBoolean(); break;
                    case NULL: reader.nextNull(); break;
                    default: reader.skipValue();
                }
            }
            reader.close();
        } catch (Exception e) {}
    }
}
