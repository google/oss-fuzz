// Copyright 2021 Google LLC
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
import tools.jackson.core.JsonParser;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.core.json.JsonReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonFactoryBuilder;

import tools.jackson.core.JacksonException;

public class JsonFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    // Configure JsonFactory with features using builder pattern
    JsonFactoryBuilder builder = JsonFactory.builder();
    
    if (data.consumeBoolean())
      builder.enable(JsonReadFeature.ALLOW_JAVA_COMMENTS);
    if (data.consumeBoolean())
      builder.enable(JsonReadFeature.ALLOW_SINGLE_QUOTES);
    if (data.consumeBoolean())
      builder.enable(JsonReadFeature.ALLOW_UNQUOTED_PROPERTY_NAMES);
    if (data.consumeBoolean())
      builder.enable(JsonReadFeature.ALLOW_YAML_COMMENTS);
    if (data.consumeBoolean())
      builder.enable(JsonReadFeature.ALLOW_TRAILING_COMMA);
    if (data.consumeBoolean())
      builder.enable(JsonReadFeature.ALLOW_NON_NUMERIC_NUMBERS);
    
    JsonFactory factory = builder.build();
    ObjectMapper mapper = new ObjectMapper(factory);
    
    try {
      mapper.readTree(data.consumeRemainingAsBytes());
    } catch (JacksonException ignored) {
    }
  }
}
