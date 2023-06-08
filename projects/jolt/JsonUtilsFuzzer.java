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
////////////////////////////////////////////////////////////////////////////////
import com.bazaarvoice.jolt.JsonUtils;
import com.bazaarvoice.jolt.exception.JsonUnmarshalException;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;

// jvm-autofuzz-heuristics-1
public class JsonUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    // Heuristic name: jvm-autofuzz-heuristics-1
    Integer choice = data.consumeInt(1, 9);

    try {
      switch (choice) {
        case 1:
          JsonUtils.javason(data.consumeRemainingAsString());
          break;
        case 2:
          JsonUtils.jsonToObject(
              data.consumeRemainingAsString(), Charset.defaultCharset().toString());
          break;
        case 3:
          JsonUtils.jsonToObject(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
          break;
        case 4:
          JsonUtils.jsonToMap(data.consumeRemainingAsString());
          break;
        case 5:
          JsonUtils.jsonToMap(data.consumeRemainingAsString(), Charset.defaultCharset().toString());
          break;
        case 6:
          JsonUtils.jsonToMap(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
          break;
        case 7:
          JsonUtils.jsonToList(data.consumeRemainingAsString());
          break;
        case 8:
          JsonUtils.jsonToList(
              data.consumeRemainingAsString(), Charset.defaultCharset().toString());
          break;
        case 9:
          JsonUtils.jsonToList(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
          break;
        default:
          break;
      }
    } catch (JsonUnmarshalException e) {
      // Known exception
    }
  }
}
