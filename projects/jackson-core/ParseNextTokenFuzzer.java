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
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.Base64Variant;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonFactory;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class ParseNextTokenFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    JsonFactory jf = new JsonFactory();
    JsonParser jp;
        
    try {
        jp = jf.createParser(data.consumeRemainingAsBytes());
      if (data.consumeBoolean()) {
      } else {
        InputStream myInputStream = new ByteArrayInputStream(data.consumeRemainingAsBytes());
        jp = jf.createParser(myInputStream);
      }
      jp.nextFieldName();

      ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      Base64Variant orig = Base64Variants.PEM;
      while (jp.nextToken() != null) {
            ;
        }
      jp.readBinaryValue(orig, bytes);
    } catch (IOException | IllegalArgumentException ignored) {
    }
  }
}
