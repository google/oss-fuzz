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
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.EnumSet;
import org.apache.commons.codec.language.bm.NameType;
import org.apache.commons.codec.language.bm.PhoneticEngine;
import org.apache.commons.codec.language.bm.RuleType;

/** This fuzzer targets the encode method in the PhoneticEngine class of the bm package. */
public class PhoneticEngineFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      PhoneticEngine engine =
          new PhoneticEngine(
              data.pickValue(EnumSet.allOf(NameType.class)),
              data.pickValue(EnumSet.allOf(RuleType.class)),
              data.consumeBoolean(),
              data.consumeInt());
      engine.encode(data.consumeRemainingAsString());
    } catch (IllegalArgumentException e) {
      // Known exception
    }
  }
}
