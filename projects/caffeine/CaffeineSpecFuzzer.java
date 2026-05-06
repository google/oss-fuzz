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
//
////////////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.github.benmanes.caffeine.cache.CaffeineSpec;
import java.lang.IllegalArgumentException;

public class CaffeineSpecFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      CaffeineSpec spec = CaffeineSpec.parse(data.consumeRemainingAsString());
      if (spec == null) {
        throw new FuzzerSecurityIssueLow("null specification");
      }
    } catch (IllegalArgumentException e) {
      /* documented to be thrown, ignore */
    } catch (Exception e) {
      e.printStackTrace(System.out);
      throw new FuzzerSecurityIssueLow("Undocumented Exception");
    }
  }
}
