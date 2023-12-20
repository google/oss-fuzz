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
import org.apache.commons.lang3.LocaleUtils;

/** This fuzzer targets the methods of the LocaleUtils class in the base package. */
public class LocaleUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer choice = data.consumeInt(1, 5);

      switch (choice) {
        case 1:
          LocaleUtils.countriesByLanguage(data.consumeRemainingAsString());
          break;
        case 2:
          LocaleUtils.isAvailableLocale(LocaleUtils.toLocale(data.consumeRemainingAsString()));
          break;
        case 3:
          LocaleUtils.isLanguageUndetermined(LocaleUtils.toLocale(data.consumeRemainingAsString()));
          break;
        case 4:
          LocaleUtils.languagesByCountry(data.consumeRemainingAsString());
          break;
        case 5:
          LocaleUtils.localeLookupList(LocaleUtils.toLocale(data.consumeRemainingAsString()));
          break;
      }
    } catch (IllegalArgumentException e) {
      // Known exception
    }
  }
}
