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
import org.checkerframework.checker.formatter.util.FormatUtil;
import org.checkerframework.checker.i18nformatter.qual.I18nConversionCategory;
import org.checkerframework.checker.i18nformatter.util.I18nFormatUtil;
import java.lang.IllegalArgumentException;
import org.checkerframework.checker.regex.util.RegexUtil;

public class UtilCheckerFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      fuzzChecker(data);
    } catch (IllegalArgumentException ignored) {}
  }

  private static void fuzzChecker(FuzzedDataProvider data) {
    int choice = data.consumeInt(0, 2);
    String content;
    switch (choice) {
      case 0:
        content = data.consumeRemainingAsString();
        FormatUtil.formatParameterCategories(content);
        FormatUtil.tryFormatSatisfiability(content);
        break;
      case 1:
        I18nConversionCategory[] categories = {
          I18nConversionCategory.NUMBER,
          I18nConversionCategory.DATE,
          I18nConversionCategory.NUMBER,
          I18nConversionCategory.UNUSED,
          I18nConversionCategory.stringToI18nConversionCategory(data.consumeString(100))
        };
        I18nConversionCategory category = data.pickValue(categories);
        I18nFormatUtil.hasFormat(data.consumeRemainingAsString(), category);
        break;
      case 2:
        content = data.consumeRemainingAsString();
        if (RegexUtil.isRegex(content)) {
          RegexUtil.asRegex(content);
        }
        break;
    }
  }
}
