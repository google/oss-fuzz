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
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;

/** This fuzzer targets the methods of the StringUtils class in the base package. */
public class StringUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer choice = data.consumeInt(1, 61);
      String string1 = data.consumeString(data.remainingBytes());
      String string2 = data.consumeRemainingAsString();

      switch (choice) {
        case 1:
          StringUtils.abbreviate(string1, string1.length());
          break;
        case 2:
          StringUtils.abbreviateMiddle(string1, string2, string1.length());
          break;
        case 3:
          StringUtils.appendIfMissing(string1, string2);
          break;
        case 4:
          StringUtils.appendIfMissingIgnoreCase(string1, string2);
          break;
        case 5:
          StringUtils.capitalize(string1);
          break;
        case 6:
          StringUtils.center(string1, string1.length());
          break;
        case 7:
          StringUtils.chomp(string1);
          break;
        case 8:
          StringUtils.chop(string1);
          break;
        case 9:
          StringUtils.compare(string1, string2);
          break;
        case 10:
          StringUtils.compareIgnoreCase(string1, string2);
          break;
        case 11:
          StringUtils.contains(string1, string2);
          break;
        case 12:
          StringUtils.containsAny(string1, string2);
          break;
        case 13:
          StringUtils.containsAnyIgnoreCase(string1, string2);
          break;
        case 14:
          StringUtils.containsNone(string1, string2);
          break;
        case 15:
          StringUtils.containsOnly(string1, string2);
          break;
        case 16:
          StringUtils.containsWhitespace(string1);
          break;
        case 17:
          StringUtils.countMatches(string1, string2);
          break;
        case 18:
          StringUtils.deleteWhitespace(string1);
          break;
        case 19:
          StringUtils.difference(string1, string2);
          break;
        case 20:
          StringUtils.endsWith(string1, string2);
          break;
        case 21:
          StringUtils.endsWithAny(string1, string2);
          break;
        case 22:
          StringUtils.endsWithIgnoreCase(string1, string2);
          break;
        case 23:
          StringUtils.equals(string1, string2);
          break;
        case 24:
          StringUtils.equalsAny(string1, string2);
          break;
        case 25:
          StringUtils.equalsAnyIgnoreCase(string1, string2);
          break;
        case 26:
          StringUtils.equalsIgnoreCase(string1, string2);
          break;
        case 27:
          StringUtils.getCommonPrefix(string1, string2);
          break;
        case 28:
          StringUtils.getDigits(string1);
          break;
        case 29:
          StringUtils.indexOf(string1, string2);
          break;
        case 30:
          StringUtils.indexOfAny(string1, string2);
          break;
        case 31:
          StringUtils.indexOfAnyBut(string1, string2);
          break;
        case 32:
          StringUtils.indexOfDifference(string1, string2);
          break;
        case 33:
          StringUtils.indexOfIgnoreCase(string1, string2);
          break;
        case 34:
          StringUtils.isAllBlank(string1, string2);
          break;
        case 35:
          StringUtils.isAllEmpty(string1, string2);
          break;
        case 36:
          StringUtils.isAllLowerCase(string1);
          break;
        case 37:
          StringUtils.isAllUpperCase(string1);
          break;
        case 38:
          StringUtils.isMixedCase(string1);
          break;
        case 39:
          if (string2.length() > 0) {
            StringUtils.join(string1.toCharArray(), string2.toCharArray()[0], 0, string1.length());
          }
          break;
        case 40:
          if (string2.length() > 0) {
            StringUtils.joinWith(string1, string2.toCharArray());
          }
          break;
        case 41:
          StringUtils.lastIndexOf(string1, string2);
          break;
        case 42:
          StringUtils.lastIndexOfAny(string1, string2);
          break;
        case 43:
          StringUtils.lastIndexOfIgnoreCase(string1, string2);
          break;
        case 44:
          StringUtils.left(string1, string1.length());
          break;
        case 45:
          StringUtils.leftPad(string1, string1.length() + 10);
          break;
        case 46:
          StringUtils.mid(string1, 0, string1.length());
          break;
        case 47:
          StringUtils.normalizeSpace(string1);
          break;
        case 48:
          StringUtils.overlay(string1, string2, 0, string1.length());
          break;
        case 49:
          StringUtils.right(string1, string1.length());
          break;
        case 50:
          StringUtils.rightPad(string1, string1.length() + 10);
          break;
        case 51:
          StringUtils.rotate(string1, string1.length());
          break;
        case 52:
          StringUtils.split(string1);
          break;
        case 53:
          StringUtils.splitByCharacterType(string1);
          break;
        case 54:
          StringUtils.splitByCharacterTypeCamelCase(string1);
          break;
        case 55:
          StringUtils.splitByWholeSeparator(string1, string2);
          break;
        case 56:
          StringUtils.splitPreserveAllTokens(string1);
          break;
        case 57:
          StringUtils.swapCase(string1);
          break;
        case 58:
          StringUtils.truncate(string1, string1.length());
          break;
        case 59:
          StringUtils.uncapitalize(string1);
          break;
        case 60:
          StringUtils.wrap(string1, string2);
          break;
        case 61:
          // TODO verify if regex injection is real
          // Validate.matchesPattern(string1, string2);
          break;
      }
    } catch (IllegalArgumentException e) {
      // Known exception
    }
  }
}
