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
import org.apache.commons.lang3.math.Fraction;

/** This fuzzer targets the methods of the Fraction class in the math package. */
public class FractionFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer choice = data.consumeInt(1, 10);
      Integer intValue = data.consumeInt();
      Fraction fraction1 = Fraction.getFraction(data.consumeString(data.remainingBytes()));
      Fraction fraction2 = Fraction.getFraction(data.consumeRemainingAsString());

      switch (choice) {
        case 1:
          fraction1.abs();
          fraction2.abs();
          break;
        case 2:
          fraction1.add(fraction2);
          break;
        case 3:
          fraction1.compareTo(fraction2);
          break;
        case 4:
          fraction1.divideBy(fraction2);
          break;
        case 5:
          fraction1.invert();
          fraction2.invert();
          break;
        case 6:
          fraction1.multiplyBy(fraction2);
          break;
        case 7:
          fraction1.pow(intValue);
          fraction2.pow(intValue);
          break;
        case 8:
          fraction1.reduce();
          fraction2.reduce();
          break;
        case 9:
          fraction1.subtract(fraction2);
          break;
        case 10:
          fraction1.toProperString();
          fraction2.toProperString();
          break;
      }
    } catch (NumberFormatException | ArithmeticException e) {
      // Known exception
    }
  }
}
