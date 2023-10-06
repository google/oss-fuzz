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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.EmptyStackException;
import net.objecthunter.exp4j.ExpressionBuilder;
import net.objecthunter.exp4j.function.Function;
import net.objecthunter.exp4j.function.Functions;
import net.objecthunter.exp4j.operator.Operator;
import net.objecthunter.exp4j.operator.Operators;

public class ExpressionBuilderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      int[] choices = data.consumeInts(data.consumeInt(1, 10));

      ExpressionBuilder builder =
          new ExpressionBuilder(data.consumeString(data.remainingBytes() / 2));
      for (Integer choice : choices) {
        String string = data.consumeString(data.remainingBytes() / choices.length);
        switch (choice % 3) {
          case 0:
            Function func = Functions.getBuiltinFunction(string);
            if (func != null) {
              builder = builder.function(func);
            }
            break;
          case 1:
            Operator op = Operators.getBuiltinOperator(string.charAt(choice % string.length()), 1);
            if (op != null) {
              builder = builder.operator(op);
            }
            break;
          case 2:
            builder = builder.variable(string);
            break;
        }
      }
      builder.build();
    } catch (IllegalArgumentException | EmptyStackException | ArithmeticException e) {
      // Known exception
    }
  }
}
