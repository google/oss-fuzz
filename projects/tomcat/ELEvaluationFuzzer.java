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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;

import jakarta.el.ExpressionFactory;
import jakarta.el.ELException;
import jakarta.el.ELContext;
import jakarta.el.ValueExpression;
import jakarta.el.MethodExpression;

import org.apache.el.lang.ELSupport;
import org.apache.jasper.el.ELContextImpl;

public class ELEvaluationFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String str = data.consumeRemainingAsString();

        try {
            evaluateExpression(str); // Fuzz the createValueExpression


            ExpressionFactory factory = ExpressionFactory.newInstance();
            ELContext context = new ELContextImpl(factory);

            MethodExpression me1 = factory.createMethodExpression(context, str, String.class, new Class<?>[] {}); // Fuzz the createMethodExpression
            MethodExpression me2 = factory.createMethodExpression(context, str, String.class, new Class<?>[] { String.class });
            MethodExpression me3 = factory.createMethodExpression(context, str, null, new Class<?>[] {});
            MethodExpression me4 = factory.createMethodExpression(context, str, null, new Class[]{String.class});

            Object r1 = me1.invoke(context, null);
            Object r2 = me2.invoke(context, null);
            Object r3 = me3.invoke(context, null);
            Object r4 = me4.invoke(context, null);
        } catch (ELException | IllegalArgumentException | ArithmeticException e) {
        }

    }

    public static String evaluateExpression(String expression) {
        ExpressionFactory exprFactory = ExpressionFactory.newInstance();

        ELContextImpl ctx = new ELContextImpl(exprFactory);
        ValueExpression ve = exprFactory.createValueExpression(ctx, expression, String.class);
        return (String) ve.getValue(ctx);
    }
}