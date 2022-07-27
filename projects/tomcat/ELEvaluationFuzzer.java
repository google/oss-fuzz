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

import org.apache.el.*;

import jakarta.el.ELException;
import jakarta.el.ValueExpression;

import org.apache.el.lang.ELSupport;
import org.apache.jasper.el.ELContextImpl;

public class ELEvaluationFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String str = data.consumeRemainingAsString();

        try {
            evaluateExpression(str);
        } catch (ELException | IllegalArgumentException | ArithmeticException e) {
        }
    }

    public static String evaluateExpression(String expression) {
        ExpressionFactoryImpl exprFactory = new ExpressionFactoryImpl();
        ELContextImpl ctx = new ELContextImpl(exprFactory);
        ctx.setFunctionMapper(new TesterFunctions.FMapper());
        ValueExpression ve = exprFactory.createValueExpression(ctx, expression, String.class);
        return (String) ve.getValue(ctx);
    }
}