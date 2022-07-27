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