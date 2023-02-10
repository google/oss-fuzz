package jakarta.servlet.jsp;

import org.apache.taglibs.standard.lang.jstl.Evaluator;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;


public class ParserFuzzer {

    private FuzzedDataProvider fuzzedDataProvider;

    public ParserFuzzer(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        this.fuzzedDataProvider = fuzzedDataProvider;
    }

    void test() {
        try {
            String result = Evaluator.parseAndRender(fuzzedDataProvider.consumeRemainingAsString());
        } catch (JspException ex) {
            /* documented, ignore */
        } catch (IllegalArgumentException ex) {
            /* general purpose, ignore */
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider)  throws Exception {

        ParserFuzzer fixture = new ParserFuzzer(fuzzedDataProvider);
        fixture.test();
    }
}