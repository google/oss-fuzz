import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.springframework.boot.json.BasicJsonParser;
import org.springframework.boot.json.JsonParseException;

public class BasicJsonParserFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String content = data.consumeRemainingAsString();
        BasicJsonParser parser = new BasicJsonParser();
        try { 
            parser.parseList(content);
            parser.parseMap(content);
        } catch (JsonParseException e) { }
    } 
}