import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import java.io.StringReader;

public class GsonParserFuzzer {
    private static final Gson gson = new Gson();
    
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            String jsonInput = data.consumeRemainingAsString();
            testJsonParsing(jsonInput);
            testStreamParsing(jsonInput);
        } catch (Exception e) {}
    }
    
    private static void testJsonParsing(String jsonInput) {
        try {
            JsonElement element = JsonParser.parseString(jsonInput);
            if (element.isJsonObject()) element.getAsJsonObject();
            else if (element.isJsonArray()) element.getAsJsonArray();
        } catch (Exception e) {}
    }
    
    private static void testStreamParsing(String jsonInput) {
        try {
            JsonReader reader = new JsonReader(new StringReader(jsonInput));
            reader.setLenient(true);
            while (reader.hasNext()) {
                switch (reader.peek()) {
                    case BEGIN_ARRAY: reader.beginArray(); break;
                    case END_ARRAY: reader.endArray(); break;
                    case BEGIN_OBJECT: reader.beginObject(); break;
                    case END_OBJECT: reader.endObject(); break;
                    case NAME: reader.nextName(); break;
                    case STRING: reader.nextString(); break;
                    case NUMBER: reader.nextLong(); break;
                    case BOOLEAN: reader.nextBoolean(); break;
                    case NULL: reader.nextNull(); break;
                    default: reader.skipValue();
                }
            }
            reader.close();
        } catch (Exception e) {}
    }
}
