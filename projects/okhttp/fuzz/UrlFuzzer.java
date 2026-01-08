import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import okhttp3.HttpUrl;

public class UrlFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String url = data.consumeString(2048);
    try {
      HttpUrl parsed = HttpUrl.parse(url);
      if (parsed != null) {
        parsed.host();
        parsed.encodedPath();
        parsed.querySize();
      }
    } catch (IllegalArgumentException ignored) {
      // Expected for invalid inputs
    }
  }
}
