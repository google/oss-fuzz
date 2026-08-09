import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.glassfish.jersey.message.internal.HttpHeaderReader;
import org.glassfish.jersey.message.internal.MatchingEntityTag;
import java.text.ParseException;

public class HttpHeaderReaderFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		String value = data.consumeRemainingAsString();
		try {
			HttpHeaderReader.readMatchingEntityTag(value);
			HttpHeaderReader.readQualityFactor(value);
			HttpHeaderReader.readDate(value);
			HttpHeaderReader.readAcceptToken(value);
			HttpHeaderReader.readAcceptLanguage(value);
			HttpHeaderReader.readStringList(value);
			HttpHeaderReader.readCookie(value);
			HttpHeaderReader.readCookies(value);
			HttpHeaderReader.readNewCookie(value);

		} catch (ParseException e) { }
	} 
}