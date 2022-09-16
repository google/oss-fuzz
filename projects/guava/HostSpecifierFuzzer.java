import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.google.common.net.HostSpecifier;
import java.text.ParseException;

public class HostSpecifierFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		try {
			HostSpecifier hs = HostSpecifier.from(data.consumeRemainingAsString());

			/*
			 * hs.toString() is a valid string, as otherwise the
			 * HostSpecifier.from() invocation to initialize hs
			 * would have thrown an exception.
			 */
			if (! HostSpecifier.isValid(hs.toString())) {
				throw new FuzzerSecurityIssueLow("toString() generated a poor host specifier");
			}
			hs.hashCode();
		} catch (ParseException e) {
			/* documented to be thrown, ignore */
		} catch (Exception e) {
			throw new FuzzerSecurityIssueLow("Undocumented Exception");
		}
	}
}
