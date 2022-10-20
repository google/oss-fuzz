import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.google.common.net.HostAndPort;
import java.lang.IllegalArgumentException;

public class HostAndPortFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		try {
			HostAndPort hap = HostAndPort.fromString(data.consumeRemainingAsString());
		} catch (IllegalArgumentException e) {
			/* documented to be thrown, ignore */
		} catch (Exception e) {
			e.printStackTrace(System.out);
			throw new FuzzerSecurityIssueLow("Undocumented Exception");
		}
	}
}
