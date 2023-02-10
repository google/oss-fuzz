import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.PreparedStatement;

public class ConnectionOptionsFuzzer extends TestServer {

	ConnectionOptionsFuzzer(boolean verbose) {
		super(verbose);
	}

	void testOneInput(String fuzzyString) {
		try {
			getConnection(fuzzyString);
		} catch (SQLException ex) {
			/* ignore */
		} catch (IllegalArgumentException ex) {
			/* ??? */
		}
	}
	
	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
		try (TestServer fuzzer = new ConnectionOptionsFuzzer(false)) {
			fuzzer.testOneInput(fuzzedDataProvider.consumeRemainingAsAsciiString());
		}
	}
}