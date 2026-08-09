import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.PreparedStatement;

public class SqlStatementFuzzer extends TestServer {

	SqlStatementFuzzer(boolean verbose) {
		super(verbose);
	}

	void testOneInput(String fuzzyString) {
		try {
			getConnection().createStatement().execute(fuzzyString);
		} catch (SQLException ex) {
			/* ignore */
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
		try (TestServer fuzzer = new SqlStatementFuzzer(false)) {
			fuzzer.testOneInput(fuzzedDataProvider.consumeRemainingAsAsciiString());
		}
	}
}