import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import org.h2.tools.Server;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.PreparedStatement;

public class SqlStatementFuzzer extends TestServer {
	
	SqlStatementFuzzer(boolean verbose) throws SQLException {
		super("myH2DBPassword", verbose);
	}

	public String getTestName() {
		return getClass().getSimpleName();
	}

	static void testOneInput(String fuzzyString, boolean verbose) {
		SqlStatementFuzzer server;
		try {
			server = new SqlStatementFuzzer(verbose);
		} catch (SQLException ex) {
			ex.printStackTrace(System.out);
			return;
		}

		try {
			Connection connection = server.getConnection();
			connection.createStatement().executeUpdate(fuzzyString);
			server.diagnostic("statement executed");
		} catch (SQLException ex) {
			/* ignore */
			server.diagnostic("statement not executed");
			server.diagnostic(ex);
		}
		
		if ( ! server.isRunning() ) {
			throw new FuzzerSecurityIssueHigh("SQL Statement caused server crash");
		}
		
		try {
			server.stop();
		} catch (SQLException ex) {
			throw new FuzzerSecurityIssueHigh("Why can't we shutdown the server?");
		}
	}
	
	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
		testOneInput(fuzzedDataProvider.consumeRemainingAsAsciiString(), false);
	}
}