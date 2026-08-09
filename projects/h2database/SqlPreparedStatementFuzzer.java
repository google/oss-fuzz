import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import org.h2.tools.Server;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.PreparedStatement;

public class SqlPreparedStatementFuzzer extends TestServer {
	
	SqlPreparedStatementFuzzer(boolean verbose) throws SQLException {
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
			connection.createStatement().executeUpdate("DROP TABLE IF EXISTS t; CREATE TABLE t (x VARCHAR(255));");
			PreparedStatement preparedStatement = connection.prepareStatement("INSERT INTO t(x) VALUES(?)");
			preparedStatement.setString(1, fuzzyString);
			preparedStatement.executeUpdate();
			server.diagnostic("insert performed");
		} catch (SQLException ex) {
			/* ignore */
			server.diagnostic("insert not executed");
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