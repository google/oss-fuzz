import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import org.h2.tools.Server;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;

public class ServerLoginFuzzer extends TestServer {

	ServerLoginFuzzer(String password, boolean verbose) throws SQLException {
		super(password, verbose);
	}

	public String getTestName() {
		return getClass().getSimpleName();
	}

	static void testOneInput(String fuzzyString, boolean verbose) {
		ServerLoginFuzzer server;
		try {
			server = new ServerLoginFuzzer("", verbose);
		} catch (SQLException ex) {
			ex.printStackTrace(System.out);
			return;
		}

		try {
			server.getConnection(fuzzyString);
		} catch (SQLException ex) {
			/* ignore failed login attempts */
			server.diagnostic("failed to get a connection");
		}

		if ( ! server.isRunning() ) {
			throw new FuzzerSecurityIssueHigh("Login attempt caused Server to crash");
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