import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import org.h2.tools.Shell;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.PreparedStatement;

public class ShellFuzzer extends TestServer {
	
	ShellFuzzer(boolean verbose) throws SQLException {
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
			Shell shell = new Shell();
			shell.setErr(new PrintStream(new ByteArrayOutputStream()));
			shell.setOut(new PrintStream(new ByteArrayOutputStream()));
			shell.runTool(new String[]{"-url", server.getConnectionURL(), "-password", server.getDatabasePassword(), "-sql", fuzzyString});
		} catch (SQLException ex) {
			/* ignore */
		} catch (Exception ex) {
			server.diagnostic("unexpected exception on the client side...");
		}
		
		if ( ! server.isRunning() ) {
			throw new FuzzerSecurityIssueHigh("Shell caused server crash");
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