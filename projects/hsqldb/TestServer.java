import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import org.hsqldb.server.Server;
import org.hsqldb.server.ServerConstants;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.PreparedStatement;

public abstract class TestServer extends Server implements AutoCloseable {

	private PrintWriter m_stderr = null;
	private PrintWriter m_stdout = null;

	TestServer(boolean verbose) {
		super();
		setVerbose(verbose);

		setDatabaseName(0, getTestName());
        setDatabasePath(0, "mem:" + getTestName());

		start();
		try {
			createTestTable();
		} catch(SQLException ex) {
			/* cannot happen? */
		}
	}

	void createTestTable() throws SQLException {
		try (Connection connection = getConnection()) {
			Statement statement = connection.createStatement();
			statement.execute("DROP TABLE TestTable IF EXISTS");
			statement.execute("CREATE TABLE TestTable (key INTEGER, value VARCHAR(256))");
			statement.execute("INSERT INTO TestTable VALUES ((0, \"Hello\"),(1, \"World\"))");
		}
	}

	public void close() throws Exception {
		stop();
	}

	protected void setVerbose(boolean verbose) {
		if (verbose) {
			m_stderr = new PrintWriter(System.err);
			m_stdout = new PrintWriter(System.out);
		} else {
			m_stderr = null;
			m_stdout = null;
		}
		this.setErrWriter(m_stderr);
		this.setLogWriter(m_stdout);
	}

	public int stop() {
		int retval = super.stop();

		/*
		 * polling [...]
		 */
        while (getState() == ServerConstants.SERVER_STATE_CLOSING) {
            Thread.yield();
        }

		return retval;
	}

	Connection getConnection(String options) throws SQLException {
		return DriverManager.getConnection("jdbc:hsqldb:mem:" + getTestName() + ";" + options, "sa", "");
	}

	Connection getConnection() throws SQLException {
		return getConnection("");
	}

	String getTestName() {
		return getClass().getSimpleName();
	}

	abstract void testOneInput(String fuzzyString);
}