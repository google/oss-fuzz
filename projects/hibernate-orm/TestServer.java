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
	}

	void dropTable(String table) throws SQLException {
		try (Connection connection = getConnection()) {
			connection.createStatement().execute("DROP TABLE " + table + " IF EXISTS");
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
		return "test";
	}
}