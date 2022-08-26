package jdbc;

import org.hsqldb.server.ServerConstants;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.PreparedStatement;

public abstract class Server extends org.hsqldb.server.Server implements AutoCloseable {

	private PrintWriter m_stderr = null;
	private PrintWriter m_stdout = null;

	public Server(boolean verbose, String databaseName) {
		super();
		setVerbose(verbose);

		setDatabaseName(0, databaseName);
        setDatabasePath(0, "mem:" + databaseName);

		start();
	}

	public abstract void prepareTables() throws SQLException;

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
		return DriverManager.getConnection("jdbc:hsqldb:mem:" + getDatabaseName(0, false) + ";" + options, "sa", "");
	}

	Connection getConnection() throws SQLException {
		return getConnection("");
	}
}