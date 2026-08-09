import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import org.h2.tools.Server;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;

public class TestServer {

	private static String g_shutdownPassword = "ServerShutdownPassword"; // needs to be non-empty string
	private Server m_server = null;
	private boolean m_verbose;
	private String m_password;

	String getDatabasePassword() {
		return m_password;
	}

	void diagnostic(String message) {
		if (m_verbose) {
			System.out.println(message);
		}
	}

	void diagnostic(Exception ex) {
		if (m_verbose) {
			ex.printStackTrace(System.out);
		}
	}

	TestServer(String password, boolean verbose) throws SQLException {
		m_verbose = verbose;
		m_password = password;

		String args[] = new String[]{ "-tcpPassword", g_shutdownPassword, "-ifNotExists", "-tcpDaemon" };
		m_server = Server.createTcpServer(args).start();
		diagnostic("Server started");

		try {
			// passwords default to empty string/null
			setPassword("", password);
		} catch (SQLException ex) {
			setPassword(password, password);
		}
	}

	String getConnectionURL() {
		return "jdbc:h2:" + m_server.getURL() + "/~/" + getTestName() + ";";
	}

	Connection getConnection() throws SQLException {
		return getConnection("PASSWORD=" + getDatabasePassword() + ";");
	}

	Connection getConnection(String options) throws SQLException {
		Connection connection = DriverManager.getConnection(getConnectionURL() + options, null, null);
		
		DatabaseMetaData metaData = connection.getMetaData();
		diagnostic("Connected to " + metaData.getDatabaseProductName() + "-" + metaData.getDatabaseProductVersion() + " via " + metaData.getURL());

		return connection;
	}

	void setPassword(String oldPassword, String newPassword) throws SQLException {
		Connection connection = getConnection("PASSWORD=" + oldPassword);
		PreparedStatement statement = connection.prepareStatement("SET PASSWORD ?");
		statement.setString(1, newPassword);
		statement.executeUpdate();
		diagnostic("Password reset.");
	}

	boolean isRunning() {
		return m_server.isRunning(true);
	}

	void stop() throws SQLException {
		m_server.shutdownTcpServer(m_server.getURL(), g_shutdownPassword, true, true);
		m_server.stop();
		diagnostic("Server stopped");
	}

	public String getTestName() {
		return getClass().getSimpleName();
	}
}
