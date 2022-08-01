import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;

public class ServerLoginFuzzer extends TestServer {

	ServerLoginFuzzer() {
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataPovider) throws Exception {
		ServerLoginFuzzer closure = new ServerLoginFuzzer();
		try {
			closure.getConnection(fuzzedDataPovider.consumeRemainingAsString());
		} catch (SQLException ex) {
			ex.printStackTrace(System.out);
			/* documented, ignore */
		}
	}
}