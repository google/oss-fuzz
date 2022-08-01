import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;

public class SqlStatementFuzzer extends TestServer {

	SqlStatementFuzzer() {
	}

	void updateRow(FuzzedDataProvider fuzzedDataPovider) throws SQLException {
		try(Connection connection = getConnection()) {
			Statement statement = connection.createStatement();
			statement.execute(fuzzedDataPovider.consumeRemainingAsString());
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataPovider) {
		SqlStatementFuzzer closure = new SqlStatementFuzzer();
		try {
			closure.createTestTable();
			closure.updateRow(fuzzedDataPovider);
		} catch (SQLException ex) {
			/* documented, ignore */
		}
	}
}