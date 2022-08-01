import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;

public class SqlPreparedStatementFuzzer extends TestServer {

	SqlPreparedStatementFuzzer() {
	}

	void updateRow(FuzzedDataProvider fuzzedDataPovider) throws SQLException {
		try(Connection connection = getConnection()) {
			PreparedStatement statement = connection.prepareStatement("UPDATE TestTable SET v=? WHERE k=?");
			statement.setInt(2, fuzzedDataPovider.consumeInt());
			statement.setString(1, fuzzedDataPovider.consumeRemainingAsString());
			statement.executeUpdate();
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataPovider) {
		SqlPreparedStatementFuzzer closure = new SqlPreparedStatementFuzzer();
		try {
			closure.createTestTable();
			closure.updateRow(fuzzedDataPovider);
		} catch (SQLException ex) {
			/* documented, ignore */
		}
	}
}