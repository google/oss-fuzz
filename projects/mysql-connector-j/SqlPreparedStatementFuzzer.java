/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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