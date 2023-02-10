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
import java.sql.SQLException;
import java.sql.Statement;

public class TestServer {

	TestServer() {
		
	}

	static boolean m_dummy = initializeMysqlConnectorJ();

	/*
	 * https://dev.mysql.com/doc/connector-j/8.0/en/connector-j-usagenotes-connect-drivermanager.html
	 */
	static boolean initializeMysqlConnectorJ() {
		try {
            // The newInstance() call is a work around for some
            // broken Java implementations

            Class.forName("com.mysql.jdbc.Driver").newInstance();
        } catch (Exception ex) {
            // handle the error
			System.err.println("Can't load mysql-connector-j'");
        }
		return true;
	}

	void createTestTable() throws SQLException {
		try (Connection connection = getConnection()) {
			Statement statement = connection.createStatement();
		
			statement.execute("DROP TABLE IF EXISTS TestTable");
			statement.execute("CREATE TABLE TestTable (k INTEGER, v VARCHAR(256))");
			statement.execute("INSERT INTO TestTable VALUES (0, \"Hello\"),(1, \"World\")");
		}
	}

	String getUserName() {
		return "test";
	}

	String getPassword() {
		return "test";
	}

	Connection getConnection(String connectionOptions) throws SQLException {
		return DriverManager.getConnection("jdbc:mysql://localhost/test?" + connectionOptions, getUserName(), getPassword());
	}

	Connection getConnection() throws SQLException {
		return getConnection("");
	}
}