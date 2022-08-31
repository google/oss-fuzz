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