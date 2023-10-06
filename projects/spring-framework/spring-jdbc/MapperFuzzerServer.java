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

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class MapperFuzzerServer extends Server {

	public MapperFuzzerServer(boolean verbose) {
		super(verbose, "CoreMapperFuzzer");
	}

	public void prepareTables() throws SQLException {
		/*
		 * HSQLDB in-memory-databases can survive the server instance being destroyed,
		 * especially when another instance is created within the same address space.
		 *
		 * Drop any previous tables to prevent a fuzz iteratation "preparing" the table
		 * for another one, which will fail to reproduce, as only the last fuzzers'
		 * input would be recorded.
		 */
		try (Connection connection = getConnection()) {
			connection.createStatement().execute("DROP TABLE PersistentClass IF EXISTS");
			connection.createStatement().execute("CREATE TABLE PersistentClass ( id INT IDENTITY, intMember INT NOT NULL, stringMember VARCHAR(255) NOT NULL )");
		}
	}
}