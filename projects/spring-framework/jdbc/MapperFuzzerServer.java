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