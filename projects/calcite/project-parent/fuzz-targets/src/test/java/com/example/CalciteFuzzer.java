// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import org.apache.calcite.adapter.jdbc.JdbcSchema;
import org.apache.calcite.jdbc.CalciteConnection;
import org.apache.calcite.plan.Contexts;
import org.apache.calcite.rel.RelNode;
import org.apache.calcite.runtime.CalciteException;
import org.apache.calcite.schema.SchemaPlus;
import org.apache.calcite.sql.SqlNode;
import org.apache.calcite.sql.SqlWriter;
import org.apache.calcite.sql.parser.SqlParseException;
import org.apache.calcite.sql.parser.SqlParser;
import org.apache.calcite.sql.pretty.SqlPrettyWriter;
import org.apache.calcite.tools.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import java.sql.*;
import javax.sql.DataSource;
import java.util.concurrent.atomic.AtomicInteger;


class CalciteFuzzer {
    static String jdbcUrl;
    static Connection connection;
    static CalciteConnection calciteConnection;
    static DataSource mockDataSource;
    static SqlParser.Config parserConfig;
    static SchemaPlus rootSchema;

    @BeforeAll
    static void setUp() throws SQLException, ClassNotFoundException {
        Class.forName("org.hsqldb.jdbcDriver");

        jdbcUrl = MockDb.INSTANCE.getUrl();
        connection = DriverManager.getConnection(jdbcUrl, "", "");

        try (Statement s = connection.createStatement()) {
            s.execute("create table testtable(" +
                    "key integer," +
                    "value varchar(25))");

            s.execute("insert into testtable values(1, 'test1')");
            s.execute("insert into testtable values(2, 'test2')");
        }

        mockDataSource = JdbcSchema.dataSource(jdbcUrl, "org.hsqldb.jdbcDriver", "", "");
    }

    @AfterAll
    static void cleanUp() {
        try {
            connection.close();
            calciteConnection.close();
        } catch (SQLException e) {
        }
    }

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        try {
            connection = DriverManager.getConnection("jdbc:calcite:");
            calciteConnection = connection.unwrap(CalciteConnection.class);
        } catch (SQLException e) {
            return;
        }

        try {
            int key = data.consumeInt();
            PreparedStatement preparedStatement = calciteConnection.prepareStatement("UPDATE testtable SET value=? WHERE key=" + key);
            preparedStatement.setString(key, data.consumeString(5000));
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
        }

        parserConfig = SqlParser.config();
        rootSchema = calciteConnection.getRootSchema();
        rootSchema.add("exampleSchema", JdbcSchema.create(rootSchema, "exampleSchema", mockDataSource, null, null));

        try {
            Frameworks.ConfigBuilder configBuilder = Frameworks.newConfigBuilder()
                    .defaultSchema(rootSchema)
                    .parserConfig(parserConfig)
                    .context(Contexts.of(calciteConnection.config()));

            Planner planner = Frameworks.getPlanner(configBuilder.build());
            SqlNode node = planner.parse(data.consumeString(5000));
            SqlNode validateNode = planner.validate(node);
            SqlWriter writer = new SqlPrettyWriter();
            validateNode.unparse(writer, 0,0);
        } catch (SqlParseException | ValidationException e) {
        } catch (AssertionError e) {
            // Need to catch in order to find more interesting findings.
        }

        try {
            FrameworkConfig config = Frameworks.newConfigBuilder()
                    .defaultSchema(rootSchema)
                    .build();

            RelBuilder r = RelBuilder.create(config);
            RelNode node = r
                    .scan("exampleSchema", "TESTTABLE")
                    .filter(r.equals(r.field(data.consumeString(1000)), r.literal(data.consumeInt())))
                    .project(r.field(data.consumeString(1000)), r.field(data.consumeRemainingAsString()))
                    .build();

            RelRunner runner = connection.unwrap(RelRunner.class);
            PreparedStatement ps = runner.prepareStatement(node);
            ps.execute();
            ps.getResultSet();
        } catch (SQLException e) {
        } catch (CalciteException | IllegalArgumentException e) {
            // Need to catch in order to find more interesting findings.
        }
    }

    static class MockDb {
        MockDb() {}
        static final MockDb INSTANCE = new MockDb();
        private final AtomicInteger id = new AtomicInteger(1);

        public String getUrl() {
            return "jdbc:hsqldb:mem:db" + id.getAndIncrement();
        }
    }
}