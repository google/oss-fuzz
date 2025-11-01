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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.sql.SQLException;
import org.mariadb.jdbc.MariaDbPoolDataSource;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-11
// Heuristic name: jvm-autofuzz-heuristics-11
// Target method: [org.mariadb.jdbc.MariaDbPoolDataSource] public  <init>(java.lang.String) throws java.sql.SQLException
// Target method: [org.mariadb.jdbc.MariaDbPoolDataSource] public getConnection(java.lang.String,java.lang.String) throws java.sql.SQLException
// Target method: [org.mariadb.jdbc.MariaDbPoolDataSource] public getXAConnection(java.lang.String,java.lang.String) throws java.sql.SQLException
// Target method: [org.mariadb.jdbc.MariaDbPoolDataSource] public getPooledConnection(java.lang.String,java.lang.String) throws java.sql.SQLException
public class MariaDbPoolDataSourceFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      String p1 = data.consumeString(100);
      String p2 = data.consumeString(100);
      Integer choice = data.consumeInt(1, 3);
      MariaDbPoolDataSource obj = new MariaDbPoolDataSource(data.consumeRemainingAsString());

      switch (choice) {
        case 1:
          obj.getConnection(p1, p2);
          break;
        case 2:
          obj.getXAConnection(p1, p2);
          break;
        case 3:
          obj.getPooledConnection(p1, p2);
          break;
      }
    } catch (SQLException e1) {
      // Known exception
    }
  }
}
