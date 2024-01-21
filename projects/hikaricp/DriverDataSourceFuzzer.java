// Copyright 2024 Google LLC
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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.zaxxer.hikari.util.DriverDataSource;
import java.util.Properties;

public class DriverDataSourceFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
      try{
        new DriverDataSource(data.consumeString(50), data.consumeString(20), new Properties(), data.consumeString(30), data.consumeString(50));
      }
      catch (java.lang.RuntimeException e) {}
  }
}