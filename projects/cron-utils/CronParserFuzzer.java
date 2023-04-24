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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import com.cronutils.parser.CronParser;
import com.cronutils.model.definition.CronDefinition;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.model.CronType;

public class CronParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    CronType[] cronTypes = { CronType.CRON4J, CronType.QUARTZ, CronType.UNIX, CronType.SPRING, CronType.SPRING53 };
    CronType cronType = data.pickValue(cronTypes);

    CronDefinition cronDef = CronDefinitionBuilder.instanceDefinitionFor(cronType);
    CronParser parser = new CronParser(cronDef);
    try{
      parser.parse(data.consumeRemainingAsString());
    }
    catch(IllegalArgumentException | ArrayIndexOutOfBoundsException e){
      return;
    }
  }
}
