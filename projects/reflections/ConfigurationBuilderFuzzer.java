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
import org.reflections.util.ConfigurationBuilder;
import org.reflections.scanners.Scanners;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.FilterBuilder;

public class ConfigurationBuilderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try{
        ConfigurationBuilder config = ConfigurationBuilder.build(data.consumeString(20));
        ClasspathHelper.forPackage(data.consumeString(20));
        new FilterBuilder().includePackage(data.consumeRemainingAsString());
        config.getUrls();
        config.getInputsFilter();
        config.getScanners();
    }
    catch (org.reflections.ReflectionsException e) {}
  }
}
