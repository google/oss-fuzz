// Copyright 2022 Google LLC
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

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.error.YAMLException;

public class SecureYamlFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      LoaderOptions options = new LoaderOptions();
      options.setAllowDuplicateKeys(false);
      options.setMaxAliasesForCollections(5);
      options.setAllowRecursiveKeys(false);
      options.setNestingDepthLimit(3);
      // since the input is often in UTF-8 for OSS Fuzz, code points are bytes
      options.setCodePointLimit(5*1024);
      Yaml yaml = new Yaml(new SafeConstructor(options));
      yaml.load(data.consumeRemainingAsString());
    } catch (YAMLException | IllegalArgumentException e) {
      return;
    }
  }
}
