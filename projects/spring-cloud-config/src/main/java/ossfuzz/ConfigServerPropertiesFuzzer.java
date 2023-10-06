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

package ossfuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.springframework.cloud.config.server.config.ConfigServerProperties;
import java.util.HashMap;

public class ConfigServerPropertiesFuzzer {

	private FuzzedDataProvider fuzzedDataProvider;

	public ConfigServerPropertiesFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		this.fuzzedDataProvider = fuzzedDataProvider;

	}

	void test() {
		ConfigServerProperties config = new org.springframework.cloud.config.server.config.ConfigServerProperties();

		config.setPrefix(fuzzedDataProvider.consumeString(16));
		config.setDefaultLabel(fuzzedDataProvider.consumeString(16));
		config.setBootstrap(fuzzedDataProvider.consumeBoolean());

		HashMap<String, String> map = new HashMap<String, String>();
		int n = fuzzedDataProvider.consumeInt(0, 100);
		for (int i = 0; i < n; i++) {
			map.put(fuzzedDataProvider.consumeString(16), fuzzedDataProvider.consumeString(16));
		}

		config.setOverrides(map);
		config.isBootstrap();
		config.getOverrides();
		config.getPrefix();
		config.getDefaultLabel();
		config.toString();
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {

		ConfigServerPropertiesFuzzer loggingInterceptorFuzzer = new ConfigServerPropertiesFuzzer(fuzzedDataProvider);
		loggingInterceptorFuzzer.test();
	}
}