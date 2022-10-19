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
import org.springframework.cloud.config.environment.Environment;
import org.springframework.cloud.config.environment.PropertySource;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

public class EnvironmentFuzzer {
	
	private FuzzedDataProvider fuzzedDataProvider;

	public EnvironmentFuzzer( FuzzedDataProvider fuzzedDataProvider) {
		this.fuzzedDataProvider = fuzzedDataProvider;

	}
	
	void test()
	{
		String[] fuzzedArray = {
			fuzzedDataProvider.consumeString(10),
			fuzzedDataProvider.consumeString(10)
		};
		Environment environment = new Environment(
			fuzzedDataProvider.consumeString(10),
			fuzzedArray,
			fuzzedDataProvider.consumeString(10),
			fuzzedDataProvider.consumeString(10),
			fuzzedDataProvider.consumeString(10)
		);
		HashMap<Integer, Integer> map = new HashMap<Integer, Integer>();
		int n = fuzzedDataProvider.consumeInt(0, 10);
		for(int i = 0; i < n; i++)
		{
			map.put(fuzzedDataProvider.consumeInt(), fuzzedDataProvider.consumeInt());
		}
		PropertySource propertySource = new PropertySource(fuzzedDataProvider.consumeString(10), map);
		List<PropertySource> lPropertySources = new ArrayList<PropertySource>();
		lPropertySources.add(propertySource);

		environment.add(propertySource);
		environment.addFirst(propertySource);
		environment.addAll(lPropertySources);

		environment.getName();
		environment.getLabel();
		environment.getProfiles();
		environment.getPropertySources();
		environment.getState();
		environment.getVersion();
		environment.setLabel(fuzzedDataProvider.consumeString(10));
		environment.setName(fuzzedDataProvider.consumeString(10));
		environment.setState(fuzzedDataProvider.consumeString(10));
		environment.setVersion(fuzzedDataProvider.consumeString(10));
		environment.setProfiles(new String[]{fuzzedDataProvider.consumeString(10), fuzzedDataProvider.consumeString(10)});
		environment.toString();
		
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {

		EnvironmentFuzzer loggingInterceptorFuzzer = new EnvironmentFuzzer(fuzzedDataProvider);
		loggingInterceptorFuzzer.test();
	}
}