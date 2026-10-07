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
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.InvalidPathException;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;

import java.io.*;

public class PathParserFuzzer {

	private FuzzedDataProvider fuzzedDataProvider;

	public PathParserFuzzer(FuzzedDataProvider fuzzedDataProvider) {

		this.fuzzedDataProvider = fuzzedDataProvider;

	}

	void test() throws IOException {
		try {
			InputStream in = getClass().getResourceAsStream("/test.json");

			BufferedReader reader = new BufferedReader(new InputStreamReader(in));
			StringBuilder result = new StringBuilder();
			String line;
			while ((line = reader.readLine()) != null) {
				result.append(line);
			}

			Object document = Configuration.defaultConfiguration().jsonProvider().parse(result.toString());
			JsonPath.read(document, fuzzedDataProvider.consumeRemainingAsString());
		} catch (IllegalArgumentException e) {

		} catch (PathNotFoundException e) {

		} catch (InvalidPathException e) {

		}

	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws IOException {

		PathParserFuzzer loggingInterceptorFuzzer = new PathParserFuzzer(fuzzedDataProvider);
		loggingInterceptorFuzzer.test();
	}
}