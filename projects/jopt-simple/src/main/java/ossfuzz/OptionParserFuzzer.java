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
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionException;
import java.util.Date;
import java.util.ArrayList;

public class OptionParserFuzzer {

	private FuzzedDataProvider fuzzedDataProvider;

	public OptionParserFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		this.fuzzedDataProvider = fuzzedDataProvider;

	}

	void test() {
		try {
			OptionParser parser = new OptionParser();
			var list = new ArrayList();
			for (int i = 0; i < fuzzedDataProvider.consumeInt(0, 10); i ++)
			{
				list.add(fuzzedDataProvider.consumeString(100));
			}

			parser.accepts(fuzzedDataProvider.consumeString(100)).withOptionalArg().ofType(Integer.class);
			parser.accepts(fuzzedDataProvider.consumeString(100)).withOptionalArg().ofType(Boolean.class);
			parser.accepts(fuzzedDataProvider.consumeString(100)).withOptionalArg().ofType(String.class);
			parser.accepts(fuzzedDataProvider.consumeString(100)).withOptionalArg().ofType(Float.class);
			parser.accepts(fuzzedDataProvider.consumeString(100)).withOptionalArg().ofType(Date.class);
			parser.accepts(fuzzedDataProvider.consumeString(100));
			parser.acceptsAll(list);
			parser.parse(fuzzedDataProvider.consumeRemainingAsString());
		} catch (IllegalArgumentException e) {

		} catch (OptionException e) {

		}

	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {

		OptionParserFuzzer fixture = new OptionParserFuzzer(fuzzedDataProvider);
		fixture.test();
	}
}