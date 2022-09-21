/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.osgi.framework.Filter;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.InvalidSyntaxException;

import java.util.Dictionary;
import java.util.Hashtable;

public class CoreFilterFuzzer {

	Dictionary<String, String> m_dictionary;
	String m_filter;

	CoreFilterFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		m_filter = fuzzedDataProvider.consumeString(10);
		m_dictionary = new Hashtable<String, String>();

		/*
		 * build datasets
		 */
		while(fuzzedDataProvider.remainingBytes() > 0) {
			int blocksize = fuzzedDataProvider.consumeInt(1,10);
			String key = fuzzedDataProvider.consumeString(blocksize);
			m_dictionary.put(key, key);
		}
	}

	void test() {
		Filter filter;
		try {
			filter = FrameworkUtil.createFilter(m_filter);
		} catch(InvalidSyntaxException ex) {
			/* ignore */
			return;
		}

		try {
			filter.match(m_dictionary);
		} catch(IllegalArgumentException ex) {
			/* ignore */
		}

		filter.toString();
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {

		CoreFilterFuzzer testClosure = new CoreFilterFuzzer(fuzzedDataProvider);
		testClosure.test();
	}
}