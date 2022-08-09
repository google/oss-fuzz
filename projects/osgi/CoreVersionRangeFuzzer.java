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

import org.osgi.framework.Version;
import org.osgi.framework.VersionRange;

public class CoreVersionRangeFuzzer {

    int    m_major, m_minor, m_micro;
	String m_range1, m_range2;
	String m_filter;

	CoreVersionRangeFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		m_major = fuzzedDataProvider.consumeInt(0, Integer.MAX_VALUE);
		m_minor = fuzzedDataProvider.consumeInt(0, Integer.MAX_VALUE);
		m_micro = fuzzedDataProvider.consumeInt(0, Integer.MAX_VALUE);
		
		m_filter = fuzzedDataProvider.consumeString(5);
		m_range1 = fuzzedDataProvider.consumeString(fuzzedDataProvider.remainingBytes() / 2);
		m_range2 = fuzzedDataProvider.consumeRemainingAsString();
	}

	void test() {
		VersionRange r1 = null, r2 = null;
		Version v;
		try {
			v  = new Version(m_major, m_minor, m_micro);
			r1 = VersionRange.valueOf(m_range1);
			r2 = VersionRange.valueOf(m_range2);
		} catch(IllegalArgumentException ex) {
			/* documented, ignore */
			return;
		}

		try {
			r1.toFilterString(m_filter);
		} catch(IllegalArgumentException ex) {
			/* documented, ignore */
		}
		
		/*
		 * these don't throw exceptions
		 */
		r1.getLeft();
		r1.getRight();
		r1.includes(v);
		r1.intersection(r2);
		r1.isEmpty();
		r1.isExact();
		r1.toString();
		r1.hashCode();
		r1.equals(r2);
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
		CoreVersionRangeFuzzer testClosure = new CoreVersionRangeFuzzer(fuzzedDataProvider);
		testClosure.test();
	}
}