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

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.TreeBidiMap;

public class CollectionsBidiMapFuzzer {

	BidiMap m_bidiMap = null;

	public CollectionsBidiMapFuzzer(FuzzedDataProvider data) {
		m_bidiMap = new TreeBidiMap();
	}
	
	void runTest(FuzzedDataProvider data) {
		switch(data.consumeInt(1, 5)) {
			case 1:
				try {
					m_bidiMap.put(data.consumeString(10), data.consumeString(10));
				} catch(IllegalArgumentException ex) {
					/* documented, ignore */
				}
				break;
			case 2:
				m_bidiMap.get(data.consumeString(10));
				break;
			case 3:
				m_bidiMap.getKey(data.consumeString(10));
				break;
			case 4:
				try {
					m_bidiMap.removeValue(data.consumeString(10));
				} catch(UnsupportedOperationException ex) {
					/* documented, ignore */
				}
				break;
			case 5:
				m_bidiMap.inverseBidiMap();
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		CollectionsBidiMapFuzzer testClosure = new CollectionsBidiMapFuzzer(data);
		testClosure.runTest(data);
	}
}
