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

    void runTest(FuzzedDataProvider data) {
        // Initialize the BidiMap inside the method for each test run
        BidiMap<String, String> m_bidiMap = new TreeBidiMap<>();
	    
        switch(data.consumeInt(1, 5)) {
            case 1:
                String key = data.consumeString(data.consumeInt(5, 15));
                String value = data.consumeString(data.consumeInt(5, 15));
                try {
                    m_bidiMap.put(key, value);
                } catch (IllegalArgumentException ex) {
                    
                }
                break;

            case 2:
                String getKey = data.consumeString(data.consumeInt(5, 15));
                m_bidiMap.get(getKey);
                break;

            case 3:
                String getValue = data.consumeString(data.consumeInt(5, 15));
                m_bidiMap.getKey(getValue);
                break;

            case 4:
                String removeValue = data.consumeString(data.consumeInt(5, 15));
                try {
                    m_bidiMap.removeValue(removeValue);
                } catch (UnsupportedOperationException ex) {
                    
                }
                break;

            case 5:
                m_bidiMap.inverseBidiMap();
                break;
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        CollectionsBidiMapFuzzer testClosure = new CollectionsBidiMapFuzzer();
        testClosure.runTest(data);
    }
}
