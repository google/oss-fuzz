// Copyright 2025 Google LLC
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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.google.gson.*;
import java.util.*;

public class GsonSerializationFuzzer {
    private static final Gson gson = new Gson();

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            TestData testData = new TestData();
            testData.name = data.consumeString(50);
            testData.value = data.consumeInt();
            testData.tags = new ArrayList<>();

            int count = data.consumeInt(0, 5);
            for (int i = 0; i < count; i++) {
                testData.tags.add(data.consumeString(20));
            }

            String json = gson.toJson(testData);
            TestData parsed = gson.fromJson(json, TestData.class);

        } catch (Exception e) {}
    }

    static class TestData {
        public String name;
        public int value;
        public List<String> tags;
    }
}
