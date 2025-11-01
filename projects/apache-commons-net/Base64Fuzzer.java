// Copyright 2024 Google LLC
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
import org.apache.commons.net.util.Base64;

public class Base64Fuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try{
            Base64 b64 = new Base64(data.consumeInt(), data.consumeBytes(1000), data.consumeBoolean());
            b64.encode(data.consumeBytes(4000));
            b64.decode(data.consumeBytes(4000));
        }
        catch (java.lang.IllegalArgumentException e) {}
    } 
}