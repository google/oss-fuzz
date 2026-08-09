// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in co  mpliance with the License.
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
//////////////////////////////////////////////////////////////////////////////////

package retrofit2;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

import static retrofit2.TestingUtils.buildRequest;

import okhttp3.Request;
import okhttp3.Response;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import retrofit2.http.GET;
import retrofit2.http.Path;


public class PathTraversalFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String str = data.consumeRemainingAsString();

            class Example {
                @GET("/foo/bar/{ping}/")
                Call<ResponseBody> method(@Path("ping") String ping) {
                    return null;
                }
            }

        try {
            Request request = buildRequest(Example.class, str);
            assert request.method().equals("GET") : new FuzzerSecurityIssueLow("Method is not GET");
            assert request.headers().size() == 0 : new FuzzerSecurityIssueLow("Headers are not zero");

            if (!request.url().toString().contains("bar")) {
                throw new FuzzerSecurityIssueLow("Path Traversal!");
            }
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
        }

    }    
}
