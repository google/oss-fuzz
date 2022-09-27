// Copyright 2021 Google LLC
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
import okhttp3.Request;

public class RequestFuzzer {

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {

		try {
			Request request = new Request.Builder()
					.url(fuzzedDataProvider.consumeString(10) + fuzzedDataProvider.consumeString(10))
					.build();
			request.body();
			request.cacheControl();
			request.header(fuzzedDataProvider.consumeString(10));
			request.headers();
			request.headers(fuzzedDataProvider.consumeString(10));
			request.isHttps();
			request.method();
			request.newBuilder();
			request.tag();
			request.url();
		} catch (IllegalArgumentException e) {

		}
	}
}