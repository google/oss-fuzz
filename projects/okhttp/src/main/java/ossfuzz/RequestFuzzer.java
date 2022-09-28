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
import okhttp3.RequestBody;
import okhttp3.MediaType;

public class RequestFuzzer {

	Request.Builder addHeaders(Request.Builder builder, FuzzedDataProvider fuzzedDataProvider) {
		int n = fuzzedDataProvider.consumeInt(0, 10);
		for (int i = 0; i < n; i++) {
			builder.addHeader(fuzzedDataProvider.consumeString(10), fuzzedDataProvider.consumeString(10));
		}
		return builder;
	}

	Request.Builder removeHeaders(Request.Builder builder, FuzzedDataProvider fuzzedDataProvider) {
		int n = fuzzedDataProvider.consumeInt(0, 10);
		for (int i = 0; i < n; i++) {
			builder.removeHeader(fuzzedDataProvider.consumeString(10));
		}
		return builder;
	}

	Request.Builder addRequestBody(Request.Builder builder, FuzzedDataProvider fuzzedDataProvider) {

		RequestBody reqBody;

		try {
			reqBody = RequestBody.create(MediaType.get(fuzzedDataProvider.consumeString(10)),
					fuzzedDataProvider.consumeString(10));
		} catch (IllegalArgumentException e) {
			return builder;
		}

		try {
			builder.method(fuzzedDataProvider.consumeString(10), reqBody);
		} catch (IllegalArgumentException e) {
		}

		try {
			builder.patch(reqBody);
		} catch (IllegalArgumentException e) {
		}
		try {
			builder.post(reqBody);
		} catch (IllegalArgumentException e) {
		}
		try {

			builder.put(reqBody);
		} catch (IllegalArgumentException e) {

		}

		return builder;
	}

	Request.Builder getBuilder(FuzzedDataProvider fuzzedDataProvider) {
		Request.Builder builder = new Request.Builder();

		try {
			builder.url(fuzzedDataProvider.consumeString(20));
		} catch (IllegalArgumentException e) {
		}
		try {
			builder.get();
		} catch (IllegalArgumentException e) {
		}

		try {
			builder.head();
		} catch (IllegalArgumentException e) {
		}

		try {
			builder.header(fuzzedDataProvider.consumeString(10), fuzzedDataProvider.consumeString(10));
		} catch (IllegalArgumentException e) {
		}

		try {
			builder.tag(fuzzedDataProvider.consumeBoolean());
		} catch (IllegalArgumentException e) {
		}

		addHeaders(builder, fuzzedDataProvider);
		addRequestBody(builder, fuzzedDataProvider);
		removeHeaders(builder, fuzzedDataProvider);

		return builder;
	}

	void test(FuzzedDataProvider fuzzedDataProvider) {
		Request request;

		try {
			request = getBuilder(fuzzedDataProvider).build();
		} catch (IllegalArgumentException | IllegalStateException e) {
			return;
		}

		try {
			request.body();
		} catch (IllegalArgumentException e) {
		}

		try {
			request.cacheControl();
		} catch (IllegalArgumentException e) {
		}

		try {
			request.header(fuzzedDataProvider.consumeString(10));
		} catch (IllegalArgumentException e) {
		}

		try {
			request.headers();
		} catch (IllegalArgumentException e) {
		}

		try {
			request.headers(fuzzedDataProvider.consumeString(10));
		} catch (IllegalArgumentException e) {
		}

		try {
			request.isHttps();
		} catch (IllegalArgumentException e) {
		}

		try {
			request.method();
		} catch (IllegalArgumentException e) {
		}

		try {
			request.tag();
		} catch (IllegalArgumentException e) {
		}

		try {
			request.url();
		} catch (IllegalArgumentException e) {
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {

		RequestFuzzer closure = new RequestFuzzer();
		closure.test(fuzzedDataProvider);

	}
}