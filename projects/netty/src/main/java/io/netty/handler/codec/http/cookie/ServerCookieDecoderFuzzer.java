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

package io.netty.handler.codec.http.cookie;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class ServerCookieDecoderFuzzer {

	private FuzzedDataProvider fuzzedDataProvider;

	public ServerCookieDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		this.fuzzedDataProvider = fuzzedDataProvider;

	}

	void test() {
		String s = fuzzedDataProvider.consumeRemainingAsString();
		try {
			ServerCookieDecoder.STRICT.decodeAll(s);
			ServerCookieDecoder.LAX.decodeAll(s);
		} catch (IllegalArgumentException e) {

		}

	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {

		ServerCookieDecoderFuzzer fixture = new ServerCookieDecoderFuzzer(fuzzedDataProvider);
		fixture.test();
	}
}