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

package ossfuzz;

import java.io.IOException;

import javax.xml.catalog.Catalog;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;
import okhttp3.logging.HttpLoggingInterceptor.Level;

public class LoggingInterceptorFuzzer {

	private FuzzedDataProvider fuzzedDataProvider;

	public LoggingInterceptorFuzzer( FuzzedDataProvider fuzzedDataProvider) {
		this.fuzzedDataProvider = fuzzedDataProvider;

	}
	Level getLevel()
	{
		Level levels[] = Level.values();
		return levels[fuzzedDataProvider.consumeInt(0, levels.length - 1)];
	}

	void test()
	{
		try (MockWebServer server = new MockWebServer()) {
			RequestFuzzer requestFuzzer = new RequestFuzzer(server.url("/index.html").toString(), fuzzedDataProvider);
			Request request = requestFuzzer.getRequest();

			if (request == null) {
				return;
			}

			server.enqueue(new MockResponse().setBody(fuzzedDataProvider.consumeString(50)));
			HttpLoggingInterceptor logger = new HttpLoggingInterceptor(new NullLogger());
			logger.setLevel(getLevel());
			
			OkHttpClient client = new OkHttpClient.Builder().addInterceptor(logger).build();

			try (Response response = client.newCall(request).execute()) {
			} catch (IOException e) {
			} catch (IllegalArgumentException e) {
			}

		} catch (IOException e) {
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {

		LoggingInterceptorFuzzer loggingInterceptorFuzzer = new LoggingInterceptorFuzzer(fuzzedDataProvider);
		loggingInterceptorFuzzer.test();
	}
}