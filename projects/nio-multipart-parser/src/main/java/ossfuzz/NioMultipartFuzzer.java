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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.synchronoss.cloud.nio.multipart.NioMultipartParser;
import org.synchronoss.cloud.nio.multipart.Multipart;
import org.synchronoss.cloud.nio.multipart.Multipart.Builder;
import org.synchronoss.cloud.nio.multipart.MultipartContext;
import org.synchronoss.cloud.nio.multipart.NioMultipartParserListener;
import org.synchronoss.cloud.nio.stream.storage.StreamStorage;

import java.util.List;
import java.util.Map;

class MultipartListener implements NioMultipartParserListener
{
	public void onPartFinished(final StreamStorage partBodyStreamStorage, final Map<String, List<String>> headersFromPart)
	{}
	public void onAllPartsFinished(){}
	public void onNestedPartStarted(final Map<String, List<String>> headersFromParentPart){}
	public void onNestedPartFinished(){}
	public void onError(final String message, final Throwable cause){}


}

public class NioMultipartFuzzer {

	private FuzzedDataProvider fuzzedDataProvider;

	public NioMultipartFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		this.fuzzedDataProvider = fuzzedDataProvider;

	}

	void test() {
		try {

			var charEncoding = fuzzedDataProvider.consumeAsciiString(fuzzedDataProvider.consumeInt(1, 64));
			var conentLength = fuzzedDataProvider.consumeInt();
			var contentType = fuzzedDataProvider.consumeRemainingAsAsciiString();
			var context = new MultipartContext(contentType, conentLength, charEncoding);
			var listener = new MultipartListener();
			var parser = Multipart.multipart(context).forNIO(listener);
		} catch (IllegalArgumentException e) {

		} catch (IllegalStateException e)
		{

		}

	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {

		NioMultipartFuzzer fixture = new NioMultipartFuzzer(fuzzedDataProvider);
		fixture.test();
	}
}