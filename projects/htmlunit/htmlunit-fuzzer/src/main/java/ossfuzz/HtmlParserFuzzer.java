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
import org.htmlunit.html.HtmlPage;
import org.htmlunit.BrowserVersion;
import org.htmlunit.StringWebResponse; 
import org.htmlunit.WebClient;
import org.htmlunit.WebResponse;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

public class HtmlParserFuzzer {

	private FuzzedDataProvider fuzzedDataProvider;

	public HtmlParserFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		this.fuzzedDataProvider = fuzzedDataProvider;
	}

	BrowserVersion getBrowserVersion() {
		/*
		 * from src/test/java/org/htmlunit/WebTestCase.java
		 */
		return new BrowserVersion.BrowserVersionBuilder(BrowserVersion.BEST_SUPPORTED)
					.setApplicationName("FLAG_ALL_BROWSERS")
					.build();
	}

	void test() {
		try (WebClient webClient = new WebClient(getBrowserVersion())) {
			/*
			 * net.sourceforge.htmlunit.corejs.javascript.EvaluatorException
			 * seems to be fatal
			 */
			webClient.getOptions().setThrowExceptionOnScriptError(false);

			webClient.loadHtmlCodeIntoCurrentWindow(fuzzedDataProvider.consumeRemainingAsString());
		} catch (IllegalArgumentException e) {
		} catch (IOException e) {
		}

	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
		HtmlParserFuzzer testFixture = new HtmlParserFuzzer(fuzzedDataProvider);
		testFixture.test();
	}
}