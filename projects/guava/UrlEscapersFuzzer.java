// Copyright 2023 Google LLC
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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.google.common.base.Charsets;
import com.google.common.escape.Escaper;
import com.google.common.net.PercentEscaper;
import com.google.common.net.UrlEscapers;
import java.lang.IllegalArgumentException;
import java.net.URLDecoder;

public class UrlEscapersFuzzer {

	/*
	 * These constants are private members copy-pasted from
	 * com.google.common.net.UrlEscapers.
	 */
	static final String URL_FORM_PARAMETER_OTHER_SAFE_CHARS = "-_.*";
	static final String URL_PATH_OTHER_SAFE_CHARS_LACKING_PLUS =
	  "-._~" // Unreserved characters.
	+ "!$'()*,;&=" // The subdelim characters (excluding '+').
	+ "@:"; // The gendelim characters permitted in paths.

	private static boolean containsUnsafeCharacters(String string, String additionalSafeChars) {
		String safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		
		/*
		 * The percent character is always safe.
		 */
		safe += "%";
		
		safe += additionalSafeChars;

		for (int i = 0; i < string.length(); ++i) {
			if (safe.indexOf(string.charAt(i)) < 0) {
				return true;
			}
		}
		return false;
	}

	public static void testUrlEscaper(Escaper escaper, String additionalSafeChars, String sample, boolean plusIsSpace) {
		String encoded = escaper.escape(sample);

		if (containsUnsafeCharacters(encoded, additionalSafeChars)) {
			throw new FuzzerSecurityIssueMedium("unsafe character was not escaped");
		}

		String percentEncoded = encoded.replace("+", (plusIsSpace ? "%20" : "%2B"));

		String decoded = URLDecoder.decode(percentEncoded, Charsets.UTF_8);

		if (!decoded.equals(sample)) {
			throw new FuzzerSecurityIssueLow("escaped sequence not being decoded as expected");
		}
	}

	private static void testPercentEncoderConstructor(String safe, boolean plusIsSpace) {
		try {
			new PercentEscaper(safe, plusIsSpace);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		} 
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		try {
			boolean plusIsSpace = data.consumeBoolean();
			String  value = data.consumeRemainingAsString();
			testPercentEncoderConstructor(value, plusIsSpace);

			testUrlEscaper(new PercentEscaper("", plusIsSpace),   (plusIsSpace ? "+" : ""),                       value, plusIsSpace);
			testUrlEscaper(UrlEscapers.urlFormParameterEscaper(), URL_FORM_PARAMETER_OTHER_SAFE_CHARS + "+",      value, true);
			testUrlEscaper(UrlEscapers.urlFragmentEscaper(),      URL_PATH_OTHER_SAFE_CHARS_LACKING_PLUS + "+/?", value, false);
			testUrlEscaper(UrlEscapers.urlPathSegmentEscaper(),   URL_PATH_OTHER_SAFE_CHARS_LACKING_PLUS + "+",   value, false);
		} catch (IllegalArgumentException e) {
			/* ignore */
		} catch (Exception e) {
			throw new FuzzerSecurityIssueLow("Undocumented Exception");
		}
	}
}
