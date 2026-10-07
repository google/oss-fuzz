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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.google.common.net.HostSpecifier;
import java.text.ParseException;

public class HostSpecifierFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		try {
			HostSpecifier hs = HostSpecifier.from(data.consumeRemainingAsString());

			/*
			 * hs.toString() is a valid string, as otherwise the
			 * HostSpecifier.from() invocation to initialize hs
			 * would have thrown an exception.
			 */
			if (! HostSpecifier.isValid(hs.toString())) {
				throw new FuzzerSecurityIssueLow("toString() generated a poor host specifier");
			}
			hs.hashCode();
		} catch (ParseException e) {
			/* documented to be thrown, ignore */
		} catch (Exception e) {
			throw new FuzzerSecurityIssueLow("Undocumented Exception");
		}
	}
}
