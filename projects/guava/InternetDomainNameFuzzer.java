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
import com.google.common.net.InternetDomainName;
import java.lang.IllegalArgumentException;
import java.lang.IllegalStateException;

public class InternetDomainNameFuzzer {
	private static void testAccessorMethods(InternetDomainName idn) {
		idn.parts();
		idn.isPublicSuffix();
		idn.hasPublicSuffix();
		idn.publicSuffix();
		idn.isUnderPublicSuffix();
		idn.isTopPrivateDomain();
		try {
			idn.topPrivateDomain();
		} catch(IllegalStateException e) {
			/* documented, ignore */
		}
		idn.isRegistrySuffix();
		idn.hasRegistrySuffix();
		idn.registrySuffix();
		idn.isUnderRegistrySuffix();
		idn.isTopDomainUnderRegistrySuffix();
		try {
			idn.topDomainUnderRegistrySuffix();
		} catch(IllegalStateException e) {
			/* documented, ignore */
		}
		idn.hasParent();
		try {
			idn.parent();
		} catch(IllegalStateException e) {
			/* documented, ignore */
		}
		idn.hashCode();
	}

	public static void testChild(InternetDomainName idn, String leftParts) {
		try {
			idn.child(leftParts);
		} catch(IllegalArgumentException e) {
			/* documented, ignore */
		} catch(NullPointerException e) {
			/* documented, ignore */
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider dataProvider) {
		
		try {
			InternetDomainName idn;
			try {
				idn = InternetDomainName.from(dataProvider.consumeString(dataProvider.remainingBytes()));
			} catch (IllegalArgumentException e) {
				/*
				 * documented to be thrown, ignore
				 */
				return;
			}

			testAccessorMethods(idn);
			testChild(idn, dataProvider.consumeString(dataProvider.remainingBytes()));

	    } catch (Exception e) {
			throw new FuzzerSecurityIssueLow("Undocumented Exception");
		}
	}
}
