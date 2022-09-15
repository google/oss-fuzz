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
