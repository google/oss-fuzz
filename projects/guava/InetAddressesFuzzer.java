import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.google.common.net.InetAddresses;
import java.lang.IllegalArgumentException;
import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.UnknownHostException;

public class InetAddressesFuzzer {

	private static void testInet6ApiSpecificMethods(InetAddress inaddr) {
		Inet6Address inet6 = null;
		if ((inaddr != null) && (inaddr instanceof Inet6Address)) {
			inet6 = (Inet6Address)inaddr;
		}
			
		if (inet6 != null) {
			try {
				InetAddresses.getEmbeddedIPv4ClientAddress(inet6);
			} catch (IllegalArgumentException e) {
				/* documented, ignore */
			} catch (Exception e) {
				throw new FuzzerSecurityIssueLow("Undocumented Exception");
			}

			try {
				InetAddresses.TeredoInfo teredoInfo = InetAddresses.getTeredoInfo(inet6);
				teredoInfo.getServer();
				teredoInfo.getClient();
				teredoInfo.getPort();
				teredoInfo.getFlags();
			} catch (IllegalArgumentException  e) {
				/* documented, ignore */
			} catch (Exception e) {
				throw new FuzzerSecurityIssueLow("Undocumented Exception");
			}

			try {
				InetAddresses.getCoercedIPv4Address(inet6);
			} catch (Exception e) {
				throw new FuzzerSecurityIssueLow("Undocumented Exception");
			}
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		
		InetAddress in6 = null;
		InetAddress in4 = null;
		try {
			in6 = InetAddresses.fromLittleEndianByteArray(data.consumeBytes(16));
			in4 = InetAddresses.fromLittleEndianByteArray(data.consumeBytes(4));
		} catch (UnknownHostException e) {
			/* documented, ignore */
		} catch (Exception e) {
			throw new FuzzerSecurityIssueLow("Undocumented Exception");
		}

		testInet6ApiSpecificMethods(in6);

		String value = data.consumeRemainingAsString();
		InetAddress addr = null, uriAddr = null;

		try {
			uriAddr = InetAddresses.forUriString(value);
			addr = InetAddresses.forString(value);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		} catch (Exception e) {
			throw new FuzzerSecurityIssueLow("Undocumented Exception");
		}

		/*
		 * These don't throw exceptions.
		 */
		try {
			InetAddresses.isInetAddress(value);
			InetAddresses.isUriInetAddress(value);
			InetAddresses.isMappedIPv4Address(value);
			InetAddresses.isMappedIPv4Address(value);
		} catch (Exception e) {
			throw new FuzzerSecurityIssueLow("Undocumented Exception");
		}
		
		if (addr != null) {
			/*
			 * These don't throw exceptions, either, but need a valid
			 * InetAddress instance.
			 */
			try {
				InetAddresses.toUriString(addr);
				InetAddresses.toAddrString(addr);
				InetAddresses.coerceToInteger(addr);
			} catch (Exception e) {
				throw new FuzzerSecurityIssueLow("Undocumented Exception");
			}

			try {
				InetAddresses.increment(addr);
				InetAddresses.decrement(addr);
			} catch (IllegalArgumentException e) {
				/* documented, ignore */
			} catch (Exception e) {
				throw new FuzzerSecurityIssueLow("Undocumented Exception");
			}

			try {
				InetAddresses.fromIPv6BigInteger(InetAddresses.toBigInteger(addr));
			} catch (IllegalArgumentException e) {
				/* documented, ignore */
			} catch (Exception e) {
				throw new FuzzerSecurityIssueLow("Undocumented Exception");
			}

			try {
				InetAddresses.fromIPv4BigInteger(InetAddresses.toBigInteger(addr));
			} catch (IllegalArgumentException e) {
				/* documented, ignore */
			} catch (Exception e) {
				throw new FuzzerSecurityIssueLow("Undocumented Exception");
			}
		}
	} 
}