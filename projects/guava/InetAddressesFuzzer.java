import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.google.common.net.InetAddresses;
import java.lang.IllegalArgumentException;
import java.net.InetAddress;

public class InetAddressesFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
	    String value = data.consumeRemainingAsString();
        InetAddress addr;

        try {
            InetAddresses.isInetAddress(value);
            InetAddresses.isUriInetAddress(value);
            InetAddresses.isMappedIPv4Address(value);
            InetAddresses.forUriString(value);
            InetAddresses.isMappedIPv4Address(value);

            addr = InetAddresses.forString(value);
            InetAddresses.toUriString(addr);
            InetAddresses.toAddrString(addr);
            InetAddresses.increment(addr);
            InetAddresses.decrement(addr);

        } catch (IllegalArgumentException e) { }
	} 
}