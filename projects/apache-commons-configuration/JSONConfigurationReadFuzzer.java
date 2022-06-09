import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ByteArrayInputStream;

import org.apache.commons.configuration2.JSONConfiguration;
import org.apache.commons.configuration2.ex.ConfigurationException;

public class JSONConfigurationReadFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // Create helper objects from fuzzer data
        final boolean useReader = data.consumeBoolean();
        final byte[] byteArray = data.consumeBytes(Integer.MAX_VALUE);

        // Create needed objects
        final JSONConfiguration jsonConfig = new JSONConfiguration();
        final InputStream inputStream = new ByteArrayInputStream(byteArray);
        final InputStreamReader reader;

        try {
            if (useReader) {
                reader = new InputStreamReader(inputStream);
                jsonConfig.read(reader);
            } else {
                jsonConfig.read(inputStream);
            }

        } catch (ConfigurationException ignored) {
            // expected Exceptions get ignored
        }
    }
}
