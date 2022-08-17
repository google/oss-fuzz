import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.commons.configuration2.YAMLConfiguration;
import org.apache.commons.configuration2.ex.ConfigurationException;

public class YAMLConfigurationReadFuzzer {
    public static void fuzzerTestOneInput(byte[] data) {
        // Create needed objects
        YAMLConfiguration yamlConfig = new YAMLConfiguration();
        InputStream inputStream = new ByteArrayInputStream(data);

        try {
            yamlConfig.read(inputStream);
        } catch (ConfigurationException ignored) {
            // expected Exceptions get ignored
        }
    }
}
