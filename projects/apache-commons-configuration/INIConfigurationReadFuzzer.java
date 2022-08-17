import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.IOException;

import org.apache.commons.configuration2.INIConfiguration;
import org.apache.commons.configuration2.ex.ConfigurationException;

public class INIConfigurationReadFuzzer extends INIConfiguration {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // Create helper objects from fuzzer data
        final char commentCharacter = data.consumeChar();
        final char separatorCharacter = data.consumeChar();
        final byte[] byteArray = data.consumeBytes(Integer.MAX_VALUE);

        // Create needed objects
        INIConfiguration iniConfig = new INIConfiguration();
        InputStream inputStream = new ByteArrayInputStream(byteArray);
        InputStreamReader reader = new InputStreamReader(inputStream);

        try {
            iniConfig.setSeparatorUsedInInput(Character.toString(separatorCharacter));
            iniConfig.setCommentLeadingCharsUsedInInput(Character.toString(commentCharacter));
            iniConfig.read(reader);
        } catch (IOException | ConfigurationException ignored) {
            // expected Exceptions get ignored
        }
    }
}
