import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.IOException;

import org.apache.commons.configuration2.INIConfiguration;
import org.apache.commons.configuration2.ex.ConfigurationException;

public class INIConfigurationWriteFuzzer extends INIConfiguration {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // Create helper objects from fuzzer data
        final char commentCharacter = data.consumeChar();
        final char inputSeparatorCharacter = data.consumeChar();
        final char outputSeparatorCharacter = data.consumeChar();
        final byte[] byteArray = data.consumeBytes(Integer.MAX_VALUE);

        // Create the needed objects
        INIConfiguration iniConfig = new INIConfiguration();
        InputStream inputStream = new ByteArrayInputStream(byteArray);
        InputStreamReader reader = new InputStreamReader(inputStream);
        StringWriter writer = new StringWriter();

        try {
            iniConfig.setSeparatorUsedInInput(Character.toString(inputSeparatorCharacter));
            iniConfig.setCommentLeadingCharsUsedInInput(Character.toString(commentCharacter));
            iniConfig.read(reader);

            iniConfig.setSeparatorUsedInOutput(Character.toString(outputSeparatorCharacter));
            iniConfig.write(writer);
        } catch (IOException | ConfigurationException ignored) {
            // expected Exceptions get ignored
        }
    }
}
