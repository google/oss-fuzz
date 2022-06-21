import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.commons.configuration2.XMLConfiguration;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.configuration2.io.FileHandler;

public class XMLConfigurationLoadFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // Create needed objects
        final File tempFile;
        try {
            tempFile = File.createTempFile("XMLConfiguration", "xml");
            tempFile.deleteOnExit();
        } catch (IOException ioe) {
            // Preparations failed ; exit early
            return;
        }
        final String absoluteFilepath = tempFile.getAbsolutePath();

        try {
            final FileWriter fileWriter = new FileWriter(tempFile);
            fileWriter.write(data.consumeRemainingAsString());
            fileWriter.close();
        } catch (IOException ioe) {
            // Preparations failed ; exit early
            return;
        }

        final FileHandler fileHandler = new FileHandler(new XMLConfiguration());
        fileHandler.setPath(absoluteFilepath);

        try {
            fileHandler.load();
        } catch (ConfigurationException ignored) {
            // expected Exceptions get ignored
        }
    }
}
