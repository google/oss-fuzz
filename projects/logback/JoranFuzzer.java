import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ch.qos.logback.classic.LoggerContext;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.joran.spi.JoranException;

import java.io.InputStream;
import java.io.ByteArrayInputStream;

public class JoranFuzzer {
	private final static Logger logger = LoggerFactory.getLogger(JoranFuzzer.class);
    private final static JoranConfigurator configurator = new JoranConfigurator();

    public static void fuzzerInitialize() {
        LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
        configurator.setContext(lc);
        lc.reset();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String content = data.consumeString(1000);

        // https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=47102
        if (content.contains("class=\"")) {
            return;
        }

        InputStream xmlcontent = new ByteArrayInputStream(content.getBytes());
        try {
            configurator.doConfigure(xmlcontent);
            logger.debug(data.consumeRemainingAsString());
        } catch (JoranException e) { }
	} 
}
