import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.xmlpull.v1.XmlPullParserFactory;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.StringReader;

public class XmlFuzzer {
    public static XmlPullParserFactory factoryNewInstance() throws XmlPullParserException {
        String property = System.getProperty(XmlPullParserFactory.PROPERTY_NAME);
        return XmlPullParserFactory.newInstance(
            property,
            null
        );
    }

    public static void processDocument(XmlPullParser xpp) throws XmlPullParserException, IOException {
        int eventType = xpp.getEventType();
        do {
            eventType = xpp.next();
        } while (eventType != xpp.END_DOCUMENT);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            XmlPullParserFactory factory = factoryNewInstance();
            factory.setNamespaceAware(true);
            XmlPullParser xpp = factory.newPullParser();
            xpp.setInput(new StringReader(data.consumeRemainingAsString()));
            processDocument(xpp);
        } catch (XmlPullParserException | IOException e) { }
	}
}
