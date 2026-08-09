import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.xmlpull.v1.XmlPullParserFactory;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.StringReader;

public class PullParserFactoryFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            XmlPullParserFactory factory = XmlPullParserFactory.newInstance(
                data.consumeString(100),
                null
            );
            factory.setFeature(data.consumeString(30), data.consumeBoolean());
            factory.getFeature(data.consumeString(30));
            factory.setNamespaceAware(data.consumeBoolean());
            XmlPullParser xpp = factory.newPullParser();
        } catch (XmlPullParserException e) { }
	}
}
