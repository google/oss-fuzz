import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.ByteArrayInputStream;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.apache.maven.model.Model;

public class Xpp3ReaderFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try{
            ByteArrayInputStream bais = new ByteArrayInputStream(data.consumeRemainingAsBytes());
            Model model = new MavenXpp3Reader().read(bais);
        }
        catch (java.io.IOException e) {}
        catch (org.codehaus.plexus.util.xml.pull.XmlPullParserException e) {}
    }
}