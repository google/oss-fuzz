import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.maven.model.Model;
import org.apache.maven.model.v4.MavenMerger;

public class MergeFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        MavenMerger mavenMerger = new MavenMerger();
        Model target = Model.newBuilder().artifactId(data.consumeString(15)).build();

        Model source = Model.newBuilder().artifactId(data.consumeString(15)).build();

        Model merged = mavenMerger.merge(target, source, data.consumeBoolean(), null);
    }
}