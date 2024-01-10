import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.zookeeper.server.DataTree;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.apache.jute.BinaryInputArchive;
import org.apache.jute.BinaryOutputArchive;
import java.io.IOException;

public class SerializeFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
        DataTree tree = new DataTree();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BinaryOutputArchive oa = BinaryOutputArchive.getArchive(baos);
        tree.serialize(oa, data.consumeString(100));
        baos.flush();
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        BinaryInputArchive ia = BinaryInputArchive.getArchive(bais);
        tree.deserialize(ia, data.consumeString(100));
    } catch (IOException e) {
    }
    
  }
}