import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.zookeeper.server.DataTree;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.txn.TxnHeader;
import org.apache.zookeeper.txn.CreateTxn;
import java.util.List;
import java.util.ArrayList;

public class DataTreeFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try{
        DataTree dt = new DataTree();
        String path = data.consumeString(20);
        dt.createNode(path, data.consumeBytes(1000), null, data.consumeLong(), data.consumeInt(), data.consumeLong(), data.consumeLong());
        dt.deleteNode(path, data.consumeLong());
        dt.processTxn(
            new TxnHeader(data.consumeInt(), data.consumeInt(), data.consumeInt(), data.consumeInt(), ZooDefs.OpCode.create), 
            new CreateTxn(data.consumeString(15), data.consumeBytes(1000), ZooDefs.Ids.OPEN_ACL_UNSAFE, data.consumeBoolean(), data.consumeInt())
        );
    
    }
    catch (org.apache.zookeeper.KeeperException.NoNodeException e) {}
    catch (org.apache.zookeeper.KeeperException.NodeExistsException e) {}
    catch (java.lang.StringIndexOutOfBoundsException e) {}
    catch (java.lang.NoClassDefFoundError e) {}
  }
}