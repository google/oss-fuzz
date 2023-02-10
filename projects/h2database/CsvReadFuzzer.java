import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;
import org.h2.tools.Csv;

public class CsvReadFuzzer {

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        ByteArrayInputStream inStream = new ByteArrayInputStream(fuzzedDataProvider.consumeRemainingAsBytes());
        InputStreamReader reader = new InputStreamReader(inStream);
        
        try {
            new Csv().read(reader, null);
        } catch (IOException e) {
            /* ignore */
        } catch (Exception e) {
            throw new FuzzerSecurityIssueLow("Undocumented Exception");
        }
    }
}