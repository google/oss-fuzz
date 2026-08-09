import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;
import org.h2.tools.Csv;
import org.h2.tools.SimpleResultSet;

public class CsvReadBackFuzzer {

    static class TableContent
    {
        private static boolean contains(String haystack[], String needle, int n)
        {
            while (n-- > 0) {
                if (haystack[n].equals(needle)) {
                    return true;
                }
            }

            return false;
        }

        public TableContent(FuzzedDataProvider fuzzedDataProvider) {
            m_columnCount = fuzzedDataProvider.consumeInt(1,4);
            m_rowCount    = fuzzedDataProvider.consumeInt(1,100);
            m_headers     = new String[getColumnCount()];
            m_content     = new String[getRowCount()][getColumnCount()];

            for (int column = 0; column < getColumnCount(); ++column) {
                m_headers[column] = "C_" + column;
            }

            for (int row = 0; row < getRowCount(); ++row) {
                for (int column = 0; column < getColumnCount(); ++column) {
                    if (row == 0) {
                        m_content[row][column] = fuzzedDataProvider.consumeAsciiString(8);
                    } else {
                        m_content[row][column] = fuzzedDataProvider.consumeRemainingAsAsciiString();
                    }
                }
            }
        }

        public SimpleResultSet simpleResultSet() {
            SimpleResultSet rs = new SimpleResultSet();
            for (int column = 0; column < getColumnCount(); ++column) {
                /*
                 * VARCHAR(255) might be insufficient
                 */
                rs.addColumn(columnHeader(column), Types.VARCHAR, 255, 0);
            }

            for (int row = 0; row < getRowCount(); ++row) {
                rs.addRow(getRow(row));
            }

            return rs;
        }

        public String columnHeader(int column) {
            return m_headers[column];
        }

        public int getColumnCount() {
            return m_columnCount;
        }

        public int getRowCount() {
            return m_rowCount;
        }

        public Object[] getRow(int row) {
            return m_content[row];
        }

        public String getCell(int row, int column) {
            return m_content[row][column];
        }

        int m_columnCount;
        int m_rowCount;

        String m_headers[];
        String m_content[][];
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        TableContent data = new TableContent(fuzzedDataProvider);

        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        OutputStreamWriter writer = new OutputStreamWriter(outStream);
        
        try {
            new Csv().write(writer, data.simpleResultSet());
        } catch (SQLException ex) {
            /* documented, ignore */
            return;
        }

        ByteArrayInputStream inStream = new ByteArrayInputStream(outStream.toByteArray());
        InputStreamReader reader = new InputStreamReader(inStream);
        ResultSet resultSet = null;
        
        try {
            resultSet = new Csv().read(reader, null);
        } catch (IOException e) {
            return;
        }

        try {
            ResultSetMetaData meta = resultSet.getMetaData();
            if (meta.getColumnCount() != data.getColumnCount()) {
                throw new FuzzerSecurityIssueLow("Column Count Mismatch");
            }

            for (int column = 0; column < meta.getColumnCount(); ++column) {
                String have = meta.getColumnLabel(column + 1);
                String want = data.columnHeader(column);
                if ( ! have.equals(want) ) {
                    System.out.println("\'" + have + "\'  !=  \'" + want + "\'");
                    throw new FuzzerSecurityIssueLow("Column Label Mismatch");
                }
            }
            int row = 0;
            while (resultSet.next()) {
                for (int column = 0; column < meta.getColumnCount(); ++column) {
                    String have = resultSet.getString(column + 1);
                    String want = data.getCell(row, column);
                    if ( ! have.equals( want ) ) {
                        System.out.println("\'" + have + "\'  !=  \'" + want + "\'");
                        throw new FuzzerSecurityIssueLow("Cell Value Mismatch");
                    }
                }
                ++row;
            }
            if (row != data.getRowCount()) {
                throw new FuzzerSecurityIssueLow("Row Count Mismatch");
            }
            resultSet.close();
        } catch (SQLException ex) {
            /* documented, but shouldn't happen on our well-known input */
            ex.printStackTrace(System.out);
            throw new FuzzerSecurityIssueLow("SQLException??");
        }
    }
}