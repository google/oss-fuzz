package org.apache.poi;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import org.apache.poi.openxml4j.exceptions.OpenXML4JException;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.examples.xssf.eventusermodel.XLSX2CSV;
import org.apache.poi.util.RecordFormatException;
import org.xml.sax.SAXException;

public class XLSX2CSVFuzzer {

    private FuzzedDataProvider fuzzedDataProvider;

    public XLSX2CSVFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        this.fuzzedDataProvider = fuzzedDataProvider;
    }

    void test() {
        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream out = new PrintStream(baos, true, StandardCharsets.UTF_8.name());
            String string = fuzzedDataProvider.consumeRemainingAsString();
            InputStream in = new ByteArrayInputStream(string.getBytes("UTF-8"));
            OPCPackage p = OPCPackage.open(in);
            XLSX2CSV xlsx2csv = new XLSX2CSV(p, out, 5);
            xlsx2csv.process();
        } catch (IOException | OpenXML4JException | SAXException ex) {
            /* documented, ignore. */
        } catch (UnsupportedFileFormatException | RecordFormatException | EmptyFileException ex) {
            /* not so documented ... */
        }

    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        XLSX2CSVFuzzer fixture = new XLSX2CSVFuzzer(fuzzedDataProvider);
        fixture.test();
    }
}