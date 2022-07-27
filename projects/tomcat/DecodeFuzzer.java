import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;

import java.lang.StringBuilder;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.io.IOException;
import java.util.Arrays;
import java.io.UnsupportedEncodingException;
import org.apache.tomcat.util.buf.UEncoder;
import org.apache.tomcat.util.buf.UEncoder.SafeCharsSet;
import org.apache.tomcat.util.buf.UDecoder;
import org.apache.tomcat.util.buf.CharChunk;
import org.apache.catalina.util.URLEncoder;
import java.nio.charset.StandardCharsets;

public class DecodeFuzzer {
    static String [] encodings = {
        "US-ASCII",
        "ISO-8859-1",
        "UTF-8",
        "UTF-16BE",
        "UTF-16LE",
        "UTF-16"
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int num = data.consumeInt(0, encodings.length - 1);
        String enc = encodings[num];
        String str = data.consumeRemainingAsString();

        try {
            String decodedData = UDecoder.URLDecode(str, Charset.forName(enc));
        } catch (IllegalArgumentException e) {
        }
    }
}
