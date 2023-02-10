// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

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
import java.math.BigInteger;
// import javax.xml.bind.DatatypeConverter;

public class EnDecodeFuzzer {
    static String [] encodings = {
        "US-ASCII",
        "ISO-8859-1",
        "UTF-8",
        "UTF-16BE",
        "UTF-16LE",
        // "UTF-16"
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int num = data.consumeInt(0, encodings.length - 1);
        String originalData = data.consumeRemainingAsAsciiString();
        URLEncoder ue = new URLEncoder();
        String enc = encodings[num];
        String encodedData = ue.encode(originalData, Charset.forName(enc));
        String decodedData = UDecoder.URLDecode(encodedData, Charset.forName(enc));

        // try {
        //     System.out.println("Encoding: " + enc);
        //     System.out.println("Original: " + toHexadecimal(originalData, enc));
        //     System.out.println("Decoded: " + toHexadecimal(decodedData, enc));   
        // } catch (Exception e) {
        //     throw new FuzzerSecurityIssueHigh("print error");
        // }

        assert decodedData.equals(originalData) : new FuzzerSecurityIssueHigh("Encoding decoding inconsistent");
    }

    // public static String toHexadecimal(String text, String enc) throws UnsupportedEncodingException
    // {
    //     byte[] myBytes = text.getBytes(enc);
    //     return DatatypeConverter.printHexBinary(myBytes);
    // }
}
