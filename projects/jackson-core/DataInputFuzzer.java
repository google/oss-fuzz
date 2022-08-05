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
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.core.JsonParser.Feature;

import java.io.*;

public class DataInputFuzzer {
  public static class MockFuzzDataInput implements DataInput
  {
    private final InputStream _input;

    public MockFuzzDataInput(byte[] data) {
        _input = new ByteArrayInputStream(data);
    }

    public MockFuzzDataInput(String utf8Data) throws IOException {
        _input = new ByteArrayInputStream(utf8Data.getBytes("UTF-8"));
    }

    public MockFuzzDataInput(InputStream in) {
        _input = in;
    }

    @Override
    public void readFully(byte[] b) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void readFully(byte[] b, int off, int len) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int skipBytes(int n) throws IOException {
        return (int) _input.skip(n);
    }

    @Override
    public boolean readBoolean() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte readByte() throws IOException {
        int ch = _input.read();
        if (ch < 0) {
            throw new EOFException("End-of-input for readByte()");
        }
        return (byte) ch;
    }

    @Override
    public int readUnsignedByte() throws IOException {
        return readByte() & 0xFF;
    }

    @Override
    public short readShort() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int readUnsignedShort() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public char readChar() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int readInt() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public long readLong() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public float readFloat() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public double readDouble() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String readLine() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String readUTF() throws IOException {
        throw new UnsupportedOperationException();
    }
  }


  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    Feature[] features = new Feature[]{
        Feature.AUTO_CLOSE_SOURCE,
        Feature.ALLOW_COMMENTS,
        Feature.ALLOW_YAML_COMMENTS,
        Feature.ALLOW_UNQUOTED_FIELD_NAMES,
        Feature.ALLOW_SINGLE_QUOTES,
        Feature.ALLOW_UNQUOTED_CONTROL_CHARS,
        Feature.ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER,
        Feature.ALLOW_NUMERIC_LEADING_ZEROS,
        Feature.ALLOW_LEADING_PLUS_SIGN_FOR_NUMBERS,
        Feature.ALLOW_LEADING_DECIMAL_POINT_FOR_NUMBERS,
        Feature.ALLOW_TRAILING_DECIMAL_POINT_FOR_NUMBERS,
        Feature.ALLOW_NON_NUMERIC_NUMBERS,
        Feature.ALLOW_MISSING_VALUES,
        Feature.ALLOW_TRAILING_COMMA,
        Feature.STRICT_DUPLICATE_DETECTION,
        Feature.IGNORE_UNDEFINED,
        Feature.INCLUDE_SOURCE_IN_LOCATION,
        Feature.USE_FAST_DOUBLE_PARSER,
    };
    JsonFactory jf = new JsonFactory();
    try {
        for (int i = 0; i < features.length; i++) {
            if (data.consumeBoolean()) {
                jf.enable(features[i]);
            } else {
                jf.disable(features[i]);
            }
        }
      int typeOfNext = data.consumeInt();
      JsonParser jp = jf.createParser(new MockFuzzDataInput(data.consumeRemainingAsString()));
      switch (typeOfNext%5) {
      case 0:
        while (jp.nextToken() != null) {
              ;
        }
      case 1:
        while (jp.nextTextValue() != null) {
              ;
        }
      case 2:
        while (jp.nextBooleanValue() != null) {
              ;
        }
      case 3:
        while (jp.nextFieldName() != null) {
              ;
        }
      case 4:
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Base64Variants b64vs = new Base64Variants();
        jp.readBinaryValue(b64vs.MIME, outputStream);
      }      
    } catch (IOException | IllegalArgumentException ignored) {
    }
  }
}


