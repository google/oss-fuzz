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
import tools.jackson.core.JsonParser;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonFactoryBuilder;
import tools.jackson.core.Base64Variants;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.core.json.JsonReadFeature;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.JacksonException;

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
    JsonReadFeature[] readFeatures = new JsonReadFeature[]{
        JsonReadFeature.ALLOW_JAVA_COMMENTS,
        JsonReadFeature.ALLOW_YAML_COMMENTS,
        JsonReadFeature.ALLOW_UNQUOTED_PROPERTY_NAMES,
        JsonReadFeature.ALLOW_SINGLE_QUOTES,
        JsonReadFeature.ALLOW_UNESCAPED_CONTROL_CHARS,
        JsonReadFeature.ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER,
        JsonReadFeature.ALLOW_LEADING_ZEROS_FOR_NUMBERS,
        JsonReadFeature.ALLOW_LEADING_PLUS_SIGN_FOR_NUMBERS,
        JsonReadFeature.ALLOW_LEADING_DECIMAL_POINT_FOR_NUMBERS,
        JsonReadFeature.ALLOW_TRAILING_DECIMAL_POINT_FOR_NUMBERS,
        JsonReadFeature.ALLOW_NON_NUMERIC_NUMBERS,
        JsonReadFeature.ALLOW_MISSING_VALUES,
        JsonReadFeature.ALLOW_TRAILING_COMMA,
    };
    StreamReadFeature[] streamFeatures = new StreamReadFeature[]{
        StreamReadFeature.AUTO_CLOSE_SOURCE,
        StreamReadFeature.STRICT_DUPLICATE_DETECTION,
        StreamReadFeature.IGNORE_UNDEFINED,
        StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION,
        StreamReadFeature.USE_FAST_DOUBLE_PARSER,
    };
    
    // Configure features using builder pattern
    JsonFactoryBuilder builder = JsonFactory.builder();
    for (int i = 0; i < readFeatures.length; i++) {
        if (data.consumeBoolean()) {
            builder.enable(readFeatures[i]);
        } else {
            builder.disable(readFeatures[i]);
        }
    }
    for (int i = 0; i < streamFeatures.length; i++) {
        if (data.consumeBoolean()) {
            builder.enable(streamFeatures[i]);
        } else {
            builder.disable(streamFeatures[i]);
        }
    }
    JsonFactory jf = builder.build();
    
    try {
      int typeOfNext = data.consumeInt();
      JsonParser jp = jf.createParser(data.consumeRemainingAsBytes());
      switch (typeOfNext%8) {
      case 0:
        while (jp.nextToken() != null) {
              ;
        }
        break;
      case 1:
        while (jp.nextValue() != null) {
              ;
        }
        break;
      case 2:
        while (jp.nextName() != null) {
              ;
        }
        break;
      case 3:
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Base64Variants b64vs = new Base64Variants();
        jp.readBinaryValue(b64vs.MIME, outputStream);
        break;
      case 4:
        String outString = jp.getValueAsString();
        break;
      case 5:
        int outInt = jp.getValueAsInt();
        break;
      case 6:
        char[] textChars = jp.getTextCharacters();
        break;
      case 7:
        int textLen = jp.getTextLength();
        int textOffset = jp.getTextOffset();
        break;
      }      
    } catch (JacksonException | IllegalArgumentException ignored) {
    }
  }
}


