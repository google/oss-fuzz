// Copyright 2023 Google LLC
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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.Charset;
import org.apache.commons.io.input.BoundedReader;
import org.apache.commons.io.input.BrokenReader;
import org.apache.commons.io.input.CharSequenceReader;
import org.apache.commons.io.input.CharacterFilterReader;
import org.apache.commons.io.input.CharacterSetFilterReader;
import org.apache.commons.io.input.CloseShieldReader;
import org.apache.commons.io.input.ClosedReader;
import org.apache.commons.io.input.NullReader;
import org.apache.commons.io.input.SequenceReader;
import org.apache.commons.io.input.TaggedReader;
import org.apache.commons.io.input.TeeReader;
import org.apache.commons.io.input.UncheckedBufferedReader;
import org.apache.commons.io.input.UncheckedFilterReader;
import org.apache.commons.io.input.XmlStreamReader;

/**
 * This fuzzer targets the read method of different Reader implementation classes in the input
 * package.
 */
public class ReaderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Reader reader = null;
      Integer size = data.remainingBytes();
      Integer intValue = data.consumeInt();
      Integer choice = data.consumeInt(1, 14);
      byte[] srcBuffer = data.consumeRemainingAsBytes();
      ByteArrayInputStream bais = new ByteArrayInputStream(srcBuffer);
      Reader srcReader = new InputStreamReader(bais);

      // Randomly create a Reader implementation object
      switch (choice) {
        case 1:
          reader = new BoundedReader(srcReader, size);
          break;
        case 2:
          reader = BrokenReader.INSTANCE;
          break;
        case 3:
          reader = new CharSequenceReader(new String(srcBuffer, Charset.defaultCharset()));
          break;
        case 4:
          reader = new CharacterFilterReader(srcReader, intValue);
          break;
        case 5:
          reader = new CharacterSetFilterReader(srcReader, intValue);
          break;
        case 6:
          reader = CloseShieldReader.wrap(srcReader);
          break;
        case 7:
          reader = ClosedReader.INSTANCE;
          break;
        case 8:
          reader = NullReader.INSTANCE;
          break;
        case 9:
          reader = new SequenceReader(srcReader);
          break;
        case 10:
          reader = new TaggedReader(srcReader);
          break;
        case 11:
          Writer writer = new OutputStreamWriter(new ByteArrayOutputStream(size));
          reader = new TeeReader(srcReader, writer);
          break;
        case 12:
          reader = UncheckedBufferedReader.builder().setReader(srcReader).get();
          break;
        case 13:
          reader = UncheckedFilterReader.builder().setReader(srcReader).get();
          break;
        case 14:
          reader = XmlStreamReader.builder().setInputStream(bais).get();
          break;
      }

      if (reader != null) {
        // Fuzz the read method of the created Reader object
        char[] buffer = new char[size + 1];
        if (reader.ready()) {
          reader.read(buffer, 0, size + 1);
        }
        reader.close();
      }
    } catch (IOException | IllegalArgumentException | UnsupportedOperationException e) {
      // Known exception
    }
  }
}
