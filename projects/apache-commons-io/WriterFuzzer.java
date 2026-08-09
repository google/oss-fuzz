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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import org.apache.commons.io.output.AppendableWriter;
import org.apache.commons.io.output.BrokenWriter;
import org.apache.commons.io.output.ChunkedWriter;
import org.apache.commons.io.output.CloseShieldWriter;
import org.apache.commons.io.output.ClosedWriter;
import org.apache.commons.io.output.FileWriterWithEncoding;
import org.apache.commons.io.output.LockableFileWriter;
import org.apache.commons.io.output.NullWriter;
import org.apache.commons.io.output.ProxyCollectionWriter;
import org.apache.commons.io.output.ProxyWriter;
import org.apache.commons.io.output.StringBuilderWriter;
import org.apache.commons.io.output.TaggedWriter;
import org.apache.commons.io.output.TeeWriter;
import org.apache.commons.io.output.UncheckedFilterWriter;
import org.apache.commons.io.output.XmlStreamWriter;

/**
 * This fuzzer targets the read method of different Writer implementation classes in the output
 * package.
 */
public class WriterFuzzer {
  private static File file;

  public static void fuzzerInitialize() {
    try {
      file = File.createTempFile("OSS-Fuzz-", "-OSS-Fuzz");
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTearDown() {
    file.delete();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Writer writer = null;
      Integer choice = data.consumeInt(1, 15);
      OutputStream os = new ByteArrayOutputStream(1024);
      Writer outWriter = new OutputStreamWriter(os);

      // Randomly create a Writer implementation object
      switch (choice) {
        case 1:
          writer = new AppendableWriter<StringBuffer>(new StringBuffer());
          break;
        case 2:
          writer = BrokenWriter.INSTANCE;
          break;
        case 3:
          writer = new ChunkedWriter(outWriter);
          break;
        case 4:
          writer = CloseShieldWriter.wrap(outWriter);
          break;
        case 5:
          writer = ClosedWriter.INSTANCE;
          break;
        case 6:
          writer =
              FileWriterWithEncoding.builder()
                  .setAppend(data.consumeBoolean())
                  .setCharset(Charset.defaultCharset())
                  .setFile(file)
                  .get();
          break;
        case 7:
          writer =
              LockableFileWriter.builder()
                  .setAppend(data.consumeBoolean())
                  .setCharset(Charset.defaultCharset())
                  .setFile(file)
                  .setLockDirectory((String) null)
                  .get();
          break;
        case 8:
          writer = NullWriter.INSTANCE;
          break;
        case 9:
          writer = new ProxyCollectionWriter(outWriter);
          break;
        case 10:
          writer = new ProxyWriter(outWriter);
          break;
        case 11:
          writer = new StringBuilderWriter(1024);
          break;
        case 12:
          writer = new TaggedWriter(outWriter);
          break;
        case 13:
          writer = new TeeWriter(outWriter);
          break;
        case 14:
          writer = UncheckedFilterWriter.builder().setWriter(outWriter).get();
          break;
        case 15:
          writer =
              XmlStreamWriter.builder()
                  .setOutputStream(os)
                  .setCharset(Charset.defaultCharset())
                  .get();
          break;
      }

      if (writer != null) {
        // Fuzz the write method of the created Writer object
        String source = data.consumeRemainingAsString();
        writer.write(source, 0, source.length());
        writer.flush();
        writer.close();
      }
    } catch (IOException | IllegalArgumentException | UnsupportedOperationException e) {
      // Known exception
    }
  }
}
