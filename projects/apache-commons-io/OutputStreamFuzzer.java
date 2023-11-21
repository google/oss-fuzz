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
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import org.apache.commons.io.output.AppendableOutputStream;
import org.apache.commons.io.output.BrokenOutputStream;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.apache.commons.io.output.ChunkedOutputStream;
import org.apache.commons.io.output.CloseShieldOutputStream;
import org.apache.commons.io.output.ClosedOutputStream;
import org.apache.commons.io.output.CountingOutputStream;
import org.apache.commons.io.output.DemuxOutputStream;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.commons.io.output.ProxyOutputStream;
import org.apache.commons.io.output.QueueOutputStream;
import org.apache.commons.io.output.TaggedOutputStream;
import org.apache.commons.io.output.TeeOutputStream;
import org.apache.commons.io.output.ThresholdingOutputStream;
import org.apache.commons.io.output.UncheckedFilterOutputStream;
import org.apache.commons.io.output.UnsynchronizedByteArrayOutputStream;
import org.apache.commons.io.output.WriterOutputStream;

/**
 * This fuzzer targets the read method of different OutputStream implementation classes in the
 * output package.
 */
public class OutputStreamFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      OutputStream os = null;
      Integer choice = data.consumeInt(1, 16);
      OutputStream baos = new ByteArrayOutputStream(1024);

      // Randomly create an OutputStream implementation object
      switch (choice) {
        case 1:
          os = new AppendableOutputStream<StringBuffer>(new StringBuffer());
          break;
        case 2:
          os = BrokenOutputStream.INSTANCE;
          break;
        case 3:
          os = ChunkedOutputStream.builder().setOutputStream(baos).get();
          break;
        case 4:
          os = CloseShieldOutputStream.wrap(baos);
          break;
        case 5:
          os = ClosedOutputStream.INSTANCE;
          break;
        case 6:
          os = new CountingOutputStream(baos);
          break;
        case 7:
          os = new DemuxOutputStream().bindStream(baos);
          break;
        case 8:
          os = NullOutputStream.INSTANCE;
          break;
        case 9:
          os = new ProxyOutputStream(baos);
          break;
        case 10:
          os = new QueueOutputStream();
          break;
        case 11:
          os = new TaggedOutputStream(baos);
          break;
        case 12:
          OutputStream branch = new ByteArrayOutputStream(1024);
          os = new TeeOutputStream(baos, branch);
          break;
        case 13:
          os = new ThresholdingOutputStream(data.consumeInt());
          break;
        case 14:
          os = UncheckedFilterOutputStream.builder().setOutputStream(baos).get();
          break;
        case 15:
          os = UnsynchronizedByteArrayOutputStream.builder().setOutputStream(baos).get();
          break;
        case 16:
          OutputStreamWriter writer = new OutputStreamWriter(baos);
          os =
              WriterOutputStream.builder()
                  .setWriter(writer)
                  .setCharset(Charset.defaultCharset())
                  .setWriteImmediately(data.consumeBoolean())
                  .get();
          break;
      }

      if (os != null) {
        // Fuzz the write method of the created OutStream object
        byte[] srcBuffer = data.consumeRemainingAsBytes();
        os.write(srcBuffer, 0, srcBuffer.length);
        os.flush();
        os.close();
      }
    } catch (IOException | IllegalArgumentException | UnsupportedOperationException e) {
      // Known exception
    }
  }
}
