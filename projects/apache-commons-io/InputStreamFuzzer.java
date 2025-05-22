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
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.io.input.AutoCloseInputStream;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.io.input.BoundedInputStream;
import org.apache.commons.io.input.BrokenInputStream;
import org.apache.commons.io.input.CharSequenceInputStream;
import org.apache.commons.io.input.CircularInputStream;
import org.apache.commons.io.input.ClassLoaderObjectInputStream;
import org.apache.commons.io.input.CloseShieldInputStream;
import org.apache.commons.io.input.ClosedInputStream;
import org.apache.commons.io.input.CountingInputStream;
import org.apache.commons.io.input.DemuxInputStream;
import org.apache.commons.io.input.InfiniteCircularInputStream;
import org.apache.commons.io.input.MarkShieldInputStream;
import org.apache.commons.io.input.MemoryMappedFileInputStream;
import org.apache.commons.io.input.MessageDigestInputStream;
import org.apache.commons.io.input.NullInputStream;
import org.apache.commons.io.input.QueueInputStream;
import org.apache.commons.io.input.ReadAheadInputStream;
import org.apache.commons.io.input.SwappedDataInputStream;
import org.apache.commons.io.input.TaggedInputStream;
import org.apache.commons.io.input.TeeInputStream;
import org.apache.commons.io.input.UncheckedFilterInputStream;
import org.apache.commons.io.input.UnixLineEndingInputStream;
import org.apache.commons.io.input.UnsynchronizedBufferedInputStream;
import org.apache.commons.io.input.UnsynchronizedByteArrayInputStream;
import org.apache.commons.io.input.UnsynchronizedFilterInputStream;
import org.apache.commons.io.input.WindowsLineEndingInputStream;
import org.apache.commons.io.input.buffer.PeekableInputStream;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

/**
 * This fuzzer targets the read method of different InputStream implementation classes in the input
 * or input.buffer packages.
 */
public class InputStreamFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      InputStream is = null;
      Integer size = data.remainingBytes();
      Boolean boolValue = data.consumeBoolean();
      Integer choice = data.consumeInt(1, 29);
      byte[] srcBuffer = data.consumeRemainingAsBytes();
      InputStream bais = new ByteArrayInputStream(srcBuffer);

      // Randomly create an InputStream implementation object
      switch (choice) {
        case 1:
          is = new PeekableInputStream(bais);
          ((PeekableInputStream) is).peek(srcBuffer);
          break;
        case 2:
          is = AutoCloseInputStream.builder().setInputStream(bais).get();
          break;
        case 3:
          is =
              BOMInputStream.builder()
                  .setInputStream(bais)
                  .setByteOrderMarks()
                  .setInclude(boolValue)
                  .get();
          break;
        case 4:
          is = new BoundedInputStream(bais);
          break;
        case 5:
          is = BrokenInputStream.INSTANCE;
          break;
        case 6:
          is =
              CharSequenceInputStream.builder()
                  .setInputStream(bais)
                  .setCharset(Charset.defaultCharset())
                  .get();
          break;
        case 7:
          is = new CircularInputStream(srcBuffer, (long) srcBuffer.length);
          break;
        case 8:
          is = new ClassLoaderObjectInputStream(InputStreamFuzzer.class.getClassLoader(), bais);
          break;
        case 9:
          is = CloseShieldInputStream.wrap(bais);
          break;
        case 10:
          is = ClosedInputStream.INSTANCE;
          break;
        case 11:
          is = new CountingInputStream(bais);
          break;
        case 12:
          is = new DemuxInputStream().bindStream(bais);
          break;
        case 13:
          is = new InfiniteCircularInputStream(srcBuffer);
          break;
        case 14:
          is = new MarkShieldInputStream(bais);
          break;
        case 15:
          is = MemoryMappedFileInputStream.builder().setInputStream(bais).get();
          break;
        case 16:
          is =
              MessageDigestInputStream.builder()
                  .setInputStream(bais)
                  .setMessageDigest("SHA-256")
                  .get();
          break;
        case 17:
          is = new NullInputStream();
          break;
        case 18:
          is =
              QueueInputStream.builder()
                  .setInputStream(bais)
                  .setBlockingQueue(null)
                  .setTimeout(null)
                  .get();
          break;
        case 19:
          is = ReadAheadInputStream.builder().setInputStream(bais).get();
          break;
        case 20:
          is = new SwappedDataInputStream(bais);
          break;
        case 21:
          is = new TaggedInputStream(bais);
          break;
        case 22:
          OutputStream baos = new ByteArrayOutputStream(srcBuffer.length);
          is = new TeeInputStream(bais, baos, boolValue);
          break;
        case 23:
          is = UncheckedFilterInputStream.builder().setInputStream(bais).get();
          break;
        case 24:
          is = new UnixLineEndingInputStream(bais, boolValue);
          break;
        case 25:
          is = UnsynchronizedBufferedInputStream.builder().setInputStream(bais).get();
          break;
        case 26:
          is = UnsynchronizedByteArrayInputStream.builder().setByteArray(srcBuffer).get();
          break;
        case 27:
          is = UnsynchronizedFilterInputStream.builder().setByteArray(srcBuffer).get();
          break;
        case 28:
          is = new WindowsLineEndingInputStream(bais, boolValue);
          break;
        case 29:
          is = new ValidatingObjectInputStream(bais);
          break;
      }

      if (is != null) {
        // Fuzz the read method of the created InputStream object
        byte[] buffer = new byte[size + 1];
        is.reset();
        if (is.available() > 0) {
          is.read(buffer, 0, size + 1);
        }
        is.close();
      }
    } catch (IOException
        | IllegalArgumentException
        | NoSuchAlgorithmException
        | UnsupportedOperationException e) {
      // Known exception
    }
  }
}
