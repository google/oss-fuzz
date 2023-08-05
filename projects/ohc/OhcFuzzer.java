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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.concurrent.ExecutionException;
import org.caffinitas.ohc.CacheLoader;
import org.caffinitas.ohc.CacheSerializer;
import org.caffinitas.ohc.OHCache;
import org.caffinitas.ohc.OHCacheBuilder;
import org.caffinitas.ohc.PermanentLoadException;

public class OhcFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    int[] choices = data.consumeInts(data.consumeInt(1, 10));

    try {
      CacheSerializer<String> serializer = new CacheSerializerImpl();
      CacheLoader<String, String> loader = new CacheLoaderImpl();
      ReadableByteChannel rbc = new ReadableByteChannelImpl();
      WritableByteChannel wbc = new WritableByteChannelImpl();

      OHCacheBuilder<String, String> builder = OHCacheBuilder.newBuilder();
      OHCache ohCache = builder.keySerializer(serializer)
                            .valueSerializer(serializer)
                            .chunkSize(data.consumeInt())
                            .build();

      for (Integer choice : choices) {
        switch (choice % 17) {
          case 0:
            ohCache.getDirect(data.consumeString(data.remainingBytes() / 2));
            break;
          case 1:
            ohCache.get(data.consumeString(data.remainingBytes() / 2));
            break;
          case 2:
            ohCache.containsKey(data.consumeString(data.remainingBytes() / 2));
            break;
          case 3:
            ohCache.put(data.consumeString(data.remainingBytes() / 2),
                data.consumeString(data.remainingBytes() / 2), data.consumeLong());
            break;
          case 4:
            ohCache.addOrReplace(data.consumeString(data.remainingBytes() / 2),
                data.consumeString(data.remainingBytes() / 2),
                data.consumeString(data.remainingBytes() / 2), data.consumeLong());
            break;
          case 5:
            ohCache.putIfAbsent(data.consumeString(data.remainingBytes() / 2),
                data.consumeString(data.remainingBytes() / 2), data.consumeLong());
            break;
          case 6:
            ohCache.remove(data.consumeString(data.remainingBytes() / 2));
            break;
          case 7:
            ((CacheLoaderImpl) loader).setString(data.consumeString(data.remainingBytes() / 2));
            ohCache.getWithLoader(data.consumeString(data.remainingBytes() / 2), loader);
            break;
          case 8:
            ohCache.stats();
            break;
          case 9:
            ohCache.getBucketHistogram();
            break;
          case 10:
            ohCache.hotKeyIterator(data.consumeInt());
            break;
          case 11:
            ohCache.serializeEntry(data.consumeString(data.remainingBytes() / 2), wbc);
            break;
          case 12:
            ohCache.serializeHotNEntries(data.consumeInt(), wbc);
            break;
          case 13:
            ohCache.serializeHotNKeys(data.consumeInt(), wbc);
            break;
          case 14:
            ((ReadableByteChannelImpl) rbc).setBytes(data.consumeBytes(data.remainingBytes() / 2));
            ohCache.deserializeKeys(rbc);
            break;
          case 15:
            ((ReadableByteChannelImpl) rbc).setBytes(data.consumeBytes(data.remainingBytes() / 2));
            ohCache.deserializeEntry(rbc);
            break;
          case 16:
            ((ReadableByteChannelImpl) rbc).setBytes(data.consumeBytes(data.remainingBytes() / 2));
            ohCache.deserializeEntries(rbc);
            break;
        }
      }
      rbc.close();
      wbc.close();
      ohCache.close();
    } catch (IllegalArgumentException | UnsupportedOperationException | IOException
        | InterruptedException | ExecutionException | IllegalStateException e) {
      // Known exception
    }
  }

  private static class CacheSerializerImpl implements CacheSerializer<String> {
    @Override
    public void serialize(String s, ByteBuffer out) {
      out.put(s.getBytes());
    }

    @Override
    public String deserialize(ByteBuffer in) {
      byte[] byteArray = new byte[in.capacity()];
      in.get(byteArray);
      return new String(byteArray);
    }

    @Override
    public int serializedSize(String s) {
      return s.length();
    }
  }

  private static class CacheLoaderImpl implements CacheLoader<String, String> {
    private String string;

    public void setString(String string) {
      this.string = string;
    }

    @Override
    public String load(String key) throws PermanentLoadException, Exception {
      return string;
    }
  }

  private static class ReadableByteChannelImpl implements ReadableByteChannel {
    private byte[] bytes;
    private Boolean open = true;

    public void setBytes(byte[] bytes) {
      this.bytes = bytes;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
      if (bytes.length > dst.remaining()) {
        return -1;
      }

      dst.put(bytes);
      return bytes.length;
    }

    @Override
    public boolean isOpen() {
      return open;
    }

    @Override
    public void close() throws IOException {
      open = false;
    }
  }

  private static class WritableByteChannelImpl implements WritableByteChannel {
    private Boolean open = true;

    @Override
    public int write(ByteBuffer src) throws IOException {
      return 0;
    }

    @Override
    public boolean isOpen() {
      return open;
    }

    @Override
    public void close() throws IOException {
      open = false;
    }
  }
}
