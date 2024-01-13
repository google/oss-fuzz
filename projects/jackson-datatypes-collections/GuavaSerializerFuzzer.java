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
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.guava.GuavaModule;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.FluentIterable;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableRangeSet;
import com.google.common.collect.ImmutableTable;
import com.google.common.collect.LinkedHashMultiset;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multiset;
import com.google.common.collect.Range;
import com.google.common.collect.RangeSet;
import com.google.common.collect.TreeRangeSet;
import com.google.common.hash.HashCode;
import com.google.common.net.HostAndPort;
import com.google.common.net.InternetDomainName;
import com.google.common.primitives.Bytes;
import java.io.IOException;

/** This fuzzer targets the serialization methods of Guava objects */
public class GuavaSerializerFuzzer {
  private static ObjectMapper mapper;

  public static void fuzzerInitialize() {
    // Register the GuavaModule for the serialization
    GuavaModule module = new GuavaModule();
    module.configureAbsentsAsNulls(false);
    mapper = new ObjectMapper().registerModule(module);
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Fuzz the serialize methods for different Guava objects
      Integer listSize = data.consumeInt(1, 10);
      switch (data.consumeInt(1, 12)) {
        case 1:
          Cache<String, String> cache = CacheBuilder.newBuilder().build();
          cache.put(data.consumeString(data.remainingBytes()), data.consumeRemainingAsString());
          mapper.enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
          mapper.writeValueAsString(cache);
          break;
        case 2:
          byte[] bytes = data.consumeRemainingAsBytes();
          Byte[] byteArray = new Byte[bytes.length];
          for (int i = 0; i < bytes.length; i++) {
            byteArray[i] = bytes[i];
          }
          FluentIterable fluentIterable = FluentIterable.from(byteArray);
          mapper.writeValueAsString(fluentIterable);
          break;
        case 3:
          HashCode hashCode = HashCode.fromString(data.consumeRemainingAsString());
          mapper.writeValueAsString(hashCode);
          break;
        case 4:
          HostAndPort hostAndPort =
              HostAndPort.fromParts(
                  data.consumeString(data.remainingBytes()), data.consumeInt(1, 65536));
          mapper.writeValueAsString(hostAndPort);
          break;
        case 5:
          Multimap<String, byte[]> multimap = HashMultimap.create();
          multimap.put(data.consumeString(data.remainingBytes()), data.consumeRemainingAsBytes());
          mapper
              .writer()
              .without(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
              .writeValueAsString(multimap);
          break;
        case 6:
          InternetDomainName internetDomainName =
              InternetDomainName.from(data.consumeRemainingAsString());
          mapper.writeValueAsString(internetDomainName);
          break;
        case 7:
          ImmutableTable.Builder<Integer, String, String> immutableTableBuilder =
              ImmutableTable.builder();
          immutableTableBuilder.put(
              data.consumeInt(1, 10),
              data.consumeString(data.remainingBytes()),
              data.consumeRemainingAsString());
          ImmutableTable<Integer, String, String> immutableTable = immutableTableBuilder.build();
          mapper.writeValueAsString(immutableTable);
          break;
        case 8:
          Multiset<String> multiSet = LinkedHashMultiset.create();
          multiSet.add(data.consumeRemainingAsString());
          mapper.writeValueAsString(multiSet);
          break;
        case 9:
          RangeSet<Integer> rangeSet = TreeRangeSet.create();
          rangeSet.add(Range.closedOpen(data.consumeInt(), data.consumeInt()));
          rangeSet.add(Range.openClosed(data.consumeInt(), data.consumeInt()));
          rangeSet.add(Range.all());
          mapper.writeValueAsString(rangeSet);
          break;
        case 10:
          ImmutableRangeSet<Integer> immutableRangeSet =
              ImmutableRangeSet.<Integer>builder()
                  .add(Range.closedOpen(data.consumeInt(), data.consumeInt()))
                  .add(Range.openClosed(data.consumeInt(), data.consumeInt()))
                  .add(Range.all())
                  .build();
          mapper.writeValueAsString(immutableRangeSet);
        case 11:
          mapper.writeValueAsString(Bytes.asList(data.consumeRemainingAsBytes()).iterator());
        case 12:
          ArrayListMultimap<String, Object> arrayListMultimap = ArrayListMultimap.create();
          arrayListMultimap.put(
              data.consumeString(data.remainingBytes()), data.consumeRemainingAsString());
          ArrayListMultimapContainer container = new ArrayListMultimapContainer(arrayListMultimap);
          mapper.writeValueAsString(container);
      }
    } catch (IOException | IllegalArgumentException e) {
      // Known exception
    }
  }

  private static class ArrayListMultimapContainer {
    @JsonTypeInfo(include = JsonTypeInfo.As.PROPERTY, use = JsonTypeInfo.Id.CLASS)
    public Object object;

    public ArrayListMultimapContainer(Object object) {
      this.object = object;
    }
  }
}
