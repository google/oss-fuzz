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
import com.fasterxml.jackson.datatype.eclipsecollections.EclipseCollectionsModule;
import java.io.IOException;
import org.eclipse.collections.api.map.ImmutableMap;
import org.eclipse.collections.api.map.MapIterable;
import org.eclipse.collections.api.map.MutableMap;
import org.eclipse.collections.api.map.MutableMapIterable;
import org.eclipse.collections.impl.factory.Maps;
import org.eclipse.collections.impl.factory.Sets;
import org.eclipse.collections.impl.factory.primitive.BooleanLists;
import org.eclipse.collections.impl.factory.primitive.ByteLists;
import org.eclipse.collections.impl.factory.primitive.CharLists;
import org.eclipse.collections.impl.factory.primitive.DoubleLists;
import org.eclipse.collections.impl.factory.primitive.FloatLists;
import org.eclipse.collections.impl.factory.primitive.IntLists;
import org.eclipse.collections.impl.factory.primitive.IntObjectMaps;
import org.eclipse.collections.impl.factory.primitive.LongLists;
import org.eclipse.collections.impl.factory.primitive.ShortLists;

/** This fuzzer targets the serialization methods of eclipse collections object */
public class EclipseCollectionsSerializerFuzzer {
  private static ObjectMapper mapper;

  public static void fuzzerInitialize() {
    // Register the EclipseCollectionsModule for the serialization
    mapper = new ObjectMapper().registerModule(new EclipseCollectionsModule());
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Fuzz the serialize methods for different eclipse collections object
      Integer listSize = data.consumeInt(1, 10);
      switch (data.consumeInt(1, 22)) {
        case 1:
          boolean[] boolArray = data.consumeBooleans(listSize);
          mapper.writeValueAsString(BooleanLists.immutable.of(boolArray));
          mapper.writeValueAsString(
              new PrimitiveIterativeObject(BooleanLists.immutable.of(boolArray)));
          break;
        case 2:
          byte[] byteArray = data.consumeRemainingAsBytes();
          mapper.writeValueAsString(ByteLists.immutable.of(byteArray));
          mapper.writeValueAsString(
              new PrimitiveIterativeObject(ByteLists.immutable.of(byteArray)));
          break;
        case 3:
          mapper =
              mapper.configure(
                  SerializationFeature.WRITE_CHAR_ARRAYS_AS_JSON_ARRAYS, data.consumeBoolean());
          char[] charArray = data.consumeRemainingAsString().toCharArray();
          mapper.writeValueAsString(CharLists.immutable.of(charArray));
          mapper.writeValueAsString(
              new PrimitiveIterativeObject(CharLists.immutable.of(charArray)));
          break;
        case 4:
          double[] doubleArray = new double[listSize];
          for (int i = 0; i < doubleArray.length; i++) {
            doubleArray[i] = data.consumeDouble();
          }
          mapper.writeValueAsString(DoubleLists.immutable.of(doubleArray));
          mapper.writeValueAsString(
              new PrimitiveIterativeObject(DoubleLists.immutable.of(doubleArray)));
          break;
        case 5:
          float[] floatArray = new float[listSize];
          for (int i = 0; i < floatArray.length; i++) {
            floatArray[i] = data.consumeFloat();
          }
          mapper.writeValueAsString(FloatLists.immutable.of(floatArray));
          mapper.writeValueAsString(
              new PrimitiveIterativeObject(FloatLists.immutable.of(floatArray)));
          break;
        case 6:
          int[] intArray = data.consumeInts(listSize);
          mapper.writeValueAsString(IntLists.immutable.of(intArray));
          mapper.writeValueAsString(new PrimitiveIterativeObject(IntLists.immutable.of(intArray)));
          break;
        case 7:
          long[] longArray = data.consumeLongs(listSize);
          mapper.writeValueAsString(LongLists.immutable.of(longArray));
          mapper.writeValueAsString(
              new PrimitiveIterativeObject(LongLists.immutable.of(longArray)));
          break;
        case 8:
          short[] shortArray = data.consumeShorts(listSize);
          mapper.writeValueAsString(ShortLists.immutable.of(shortArray));
          mapper.writeValueAsString(
              new PrimitiveIterativeObject(ShortLists.immutable.of(shortArray)));
          break;
        case 9:
          mapper.writeValueAsString(Sets.immutable.of(data.consumeRemainingAsString()));
          break;
        case 10:
          mapper.writeValueAsString(Sets.immutable.of(data.consumeRemainingAsBytes()));
          break;
        case 11:
          mapper
              .writerFor(MutableMap.class)
              .writeValueAsString(Maps.mutable.of(0, data.consumeRemainingAsString()));
          break;
        case 12:
          mapper
              .writerFor(MutableMap.class)
              .writeValueAsString(Maps.mutable.of(0, data.consumeRemainingAsBytes()));
          break;
        case 13:
          mapper
              .writerFor(ImmutableMap.class)
              .writeValueAsString(Maps.immutable.of(0, data.consumeRemainingAsString()));
          break;
        case 14:
          mapper
              .writerFor(ImmutableMap.class)
              .writeValueAsString(Maps.immutable.of(0, data.consumeRemainingAsBytes()));
          break;
        case 15:
          mapper
              .writerFor(MapIterable.class)
              .writeValueAsString(Maps.immutable.of(0, data.consumeRemainingAsString()));
          break;
        case 16:
          mapper
              .writerFor(MapIterable.class)
              .writeValueAsString(Maps.immutable.of(0, data.consumeRemainingAsBytes()));
          break;
        case 17:
          mapper
              .writerFor(MutableMapIterable.class)
              .writeValueAsString(Maps.mutable.of(0, data.consumeRemainingAsString()));
          break;
        case 18:
          mapper
              .writerFor(MutableMapIterable.class)
              .writeValueAsString(Maps.mutable.of(0, data.consumeRemainingAsBytes()));
          break;
        case 19:
          mapper.writeValueAsString(Maps.immutable.of(0, data.consumeRemainingAsString()));
          break;
        case 20:
          mapper.writeValueAsString(Maps.immutable.of(0, data.consumeRemainingAsBytes()));
          break;
        case 21:
          mapper.writeValueAsString(IntObjectMaps.immutable.of(0, data.consumeRemainingAsString()));
          break;
        case 22:
          mapper.writeValueAsString(IntObjectMaps.immutable.of(0, data.consumeRemainingAsBytes()));
          break;
      }
    } catch (IOException e) {
      // Known exception
    }
  }

  private static class PrimitiveIterativeObject {
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    Object object;

    public PrimitiveIterativeObject(Object object) {
      this.object = object;
    }
  }
}
