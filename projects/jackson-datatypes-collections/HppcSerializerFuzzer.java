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
import com.carrotsearch.hppc.BitSet;
import com.carrotsearch.hppc.ByteArrayList;
import com.carrotsearch.hppc.CharArrayList;
import com.carrotsearch.hppc.CharHashSet;
import com.carrotsearch.hppc.DoubleArrayList;
import com.carrotsearch.hppc.FloatArrayList;
import com.carrotsearch.hppc.IntArrayList;
import com.carrotsearch.hppc.IntHashSet;
import com.carrotsearch.hppc.LongArrayList;
import com.carrotsearch.hppc.LongHashSet;
import com.carrotsearch.hppc.ShortArrayList;
import com.carrotsearch.hppc.ShortHashSet;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.hppc.HppcModule;
import java.io.IOException;

/** This fuzzer targets the serialization methods of Hppc objects */
public class HppcSerializerFuzzer {
  private static ObjectMapper mapper;

  public static void fuzzerInitialize() {
    // Register the HppcModule for the serialization
    mapper = new ObjectMapper().registerModule(new HppcModule());
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Fuzz the serialize methods for different Hppc objects
      Integer listSize = data.consumeInt(1, 10);
      switch (data.consumeInt(1, 8)) {
        case 1:
          byte[] byteArray = data.consumeRemainingAsBytes();
          ByteArrayList byteArrayList = new ByteArrayList();
          byteArrayList.add(byteArray);
          mapper.writeValueAsString(byteArray);
          mapper.writeValueAsString(byteArrayList);
          break;
        case 2:
          char[] charArray = data.consumeRemainingAsString().toCharArray();
          CharArrayList charArrayList = new CharArrayList();
          CharHashSet charHashSet = new CharHashSet();
          charArrayList.add(charArray);
          charHashSet.addAll(charArray);
          mapper.writeValueAsString(charArrayList);
          mapper.writeValueAsString(charHashSet);
          break;
        case 3:
          double[] doubleArray = new double[listSize];
          for (int i = 0; i < doubleArray.length; i++) {
            doubleArray[i] = data.consumeDouble();
          }
          DoubleArrayList doubleArrayList = new DoubleArrayList();
          doubleArrayList.add(doubleArray);
          mapper.writeValueAsString(doubleArrayList);
          break;
        case 4:
          float[] floatArray = new float[listSize];
          for (int i = 0; i < floatArray.length; i++) {
            floatArray[i] = data.consumeFloat();
          }
          FloatArrayList floatArrayList = new FloatArrayList();
          floatArrayList.add(floatArray);
          mapper.writeValueAsString(floatArrayList);
          break;
        case 5:
          int[] intArray = data.consumeInts(listSize);
          IntArrayList intArrayList = new IntArrayList();
          IntHashSet intHashSet = new IntHashSet();
          intArrayList.add(intArray);
          intHashSet.addAll(intArray);
          mapper.writeValueAsString(intArrayList);
          mapper.writeValueAsString(intHashSet);
          break;
        case 6:
          long[] longArray = data.consumeLongs(listSize);
          LongArrayList longArrayList = new LongArrayList();
          LongHashSet longHashSet = new LongHashSet();
          longArrayList.add(longArray);
          longHashSet.addAll(longArray);
          mapper.writeValueAsString(longArrayList);
          mapper.writeValueAsString(longHashSet);
          break;
        case 7:
          short[] shortArray = data.consumeShorts(listSize);
          ShortArrayList shortArrayList = new ShortArrayList();
          ShortHashSet shortHashSet = new ShortHashSet();
          shortArrayList.add(shortArray);
          shortHashSet.addAll(shortArray);
          mapper.writeValueAsString(shortArrayList);
          mapper.writeValueAsString(shortHashSet);
          break;
        case 8:
          BitSet bitSet = new BitSet();
          for (int i = 0; i < 5; i++) {
            bitSet.set(data.consumeInt(0, (int) bitSet.capacity()));
          }
          mapper.writeValueAsString(bitSet);
          break;
      }
    } catch (IOException e) {
      // Known exception
    }
  }
}
