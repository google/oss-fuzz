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
import org.apache.commons.lang3.ArrayFill;
import org.apache.commons.lang3.ArraySorter;
import org.apache.commons.lang3.ArrayUtils;

/** This fuzzer targets the methods of the ArrayUtils class in the base package. */
public class ArrayUtilsFuzzer {
  private static boolean[] boolArray;
  private static byte[] byteArray;
  private static char[] charArray;
  private static double[] doubleArray;
  private static float[] floatArray;
  private static int[] intArray;
  private static long[] longArray;
  private static short[] shortArray;
  private static String[] strArray;

  public static void fuzzerInitialize() {
    boolArray = new boolean[1];
    byteArray = new byte[1];
    charArray = new char[1];
    doubleArray = new double[1];
    floatArray = new float[1];
    intArray = new int[1];
    longArray = new long[1];
    shortArray = new short[1];
    strArray = new String[1];
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      cleanLargeArray();

      for (Integer count = 0; count < data.consumeInt(1, 10); count++) {
        switch (data.consumeInt(1, 143)) {
          case 1:
            ArrayUtils.add(boolArray, data.consumeBoolean());
            break;
          case 2:
            ArrayUtils.add(byteArray, data.consumeByte());
            break;
          case 3:
            ArrayUtils.add(charArray, data.consumeChar());
            break;
          case 4:
            ArrayUtils.add(doubleArray, data.consumeDouble());
            break;
          case 5:
            ArrayUtils.add(floatArray, data.consumeFloat());
            break;
          case 6:
            ArrayUtils.add(intArray, data.consumeInt());
            break;
          case 7:
            ArrayUtils.add(longArray, data.consumeLong());
            break;
          case 8:
            ArrayUtils.add(shortArray, data.consumeShort());
            break;
          case 9:
            ArrayUtils.add(strArray, data.consumeString(10));
            break;
          case 10:
            ArrayUtils.addAll(boolArray, data.consumeBoolean());
            break;
          case 11:
            ArrayUtils.addAll(byteArray, data.consumeByte());
            break;
          case 12:
            ArrayUtils.addAll(charArray, data.consumeChar());
            break;
          case 13:
            ArrayUtils.addAll(doubleArray, data.consumeDouble());
            break;
          case 14:
            ArrayUtils.addAll(floatArray, data.consumeFloat());
            break;
          case 15:
            ArrayUtils.addAll(intArray, data.consumeInt());
            break;
          case 16:
            ArrayUtils.addAll(longArray, data.consumeLong());
            break;
          case 17:
            ArrayUtils.addAll(shortArray, data.consumeShort());
            break;
          case 18:
            ArrayUtils.addAll(strArray, data.consumeString(10));
            break;
          case 19:
            ArrayUtils.addFirst(boolArray, data.consumeBoolean());
            break;
          case 20:
            ArrayUtils.addFirst(byteArray, data.consumeByte());
            break;
          case 21:
            ArrayUtils.addFirst(charArray, data.consumeChar());
            break;
          case 22:
            ArrayUtils.addFirst(doubleArray, data.consumeDouble());
            break;
          case 23:
            ArrayUtils.addFirst(floatArray, data.consumeFloat());
            break;
          case 24:
            ArrayUtils.addFirst(intArray, data.consumeInt());
            break;
          case 25:
            ArrayUtils.addFirst(longArray, data.consumeLong());
            break;
          case 26:
            ArrayUtils.addFirst(shortArray, data.consumeShort());
            break;
          case 27:
            ArrayUtils.addFirst(strArray, data.consumeString(10));
            break;
          case 28:
            ArrayUtils.reverse(boolArray);
            break;
          case 29:
            ArrayUtils.reverse(byteArray);
            break;
          case 30:
            ArrayUtils.reverse(charArray);
            break;
          case 31:
            ArrayUtils.reverse(doubleArray);
            break;
          case 32:
            ArrayUtils.reverse(floatArray);
            break;
          case 33:
            ArrayUtils.reverse(intArray);
            break;
          case 34:
            ArrayUtils.reverse(longArray);
            break;
          case 35:
            ArrayUtils.reverse(shortArray);
            break;
          case 36:
            ArrayUtils.reverse(strArray);
            break;
          case 37:
            ArrayUtils.shift(boolArray, 10);
            break;
          case 38:
            ArrayUtils.shift(byteArray, 10);
            break;
          case 39:
            ArrayUtils.shift(charArray, 10);
            break;
          case 40:
            ArrayUtils.shift(doubleArray, 10);
            break;
          case 41:
            ArrayUtils.shift(floatArray, 10);
            break;
          case 42:
            ArrayUtils.shift(intArray, 10);
            break;
          case 43:
            ArrayUtils.shift(longArray, 10);
            break;
          case 44:
            ArrayUtils.shift(shortArray, 10);
            break;
          case 45:
            ArrayUtils.shift(strArray, 10);
            break;
          case 46:
            ArrayUtils.shuffle(boolArray);
            break;
          case 47:
            ArrayUtils.shuffle(byteArray);
            break;
          case 48:
            ArrayUtils.shuffle(charArray);
            break;
          case 49:
            ArrayUtils.shuffle(doubleArray);
            break;
          case 50:
            ArrayUtils.shuffle(floatArray);
            break;
          case 51:
            ArrayUtils.shuffle(intArray);
            break;
          case 52:
            ArrayUtils.shuffle(longArray);
            break;
          case 53:
            ArrayUtils.shuffle(shortArray);
            break;
          case 54:
            ArrayUtils.shuffle(strArray);
            break;
          case 55:
            ArrayUtils.swap(boolArray, 0, 1);
            break;
          case 56:
            ArrayUtils.swap(byteArray, 0, 1);
            break;
          case 57:
            ArrayUtils.swap(charArray, 0, 1);
            break;
          case 58:
            ArrayUtils.swap(doubleArray, 0, 1);
            break;
          case 59:
            ArrayUtils.swap(floatArray, 0, 1);
            break;
          case 60:
            ArrayUtils.swap(intArray, 0, 1);
            break;
          case 61:
            ArrayUtils.swap(longArray, 0, 1);
            break;
          case 62:
            ArrayUtils.swap(shortArray, 0, 1);
            break;
          case 63:
            ArrayUtils.swap(strArray, 0, 1);
            break;
          case 64:
            ArrayUtils.toPrimitive(ArrayUtils.toObject(boolArray));
            break;
          case 65:
            ArrayUtils.toPrimitive(ArrayUtils.toObject(byteArray));
            break;
          case 66:
            ArrayUtils.toPrimitive(ArrayUtils.toObject(charArray));
            break;
          case 67:
            ArrayUtils.toPrimitive(ArrayUtils.toObject(doubleArray));
            break;
          case 68:
            ArrayUtils.toPrimitive(ArrayUtils.toObject(floatArray));
            break;
          case 69:
            ArrayUtils.toPrimitive(ArrayUtils.toObject(intArray));
            break;
          case 70:
            ArrayUtils.toPrimitive(ArrayUtils.toObject(longArray));
            break;
          case 71:
            ArrayUtils.toPrimitive(ArrayUtils.toObject(shortArray));
            break;
          case 72:
            ArrayUtils.removeElement(boolArray, data.consumeBoolean());
            break;
          case 73:
            ArrayUtils.removeElement(byteArray, data.consumeByte());
            break;
          case 74:
            ArrayUtils.removeElement(charArray, data.consumeChar());
            break;
          case 75:
            ArrayUtils.removeElement(doubleArray, data.consumeDouble());
            break;
          case 76:
            ArrayUtils.removeElement(floatArray, data.consumeFloat());
            break;
          case 77:
            ArrayUtils.removeElement(intArray, data.consumeInt());
            break;
          case 78:
            ArrayUtils.removeElement(longArray, data.consumeLong());
            break;
          case 79:
            ArrayUtils.removeElement(shortArray, data.consumeShort());
            break;
          case 80:
            ArrayUtils.removeElement(strArray, data.consumeString(10));
            break;
          case 81:
            ArrayUtils.subarray(boolArray, 0, 1);
            break;
          case 82:
            ArrayUtils.subarray(byteArray, 0, 1);
            break;
          case 83:
            ArrayUtils.subarray(charArray, 0, 1);
            break;
          case 84:
            ArrayUtils.subarray(doubleArray, 0, 1);
            break;
          case 85:
            ArrayUtils.subarray(floatArray, 0, 1);
            break;
          case 86:
            ArrayUtils.subarray(intArray, 0, 1);
            break;
          case 87:
            ArrayUtils.subarray(longArray, 0, 1);
            break;
          case 88:
            ArrayUtils.subarray(shortArray, 0, 1);
            break;
          case 89:
            ArrayUtils.subarray(strArray, 0, 1);
            break;
          case 90:
            ArrayUtils.contains(boolArray, data.consumeBoolean());
            break;
          case 91:
            ArrayUtils.contains(byteArray, data.consumeByte());
            break;
          case 92:
            ArrayUtils.contains(charArray, data.consumeChar());
            break;
          case 93:
            ArrayUtils.contains(doubleArray, data.consumeDouble());
            break;
          case 94:
            ArrayUtils.contains(floatArray, data.consumeFloat());
            break;
          case 95:
            ArrayUtils.contains(intArray, data.consumeInt());
            break;
          case 96:
            ArrayUtils.contains(longArray, data.consumeLong());
            break;
          case 97:
            ArrayUtils.contains(shortArray, data.consumeShort());
            break;
          case 98:
            ArrayUtils.contains(strArray, data.consumeString(10));
            break;
          case 99:
            ArrayUtils.indexesOf(boolArray, data.consumeBoolean());
            break;
          case 100:
            ArrayUtils.indexesOf(byteArray, data.consumeByte());
            break;
          case 101:
            ArrayUtils.indexesOf(charArray, data.consumeChar());
            break;
          case 102:
            ArrayUtils.indexesOf(doubleArray, data.consumeDouble());
            break;
          case 103:
            ArrayUtils.indexesOf(floatArray, data.consumeFloat());
            break;
          case 104:
            ArrayUtils.indexesOf(intArray, data.consumeInt());
            break;
          case 105:
            ArrayUtils.indexesOf(longArray, data.consumeLong());
            break;
          case 106:
            ArrayUtils.indexesOf(shortArray, data.consumeShort());
            break;
          case 107:
            ArrayUtils.indexesOf(strArray, data.consumeString(10));
            break;
          case 108:
            ArrayUtils.isSorted(boolArray);
            break;
          case 109:
            ArrayUtils.isSorted(byteArray);
            break;
          case 110:
            ArrayUtils.isSorted(charArray);
            break;
          case 111:
            ArrayUtils.isSorted(doubleArray);
            break;
          case 112:
            ArrayUtils.isSorted(floatArray);
            break;
          case 113:
            ArrayUtils.isSorted(intArray);
            break;
          case 114:
            ArrayUtils.isSorted(longArray);
            break;
          case 115:
            ArrayUtils.isSorted(shortArray);
            break;
          case 116:
            ArrayUtils.isSorted(strArray);
            break;
          case 117:
            ArrayUtils.lastIndexOf(boolArray, data.consumeBoolean());
            break;
          case 118:
            ArrayUtils.lastIndexOf(byteArray, data.consumeByte());
            break;
          case 119:
            ArrayUtils.lastIndexOf(charArray, data.consumeChar());
            break;
          case 120:
            ArrayUtils.lastIndexOf(doubleArray, data.consumeDouble());
            break;
          case 121:
            ArrayUtils.lastIndexOf(floatArray, data.consumeFloat());
            break;
          case 122:
            ArrayUtils.lastIndexOf(intArray, data.consumeInt());
            break;
          case 123:
            ArrayUtils.lastIndexOf(longArray, data.consumeLong());
            break;
          case 124:
            ArrayUtils.lastIndexOf(shortArray, data.consumeShort());
            break;
          case 125:
            ArrayUtils.lastIndexOf(strArray, data.consumeString(10));
            break;
          case 126:
            ArrayUtils.removeAllOccurrences(boolArray, data.consumeBoolean());
            break;
          case 127:
            ArrayUtils.removeAllOccurrences(byteArray, data.consumeByte());
            break;
          case 128:
            ArrayUtils.removeAllOccurrences(charArray, data.consumeChar());
            break;
          case 129:
            ArrayUtils.removeAllOccurrences(doubleArray, data.consumeDouble());
            break;
          case 130:
            ArrayUtils.removeAllOccurrences(floatArray, data.consumeFloat());
            break;
          case 131:
            ArrayUtils.removeAllOccurrences(intArray, data.consumeInt());
            break;
          case 132:
            ArrayUtils.removeAllOccurrences(longArray, data.consumeLong());
            break;
          case 133:
            ArrayUtils.removeAllOccurrences(shortArray, data.consumeShort());
            break;
          case 134:
            ArrayUtils.removeAllOccurrences(strArray, data.consumeString(10));
            break;
          case 135:
            ArrayUtils.removeElements(boolArray, boolArray);
            break;
          case 136:
            ArrayUtils.removeElements(byteArray, byteArray);
            break;
          case 137:
            ArrayUtils.removeElements(charArray, charArray);
            break;
          case 138:
            ArrayUtils.removeElements(doubleArray, doubleArray);
            break;
          case 139:
            ArrayUtils.removeElements(floatArray, floatArray);
            break;
          case 140:
            ArrayUtils.removeElements(intArray, intArray);
            break;
          case 141:
            ArrayUtils.removeElements(longArray, longArray);
            break;
          case 142:
            ArrayUtils.removeElements(shortArray, shortArray);
            break;
          case 143:
            ArrayUtils.removeElements(strArray, strArray);
            break;
        }
      }
    } catch (IllegalArgumentException e) {
      // Known exception
    }
  }

  private static void cleanLargeArray() {
    if (boolArray.length > 256) {
      boolArray = new boolean[1];
    }
    if (byteArray.length > 256) {
      byteArray = new byte[1];
      ArrayFill.fill(byteArray, (byte) 0);
    }
    if (charArray.length > 256) {
      charArray = new char[1];
      ArrayFill.fill(charArray, (char) 0);
    }
    if (doubleArray.length > 256) {
      doubleArray = new double[1];
      ArrayFill.fill(doubleArray, 0d);
    }
    if (floatArray.length > 256) {
      floatArray = new float[1];
      ArrayFill.fill(floatArray, 0f);
    }
    if (intArray.length > 256) {
      intArray = new int[1];
      ArrayFill.fill(intArray, 0);
    }
    if (longArray.length > 256) {
      longArray = new long[1];
      ArrayFill.fill(longArray, 0l);
    }
    if (shortArray.length > 256) {
      shortArray = new short[1];
      ArrayFill.fill(shortArray, (short) 0);
    }
    if (strArray.length > 256) {
      strArray = new String[1];
      ArrayFill.fill(strArray, "");
    }

    sortArray();
  }

  private static void sortArray() {
    ArraySorter.sort(byteArray);
    ArraySorter.sort(charArray);
    ArraySorter.sort(doubleArray);
    ArraySorter.sort(floatArray);
    ArraySorter.sort(intArray);
    ArraySorter.sort(longArray);
    ArraySorter.sort(shortArray);
    ArraySorter.sort(strArray);
  }
}
