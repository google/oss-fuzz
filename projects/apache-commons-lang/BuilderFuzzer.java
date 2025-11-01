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
import org.apache.commons.lang3.builder.Builder;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.DiffBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ReflectionDiffBuilder;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/** This fuzzer targets the methods of the classes in the buidler package */
public class BuilderFuzzer {
  private static final ToStringStyle[] styles = {
    ToStringStyle.DEFAULT_STYLE, ToStringStyle.JSON_STYLE,
    ToStringStyle.MULTI_LINE_STYLE, ToStringStyle.NO_CLASS_NAME_STYLE,
    ToStringStyle.NO_FIELD_NAMES_STYLE, ToStringStyle.SHORT_PREFIX_STYLE,
    ToStringStyle.SIMPLE_STYLE
  };
  private static CompareToBuilder compareTo;
  private static DiffBuilder diff;
  private static EqualsBuilder equals;
  private static HashCodeBuilder hashCode;
  private static ReflectionDiffBuilder reflectionDiff;
  private static ReflectionToStringBuilder reflectionToString;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Builder builder = null;
      ToStringStyle styleChoice = data.pickValue(styles);
      Integer choice = data.consumeInt(1, 10);
      Object obj1 = getRandomObject(data);
      Object obj2 = getRandomObject(data);

      initializeBuilder(obj1, obj2, styleChoice);

      switch (choice) {
        case 1:
          CompareToBuilder.reflectionCompare(obj1, obj2);
          break;
        case 2:
          builder = compareTo.append(Object.class.cast(obj1), Object.class.cast(obj2));
          break;
        case 3:
          builder =
              diff.append(
                  data.consumeRemainingAsString(),
                  Object.class.cast(obj1),
                  Object.class.cast(obj2));
          break;
        case 4:
          EqualsBuilder.reflectionEquals(obj1, obj2, data.consumeBoolean());
          break;
        case 5:
          builder = equals.append(Object.class.cast(obj1), Object.class.cast(obj2));
          break;
        case 6:
          HashCodeBuilder.reflectionHashCode(obj1, data.consumeBoolean());
          HashCodeBuilder.reflectionHashCode(obj2, data.consumeBoolean());
          break;
        case 7:
          builder = hashCode.append(Object.class.cast(obj1)).append(Object.class.cast(obj2));
          break;
        case 8:
          builder = reflectionDiff;
          break;
        case 9:
          ReflectionToStringBuilder.toString(obj1, styleChoice);
          ReflectionToStringBuilder.toString(obj2, styleChoice);
          break;
        case 10:
          builder = reflectionToString.reflectionAppendArray(obj1).reflectionAppendArray(obj2);
          break;
      }

      if (builder != null) {
        builder.build();
      }
    } catch (IllegalArgumentException | ClassCastException e) {
      // Known exception
    }
  }

  private static void initializeBuilder(Object obj1, Object obj2, ToStringStyle style) {
    compareTo = new CompareToBuilder();
    diff = new DiffBuilder(obj1, obj2, style);
    equals = new EqualsBuilder();
    hashCode = new HashCodeBuilder();
    reflectionDiff = new ReflectionDiffBuilder(obj1, obj2, style);
    reflectionToString = new ReflectionToStringBuilder(obj1, style);
  }

  private static Object getRandomObject(FuzzedDataProvider data) {
    Object obj = null;

    switch (data.consumeInt(1, 18)) {
      case 1:
        obj = data.consumeBoolean();
        break;
      case 2:
        obj = data.consumeBooleans(data.remainingBytes());
        break;
      case 3:
        obj = data.consumeBytes(data.remainingBytes());
        break;
      case 4:
        obj = data.consumeByte();
        break;
      case 5:
        obj = data.consumeChar();
        break;
      case 6:
        obj = data.consumeString(data.remainingBytes()).toCharArray();
        break;
      case 7:
        obj = data.consumeDouble();
        break;
      case 8:
        double[] doubleArray = new double[data.consumeInt(1, 5)];
        for (Integer i = 0; i < doubleArray.length; i++) {
          doubleArray[i] = data.consumeDouble();
        }
        obj = doubleArray;
        break;
      case 9:
        obj = data.consumeFloat();
        break;
      case 10:
        float[] floatArray = new float[data.consumeInt(1, 5)];
        for (Integer i = 0; i < floatArray.length; i++) {
          floatArray[i] = data.consumeFloat();
        }
        obj = floatArray;
        break;
      case 11:
        obj = data.consumeInt();
        break;
      case 12:
        obj = data.consumeInts(data.remainingBytes());
        break;
      case 13:
        obj = data.consumeLong();
        break;
      case 14:
        obj = data.consumeLongs(data.remainingBytes());
        break;
      case 15:
        obj = data.consumeShort();
        break;
      case 16:
        obj = data.consumeShorts(data.remainingBytes());
        break;
      case 17:
        obj = data.consumeString(data.remainingBytes());
        break;
      case 18:
        String[] strArray = new String[data.consumeInt(1, 5)];
        for (Integer i = 0; i < strArray.length; i++) {
          strArray[i] = data.consumeString(data.remainingBytes());
        }
        obj = strArray;
        break;
    }

    return obj;
  }
}
