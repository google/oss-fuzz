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
import org.apache.commons.lang3.reflect.ConstructorUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.lang3.reflect.InheritanceUtils;
import org.apache.commons.lang3.reflect.MethodUtils;
import org.apache.commons.lang3.reflect.TypeUtils;

/** This fuzzer targets the methods of the Utils classes in the reflect package */
public class ReflectUtilsFuzzer extends ClassFuzzerBase {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Randomly pick 2 class objects
      Class cls1 = data.pickValue(classSet);
      Class cls2 = data.pickValue(classSet);

      switch (data.consumeInt(1, 28)) {
        case 1:
          ConstructorUtils.getAccessibleConstructor(cls1, cls2);
          break;
        case 2:
          ConstructorUtils.getAccessibleConstructor(data.pickValue(cls1.getConstructors()));
          ConstructorUtils.getAccessibleConstructor(data.pickValue(cls2.getConstructors()));
          break;
        case 3:
          ConstructorUtils.getMatchingAccessibleConstructor(cls1, cls2);
          break;
        case 4:
          ConstructorUtils.invokeConstructor(cls1, cls2);
          break;
        case 5:
          ConstructorUtils.invokeExactConstructor(cls1, cls2);
          break;
        case 6:
          FieldUtils.getAllFields(cls1);
          FieldUtils.getAllFields(cls2);
          break;
        case 7:
          FieldUtils.getDeclaredField(cls1, data.consumeRemainingAsString());
          break;
        case 8:
          FieldUtils.getField(cls1, data.consumeRemainingAsString());
          break;
        case 9:
          FieldUtils.readDeclaredStaticField(cls1, data.consumeRemainingAsString());
          break;
        case 10:
          FieldUtils.readDeclaredStaticField(cls1, data.consumeRemainingAsString());
          break;
        case 11:
          FieldUtils.readField(cls1, data.consumeRemainingAsString());
          break;
        case 12:
          FieldUtils.readStaticField(cls1, data.consumeRemainingAsString());
          break;
        case 13:
          InheritanceUtils.distance(cls1, cls2);
          break;
        case 14:
          MethodUtils.getAccessibleMethod(data.pickValue(cls1.getMethods()));
          MethodUtils.getAccessibleMethod(data.pickValue(cls2.getMethods()));
          break;
        case 15:
          MethodUtils.getAccessibleMethod(cls1, data.consumeRemainingAsString(), cls2);
          break;
        case 16:
          MethodUtils.getMatchingAccessibleMethod(cls1, data.consumeRemainingAsString(), cls2);
          break;
        case 17:
          MethodUtils.getMatchingMethod(cls1, data.consumeRemainingAsString(), cls2);
          break;
        case 18:
          MethodUtils.invokeExactStaticMethod(cls1, data.consumeRemainingAsString(), cls2);
          break;
        case 19:
          MethodUtils.invokeStaticMethod(cls1, data.consumeRemainingAsString(), cls2);
          break;
        case 20:
          TypeUtils.containsTypeVariables(data.pickValue(cls1.getTypeParameters()));
          TypeUtils.containsTypeVariables(data.pickValue(cls2.getTypeParameters()));
          break;
        case 21:
          TypeUtils.equals(
              data.pickValue(cls1.getTypeParameters()), data.pickValue(cls2.getTypeParameters()));
          break;
        case 22:
          TypeUtils.genericArrayType(data.pickValue(cls1.getTypeParameters()));
          TypeUtils.genericArrayType(data.pickValue(cls2.getTypeParameters()));
          break;
        case 23:
          TypeUtils.getArrayComponentType(data.pickValue(cls1.getTypeParameters()));
          TypeUtils.getArrayComponentType(data.pickValue(cls2.getTypeParameters()));
          break;
        case 24:
          TypeUtils.getTypeArguments(data.pickValue(cls1.getTypeParameters()), cls1);
          TypeUtils.getTypeArguments(data.pickValue(cls2.getTypeParameters()), cls2);
          break;
        case 25:
          TypeUtils.isArrayType(data.pickValue(cls1.getTypeParameters()));
          TypeUtils.isArrayType(data.pickValue(cls2.getTypeParameters()));
          break;
        case 26:
          TypeUtils.isAssignable(
              data.pickValue(cls1.getTypeParameters()), data.pickValue(cls2.getTypeParameters()));
          break;
        case 27:
          TypeUtils.getTypeArguments(
              TypeUtils.parameterize(cls1, data.pickValue(cls1.getTypeParameters())));
          TypeUtils.getTypeArguments(
              TypeUtils.parameterize(cls2, data.pickValue(cls2.getTypeParameters())));
          break;
        case 28:
          TypeUtils.wrap(cls1);
          TypeUtils.wrap(cls2);
          break;
      }
    } catch (ReflectiveOperationException
        | IllegalArgumentException
        | IllegalStateException
        | LinkageError e) {
      // Known exception
    } catch (NullPointerException e) {
      // Some methods throw NullPointerException
      if (!isExpectedNullPointerException(e)) {
        // Throw unexpected NullPointerException
        throw e;
      }
    }
  }

  private static Boolean isExpectedNullPointerException(NullPointerException e) {
    final String[] expectedMessages = {"Cannot locate", "Cannot invoke"};

    Boolean result = false;
    for (String message : expectedMessages) {
      result |= e.getMessage().contains(message);
    }

    return result;
  }
}
