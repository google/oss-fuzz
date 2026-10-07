// Copyright 2024 Google LLC
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
import org.joda.convert.StringConvert;
import org.joda.convert.factory.ByteObjectArrayStringConverterFactory;
import java.util.Arrays;

public class StringConvertFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try{
      StringConvert test = new StringConvert(data.consumeBoolean(), ByteObjectArrayStringConverterFactory.INSTANCE);
      Byte[] array = test.convertFromString(Byte[].class, data.consumeRemainingAsString());
      test.convertToString(array);
      test.convertToString(Byte[].class, array);
      test.convertFromString(Byte[].class, test.convertToString(array));
    }
    catch (java.lang.NumberFormatException e){}
    catch (java.lang.IllegalArgumentException e){}
  }
}