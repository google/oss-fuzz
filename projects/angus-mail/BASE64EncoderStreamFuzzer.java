// Copyright 2022 Google LLC
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

import java.lang.NumberFormatException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.eclipse.angus.mail.util.BASE64EncoderStream;
import org.eclipse.angus.mail.util.ASCIIUtility;

public class BASE64EncoderStreamFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    BASE64EncoderStream b64es = new BASE64EncoderStream(baos, Integer.MAX_VALUE);
    try{
      b64es.write(data.consumeRemainingAsBytes());
    }
    catch(IOException e){
      return;
    }
    
  }
}
