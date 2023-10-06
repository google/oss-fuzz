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
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.Base64Variant;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.io.SerializedString;

import java.io.Writer;
import java.io.StringWriter;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class ParseNextTokenFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    JsonFactory jf = new JsonFactory();
    JsonParser jp;
        
    try {
        jp = jf.createParser(data.consumeRemainingAsBytes());
        for (int i = 0;i < data.consumeInt(3, 1000); i++) {
          int execType = data.consumeInt(0, 17);
          if (execType==0) {
            InputStream myInputStream = new ByteArrayInputStream(data.consumeRemainingAsBytes());
            jp = jf.createParser(myInputStream);
          } else if(execType==1) {
            jp.nextToken();
          } else if(execType==2) {
            jp.nextTextValue();
          } else if(execType==3) {
            jp.nextBooleanValue();
          } else if(execType==4) {
            jp.nextFieldName();
          } else if(execType==5) {
            jp.nextFieldName(new SerializedString(data.consumeString(10000)));
          } else if(execType==6) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            Base64Variant orig = Base64Variants.PEM;
            jp.readBinaryValue(orig, bytes);
          } else if(execType==7) {
            String outString = jp.getValueAsString();
          } else if(execType==8) {
            int outInt = jp.getValueAsInt();
          } else if(execType==9) {
            Writer writer = new StringWriter();
            int len = jp.getText(writer);
          } else if(execType==10) {
            char[] textChars = jp.getTextCharacters();
          } else if(execType==11) {
            int textLen = jp.getTextLength();
          } else if(execType==12) {
            int textOffset = jp.getTextOffset();
          } else if(execType==13) {
            jp.getBinaryValue(Base64Variants.PEM);
          } else if(execType==14) {
            jp.nextIntValue(data.consumeInt());
          } else if(execType==15) {
            jp.nextLongValue(data.consumeLong());
          } else if(execType==16) {
            jp.finishToken();
          }
        }
    } catch (IOException | IllegalArgumentException ignored) {
  }
}
}
