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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.lang.IllegalArgumentException;
import java.lang.NullPointerException;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.JsonObjectParser;


class JsonObjectParserFuzzer {
  static String [] charsetArray = {"ISO-8859-1", "US-ASCII", "UTF-16", "UTF-16BE", "UTF-16LE", "UTF-8"};

  @FuzzTest
  void myFuzzTest(FuzzedDataProvider data) {  
    Charset charset = Charset.forName(data.pickValue(charsetArray));
    boolean readLeniency = data.consumeBoolean();
    String input = data.consumeRemainingAsString();

    try {
      JsonObjectParser parser = new JsonObjectParser(GsonFactory.builder().setReadLeniency(readLeniency).build());
      InputStream inputStream = new ByteArrayInputStream(input.getBytes(charset));
      GenericJson json = parser.parseAndClose(inputStream, charset, GenericJson.class);
    } catch (IOException | IllegalArgumentException | NullPointerException e) {
    }
    
  }
}