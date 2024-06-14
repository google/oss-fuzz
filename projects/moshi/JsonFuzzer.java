// Copyright 2021 Google LLC
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

import com.squareup.moshi.Moshi;
import com.squareup.moshi.JsonAdapter;
import com.squareup.moshi.Moshi;
import com.squareup.moshi.recipes.models.Player;
import com.squareup.moshi.JsonDataException;
import java.io.*;


public class JsonFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    Moshi moshi = new Moshi.Builder().build();
    JsonAdapter<Player> jsonAdapter = moshi.adapter(Player.class);
    try {
      jsonAdapter.fromJson(data.consumeRemainingAsString());
    }
    catch (IOException | JsonDataException e) {

    }
  }
}

