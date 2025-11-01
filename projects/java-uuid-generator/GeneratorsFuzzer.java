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
import com.fasterxml.uuid.EthernetAddress;
import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.UUIDUtil;
import java.util.Random;
import java.util.UUID;

public class GeneratorsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      UUID uuid = null;
      EthernetAddress addr = null;

      Integer choice = data.consumeInt(1, 7);

      switch (choice) {
        case 1:
          Generators.randomBasedGenerator(new Random(data.consumeLong())).generate();
          break;
        case 2:
          Generators.timeBasedEpochGenerator(new Random(data.consumeLong())).generate();
          break;
        case 3:
          Generators.nameBasedGenerator().generate(data.consumeRemainingAsString());
          break;
        case 4:
          uuid = UUIDUtil.uuid(data.consumeString(data.remainingBytes() / 2));
          Generators.nameBasedGenerator(uuid).generate(data.consumeRemainingAsString());
          break;
        case 5:
          uuid = UUIDUtil.uuid(data.consumeString(data.remainingBytes() / 2));
          Generators.nameBasedGenerator(uuid, null).generate(data.consumeRemainingAsString());
          break;
        case 6:
          addr = new EthernetAddress(data.consumeRemainingAsString());
          Generators.timeBasedGenerator(addr).generate();
          break;
        case 7:
          addr = new EthernetAddress(data.consumeRemainingAsString());
          Generators.timeBasedReorderedGenerator(addr).generate();
          break;
      }
    } catch (NumberFormatException e1) {
      // Known exceptions
    }
  }
}
