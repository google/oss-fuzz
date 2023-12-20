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
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.csv.CsvFactory;
import com.fasterxml.jackson.dataformat.csv.CsvGenerator;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.javaprop.JavaPropsFactory;
import com.fasterxml.jackson.dataformat.javaprop.JavaPropsMapper;
import com.fasterxml.jackson.dataformat.toml.TomlFactory;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;
import com.fasterxml.jackson.dataformat.toml.TomlReadFeature;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.DateTimeException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/** This fuzzer targets the deserialization methods of YAML/TOML/JavaProps/CSV objects */
public class DeserializerFuzzer {
  private static ObjectMapper mapper;
  private static List<Class> choice;

  public static void fuzzerInitialize() {
    mapper = null;
    initializeClassChoice();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    JsonParser parser = null;

    try {
      // Initialize ObjectMapper object
      switch (data.consumeInt(1, 4)) {
        case 1:
          mapper =
              CsvMapper.builder(
                      CsvFactory.builder()
                          .enable(data.pickValue(EnumSet.allOf(CsvGenerator.Feature.class)))
                          .build())
                  .build();
          break;
        case 2:
          mapper = JavaPropsMapper.builder(JavaPropsFactory.builder().build()).build();
          break;
        case 3:
          mapper =
              TomlMapper.builder(
                      TomlFactory.builder()
                          .enable(data.pickValue(EnumSet.allOf(TomlReadFeature.class)))
                          .build())
                  .build();
          break;
        case 4:
          mapper =
              YAMLMapper.builder(
                      YAMLFactory.builder()
                          .enable(data.pickValue(EnumSet.allOf(YAMLGenerator.Feature.class)))
                          .build())
                  .build();
          break;
      }

      // Failsafe logic
      if (mapper == null) {
        return;
      }

      // Fuzz the deserialize methods for different Yaml/Toml/JavaProps/Csv objects
      if (data.consumeBoolean()) {
        byte[] output = new byte[data.remainingBytes()];
        parser = mapper.getFactory().createParser(output);
        mapper.readTree(parser);
      } else {
        Class type = data.pickValue(choice);
        String value = data.consumeRemainingAsString();
        if ((value == null) || (value.isEmpty())) {
          return;
        }
        mapper.readValue(value, type);
      }
    } catch (IOException | IllegalArgumentException | DateTimeException | IllegalStateException e) {
      // Known exception
    } finally {
      try {
        if (parser != null) {
          parser.close();
        }
      } catch (IOException e) {
        // Ignore exceptions for closing JsonParser object
      }
    }
  }

  private static void initializeClassChoice() {
    choice = new ArrayList<Class>();
    choice.add(ByteArrayContainer.class);
    choice.add(ByteArrayOutputStream.class);
    choice.add(ModelContainer.class);
    choice.add(DelegateContainer.class);
    choice.add(RawContainer.class);
    choice.add(MapContainer.class);
    choice.add(ListContainer.class);
    choice.add(ArrayContainer.class);
    choice.add(EnumFuzz.class);
    choice.add(EnumContainer.class);
    choice.add(Exception.class);
    choice.add(Map.class);
    choice.add(List.class);
    choice.add(Set.class);
    choice.add(Stream.class);
    choice.add(String.class);
    choice.add(Boolean.class);
    choice.add(Character.class);
    choice.add(Byte.class);
    choice.add(Integer.class);
    choice.add(Long.class);
    choice.add(Short.class);
    choice.add(Double.class);
    choice.add(Float.class);
    choice.add(BigInteger.class);
    choice.add(BigDecimal.class);
    choice.add(Number.class);
  }

  private static class ByteArrayContainer {
    public byte[] value;

    @JsonCreator
    public ByteArrayContainer(byte[] value) {
      this.value = value;
    }
  }

  @JsonRootName("Model")
  private static class ModelContainer {
    public String string;

    @JsonCreator
    public ModelContainer(@JsonProperty(value = "string", required = true) String string) {
      this.string = string;
    }
  }

  private static class DelegateContainer {
    public String string;

    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public DelegateContainer(String string) {
      this.string = string;
    }
  }

  @JsonPropertyOrder({"id", "raw"})
  private static class RawContainer {
    @JsonRawValue public String string;
  }

  private static class MapContainer {
    public Map<Integer, String> map;

    public void setMap(Map<Integer, String> map) {
      this.map = map;
    }
  }

  private static class ListContainer {
    public List<String> list;

    public void setList(List<String> list) {
      this.list = list;
    }
  }

  private static class ArrayContainer {
    public String[] array;

    public String[] getArray() {
      return array;
    }

    public void setArray(String[] array) {
      this.array = array;
    }
  }

  private static enum EnumFuzz {
    A,
    B,
    C,
    D,
    E;
  }

  private static class EnumContainer {
    public EnumFuzz enumFuzz;

    public EnumContainer(EnumFuzz enumFuzz) {
      this.enumFuzz = enumFuzz;
    }
  }
}
