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
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.annotation.JsonRootName;
import tools.jackson.core.FormatFeature;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.TokenStreamFactory;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ObjectWriter;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.dataformat.csv.CsvFactory;
import tools.jackson.dataformat.csv.CsvMapper;
import tools.jackson.dataformat.csv.CsvWriteFeature;
import tools.jackson.dataformat.javaprop.JavaPropsFactory;
import tools.jackson.dataformat.javaprop.JavaPropsMapper;
import tools.jackson.dataformat.toml.TomlFactory;
import tools.jackson.dataformat.toml.TomlMapper;
import tools.jackson.dataformat.toml.TomlWriteFeature;
import tools.jackson.dataformat.yaml.YAMLFactory;
import tools.jackson.dataformat.yaml.YAMLMapper;
import tools.jackson.dataformat.yaml.YAMLWriteFeature;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.snakeyaml.engine.v2.api.DumpSettings;
import org.snakeyaml.engine.v2.common.FlowStyle;

/** This fuzzer targets the serialization methods of YAML/TOML/JavaProps/CSV objects */
public class SerializerFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    TokenStreamFactory factory = null;
    JsonGenerator generator = null;
    ObjectMapper mapper = null;
    FormatFeature feature = null;

    try {
      switch (data.consumeInt(1, 4)) {
        case 1:
          // Initialize CsvFactory object
          factory = CsvFactory.builder().build();

          // Initialize CsvMapper object
          mapper = CsvMapper.builder((CsvFactory) factory).build();

          // Initialize format options
          feature = data.pickValue(EnumSet.allOf(CsvWriteFeature.class));
          break;
        case 2:
          // Initialize JavaPropsFactory object
          factory = JavaPropsFactory.builder().build();

          // Initialize JavaPropsMapper object
          mapper = JavaPropsMapper.builder((JavaPropsFactory) factory).build();
          break;
        case 3:
          // Initialize TomlFactory object
          factory = TomlFactory.builder().build();

          // Initialize TomlMapper object
          mapper = TomlMapper.builder((TomlFactory) factory).build();

          // Initialize format options
          feature = data.pickValue(EnumSet.allOf(TomlWriteFeature.class));
          break;
        case 4:
          // Initialize YAMLFactory object
          DumpSettings dumpSettings = DumpSettings.builder()
                  .setDefaultFlowStyle(data.pickValue(EnumSet.allOf(FlowStyle.class)))
                  .build();
          factory = YAMLFactory.builder().dumperOptions(dumpSettings).build();

          // Initialize YAMLMapper object
          mapper = YAMLMapper.builder((YAMLFactory) factory).build();

          // Initialize format options
          feature = data.pickValue(EnumSet.allOf(YAMLWriteFeature.class));
          break;
      }

      // Failsafe logic
      if ((factory == null) || (mapper == null)) {
        return;
      }

      // Initialize ObjectWriter object
      ObjectWriter writer = mapper.writer();

      // Initialize ObjectNode object
      ObjectNode node = mapper.createObjectNode();

      // Initialize JsonGenerator object
      generator = factory.createGenerator(new StringWriter());

      // Randomize writer options
      if (data.consumeBoolean()) {
        writer = writer.withDefaultPrettyPrinter();
      }
      if (feature != null) {
        writer = writer.with(feature);
      }

      // Failsafe logic
      if (generator == null) {
        return;
      }

      // Object to write
      Object object = null;

      // Fuzz the serialize methods for different XML objects
      switch (data.consumeInt(1, 23)) {
        case 1:
          node.put("data", data.consumeRemainingAsBytes());
          object = node;
          break;
        case 2:
          generator.writeStartObject();
          generator.writeBinary(data.consumeRemainingAsBytes());
          generator.writeEndObject();
          break;
        case 3:
          generator.writeStartObject();
          generator.writeString(data.consumeRemainingAsString());
          generator.writeEndObject();
          break;
        case 4:
          Map<String, String> innerMap =
              Collections.singletonMap("inner_data", data.consumeRemainingAsString());
          Map<String, Map<String, String>> map = Collections.singletonMap("data", innerMap);
          object = map;
          break;
        case 5:
          List<String> innerList = Collections.singletonList(data.consumeRemainingAsString());
          List<List<String>> list = Collections.singletonList(innerList);
          object = list;
          break;
        case 6:
          object = BigInteger.valueOf(data.consumeLong());
          break;
        case 7:
          object = data.consumeRemainingAsString();
          break;
        case 8:
          object = data.consumeRemainingAsBytes();
          break;
        case 9:
          object = BigDecimal.valueOf(data.consumeDouble());
          break;
        case 10:
          object = data.consumeBoolean();
          break;
        case 11:
          object = data.consumeInt();
          break;
        case 12:
          object = data.consumeLong();
          break;
        case 13:
          object = data.consumeDouble();
          break;
        case 14:
          object = data.consumeBoolean();
          break;
        case 15:
          object = data.consumeByte();
          break;
        case 16:
          object = data.consumeChar();
          break;
        case 17:
          object = data.consumeBoolean();
          break;
        case 18:
          object = new ByteArrayInputStream(data.consumeRemainingAsBytes());
          break;
        case 19:
          object = new RawContainer(data.consumeRemainingAsString());
          break;
        case 20:
          object = new ByteBufferContainer(data.consumeRemainingAsBytes());
          break;
        case 21:
          object = new MapContainer(data.consumeRemainingAsString());
          break;
        case 22:
          object = new ListContainer(data.consumeRemainingAsString());
          break;
        case 23:
          object = new ByteArrayContainer(data.consumeRemainingAsBytes());
          break;
      }

      writer.writeValueAsString(object);
      writer.writeValueAsBytes(object);
    } catch (JacksonException | IllegalArgumentException e) {
      // Known exception
    } finally {
      try {
        if (generator != null) {
          // Close JsonGenerator object
          generator.flush();
          generator.close();
        }
      } catch (JacksonException e) {
        // Ignore exceptions for generator closing
      }
    }
  }

  @JsonRootName("ByteArray")
  private static class ByteArrayContainer {
    public byte[] value;

    public ByteArrayContainer(byte[] value) {
      this.value = value;
    }
  }

  @JsonPropertyOrder({"id", "raw"})
  private static class RawContainer {
    @JsonRawValue public String string;
    @JsonRawValue public char[] charArray;

    public RawContainer(String string) {
      this.string = string;
      this.charArray = string.toCharArray();
    }
  }

  private static class ByteBufferContainer {
    public ByteBuffer byteBuffer;

    public ByteBufferContainer(byte[] byteArray) {
      this.byteBuffer = ByteBuffer.allocateDirect(byteArray.length);
      this.byteBuffer.put(byteArray);
    }
  }

  private static class MapContainer {
    public Map<Integer, String> map;

    public MapContainer(String string) {
      this.map = new HashMap<Integer, String>();
      this.map.put(0, string);
    }
  }

  private static class ListContainer {
    public List<String> list;

    public ListContainer(String string) {
      this.list = new ArrayList<String>();
      this.list.add(string);
    }
  }
}
