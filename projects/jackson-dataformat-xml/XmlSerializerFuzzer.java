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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.dataformat.xml.JacksonXmlModule;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.ser.ToXmlGenerator;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/** This fuzzer targets the serialization methods of Hppc objects */
public class XmlSerializerFuzzer {
  private static ObjectWriter writer;

  public static void fuzzerInitialize() {
    // Register the JacksonXmlModule for the serialization
    writer = new XmlMapper(new JacksonXmlModule()).writer();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Object object = null;

      // Fuzz the serialize methods for different XML objects
      if (data.consumeBoolean()) {
        writer = writer.withDefaultPrettyPrinter();
      }
      writer = writer.with(data.pickValue(EnumSet.allOf(ToXmlGenerator.Feature.class)));
      switch (data.consumeInt(1, 24)) {
        case 1:
          object = new ByteArrayContainer(data.consumeRemainingAsBytes());
          break;
        case 2:
          List<String> list = new ArrayList<String>();
          list.add(data.consumeRemainingAsString());
          object = list;
          break;
        case 3:
          List<String> listIter = new ArrayList<String>();
          listIter.add(data.consumeRemainingAsString());
          object = listIter.iterator();
          break;
        case 4:
          object = Stream.of(data.consumeRemainingAsString()).iterator();
          break;
        case 5:
          List<String> listIterCon = new ArrayList<String>();
          listIterCon.add(data.consumeRemainingAsString());
          object = new IteratorContainer(listIterCon.iterator());
          break;
        case 6:
          object = new ItemContainer();
          break;
        case 7:
          object = new ModelContainer(data.consumeRemainingAsString());
          break;
        case 8:
          object = new RawContainer(data.consumeRemainingAsString());
          break;
        case 9:
          object = new ByteBufferContainer(data.consumeRemainingAsBytes());
          break;
        case 10:
          object = new MapContainer(data.consumeRemainingAsString());
          break;
        case 11:
          object = new ListContainer(data.consumeRemainingAsString());
          break;
        case 12:
          object = BigInteger.valueOf(data.consumeLong());
          break;
        case 13:
          object = data.consumeRemainingAsString();
          break;
        case 14:
          object = data.consumeRemainingAsBytes();
          break;
        case 15:
          object = BigDecimal.valueOf(data.consumeDouble());
          break;
        case 16:
          object = data.consumeBoolean();
          break;
        case 17:
          object = data.consumeInt();
          break;
        case 18:
          object = data.consumeLong();
          break;
        case 19:
          object = data.consumeDouble();
          break;
        case 20:
          object = data.consumeBoolean();
          break;
        case 21:
          object = data.consumeByte();
          break;
        case 22:
          object = data.consumeChar();
          break;
        case 23:
          object = data.consumeBoolean();
          break;
        case 24:
          object = new ByteArrayInputStream(data.consumeRemainingAsBytes());
          break;
      }

      writer.writeValueAsString(object);
      writer.writeValueAsBytes(object);
    } catch (IOException | NumberFormatException e) {
      // Known exception
    }
  }

  private static class ByteArrayContainer {
    public byte[] value;

    public ByteArrayContainer(byte[] value) {
      this.value = value;
    }
  }

  private static class IteratorContainer {
    private Iterator<String> iterator;

    @JacksonXmlElementWrapper(localName = "elements")
    @JacksonXmlProperty(localName = "element")
    public Iterator<String> getIterator() {
      return iterator;
    }

    public IteratorContainer(Iterator<String> iterator) {
      this.iterator = iterator;
    }
  }

  private static class ItemContainer {
    @JsonProperty("item")
    @JacksonXmlElementWrapper(localName = "list")
    public Iterator<String> items() {
      return new Iterator<String>() {
        int item = 5;

        @Override
        public boolean hasNext() {
          return item > 0;
        }

        @Override
        public String next() {
          return Integer.toString(--item);
        }
      };
    }
  }

  @JsonRootName("Model")
  private static class ModelContainer {
    @JacksonXmlProperty(isAttribute = true, localName = "string")
    public String string;

    public ModelContainer(String string) {
      this.string = string;
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
