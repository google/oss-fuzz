import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import java.io.IOException;
import java.util.Optional;
import java.util.List;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.fasterxml.jackson.annotation.JsonMerge;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;

public class DatatypeFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String content = data.consumeString(100);
        String merge = data.consumeRemainingAsString();

        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.registerModule(new Jdk8Module());

        try {
            Dummy dummy1 = mapper.readValue(content, Dummy.class);
            Dummy dummy2 = mapper.readValue(mapper.writeValueAsString(dummy1), Dummy.class);
            if (!dummy1.equals(dummy2)) {
                throw new FuzzerSecurityIssueLow("Different values " + dummy1.debug() + " != " + dummy2.debug());
            }
            mapper.readerForUpdating(merge);
        } catch (IOException e) {
        }
    }

    public static class Dummy {
        public Optional<String> value = Optional.empty();
        public Optional<Boolean> bool = Optional.empty();;

        @JsonMerge
        public Optional<List<String>> list = Optional.empty();

        public OptionalInt optint = OptionalInt.empty();
        public OptionalLong optlong = OptionalLong.empty();
        public OptionalDouble optdouble = OptionalDouble.empty();

        public String debug() { 
            return "%s %s %s %s %s %s".formatted(this.value, this.bool, this.list, this.optint, this.optlong, this.optdouble);
        } 
    }
}
