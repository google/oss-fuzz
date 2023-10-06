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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.kohsuke.args4j.*;
import org.kohsuke.args4j.spi.StringArrayOptionHandler;

import java.io.File;
import java.util.*;

public class CmdLineParserFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        ParserProperties props = ParserProperties.defaults();
        try {
            props.withAtSyntax(data.consumeBoolean());
            props.withShowDefaults(data.consumeBoolean());
            props.withUsageWidth(data.consumeInt());
            props.withOptionValueDelimiter(data.consumeString(100));
        } catch (IllegalArgumentException e) {}

        Collection<String> args = new HashSet<String>();
        for (int i = 0; i < data.consumeInt(0, 50); i++) {
            args.add(data.consumeString(100));
        }

        CmdLineParser parser = new CmdLineParser(DummyClass.class);
        try {
            parser.parseArgument(args);
        } catch (CmdLineException e) {}
    }

    static class DummyClass {
        @Option(name="-str",usage="set a string")
        public String str = "pretty string";

        @Option(name="-req",usage="set a string", required = true)
        public String req = "required";

        @Option(name="-noDefault")
        public String noDefault;

        @Option(name="-noDefaultReq", required = true)
        public String noDefaultReq;

        @Option(name="-byteVal", usage = "my favorite byte")
        public byte byteVal;

        @Option(name="-strArray", usage="my favorite strarr")
        public String strArray[] = new String[] { "san", "dra", "chen"};

        public enum DrinkName {
            BEER,
            WHISKEY,
            SCOTCH,
            BOURBON,
            BRANDY
        };

        @Option(name="-drinkArray", usage="my favorite drinks")
        public DrinkName drinkArray[] = new DrinkName[] { DrinkName.BEER, DrinkName.BOURBON };

        @Option(name="-drink", usage="my favorite drink")
        public DrinkName drink = DrinkName.BEER;

        @Option(name="-drinkList", usage="my favorite drinks")
        public List<DrinkName> drinkList = Arrays.asList(DrinkName.BEER, DrinkName.BRANDY);

        @Argument
        public String arguments[] = new String[] { "foo", "bar" };

        @Option(name="-o", usage="output to this file", metaVar="OUTPUT")
        private File out = new File(".");

        @Option(name="-hidden-str", hidden=true, usage="hidden option")
        private String hiddenStr = "(default value)";

        @Option(name="-n", usage="repeat <n> times\n")
        private int num = -1;

        @Option(name="-boolean")
        public boolean _boolean;

        @Option(name="-byte")
        public byte _byte;

        @Option(name="-char")
        public char _char;

        @Option(name="-double")
        public double _double;

        @Option(name="-float")
        public float _float;

        @Option(name="-int")
        public int _int;

        @Option(name="-long")
        public long _long;

        @Option(name="-short")
        public short _short;

        @Option(name = "-z", depends ={"-y"})
        int a;

        @Option(name = "-y", depends ={"-z"})
        int b;

        @Option(name = "-a", aliases="--alpha")
        int w;

        @Option(name = "-b", aliases="--bravo")
        int x;

        @Option(name = "-c", depends ={"--alpha"})
        int y;

        @Option(name = "-d", depends ={"-b", "-c"})
        int z;

        @Option(name = "-h", forbids ={"-a", "-b"})
        int o;

        @Option(name="-list")
        List<String> list;

        @Option(name="-string")
        String string;

        @Option(name="-array")
        String[] array;

        @Option(name="-multivalued-array", handler = StringArrayOptionHandler.class)
        String[] multiValuedArray;
    }
}
