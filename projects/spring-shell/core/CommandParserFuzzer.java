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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;

import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.shell.command.CommandOption;
import org.springframework.shell.command.CommandParser;

import java.util.Arrays;
import java.util.List;
import java.lang.Character;
public class CommandParserFuzzer {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        String longName1 = data.consumeString(200);
        String longName2 = data.consumeString(5);
        String shortName1 = data.consumeString(100);
        String argument = data.consumeString(100);
        String description = data.consumeRemainingAsString();

        char[] c = shortName1.toCharArray();
        Character[] shortNameArray = new Character[c.length];
        int i = 0;
        for (char value : c) {
            shortNameArray[i++] = Character.valueOf(value);
        }

        CommandParser parser;
        ConversionService conversionService = new DefaultConversionService();
        parser = CommandParser.of(conversionService);

        CommandOption option1 = CommandOption.of(new String[]{longName1}, shortNameArray, description);
        CommandOption option2 = CommandOption.of(new String[]{longName2}, new Character[0], description);
        List<CommandOption> options = Arrays.asList(option1, option2);
        String[] args = new String[]{"--"+longName1, argument};
        CommandParser.CommandParserResults results = parser.parse(options, args);

        if (results.errors().size() > 0){
            throw new FuzzerSecurityIssueMedium("Something went wrong while parsing");
        }
    }
}
