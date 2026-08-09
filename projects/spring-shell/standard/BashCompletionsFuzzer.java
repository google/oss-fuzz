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

import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.shell.command.CommandCatalog;
import org.springframework.shell.standard.completion.BashCompletions;


public class BashCompletionsFuzzer {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        String command = data.consumeRemainingAsString();

        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();

        CommandCatalog commandCatalog = CommandCatalog.of();
        BashCompletions completions = new BashCompletions(context, commandCatalog);
        String bash = completions.generate(command);

    }
}
