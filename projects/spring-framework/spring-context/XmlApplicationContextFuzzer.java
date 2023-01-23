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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.util.*;
import java.nio.file.Files;
import org.springframework.context.support.FileSystemXmlApplicationContext;
import org.springframework.context.ApplicationContext;
import java.nio.file.Path;
import java.io.IOException;
import org.springframework.beans.factory.BeanDefinitionStoreException;

public class XmlApplicationContextFuzzer {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String path = data.consumeString(50);

        try {
            Path tempFile = Files.createTempFile("dummy", ".xml");
            Files.writeString(tempFile, data.consumeRemainingAsString());

            ApplicationContext ctx = new FileSystemXmlApplicationContext("file:" + tempFile.toAbsolutePath().toString());

            ctx.getApplicationName();
            ctx.getDisplayName();
            ctx.getParent();
            ctx.getResource(path);
            ctx.getClassLoader();

            Files.delete(tempFile);
        } catch (IOException|BeanDefinitionStoreException e) {}
    }
}
