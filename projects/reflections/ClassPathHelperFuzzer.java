// Copyright 2024 Google LLC
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
import org.reflections.util.ClasspathHelper;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;



public class ClassPathHelperFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try{
            List<URL> urls = new ArrayList<>();
            for (int i = 0; i < data.consumeInt(0, 100); i++) {
                urls.add(new URL("http://" + data.consumeString(50)));
            }
            URLClassLoader urlClassLoader = new URLClassLoader(urls.toArray(new URL[0]), null);
            ClasspathHelper.forClassLoader(urlClassLoader);
        }
        catch (MalformedURLException e) {}
    }
}