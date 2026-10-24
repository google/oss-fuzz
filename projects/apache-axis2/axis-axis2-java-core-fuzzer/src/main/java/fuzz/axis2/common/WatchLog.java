// Copyright 2026 Google LLC
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

package fuzz.axis2.common;

import org.apache.commons.logging.Log;

/**
 * commons-logging Log that discards output but inspects every Throwable Axis2 logs, so that a
 * StackOverflowError / OutOfMemoryError caught by the framework still reaches Findings.
 * Silencing the log also keeps the fuzzers fast: bad requests make Axis2 log a stack trace each.
 * {@link #install()} must run before the first Axis2 class is loaded.
 */
public class WatchLog implements Log {

    public static void install() {
        System.setProperty("org.apache.commons.logging.LogFactory",
                "org.apache.commons.logging.impl.LogFactoryImpl");
        System.setProperty("org.apache.commons.logging.Log", WatchLog.class.getName());
    }

    public WatchLog(String name) {
    }

    private static void inspect(Throwable t) {
        if (t != null) {
            Findings.logged(t);
        }
    }

    public boolean isDebugEnabled() { return false; }
    public boolean isErrorEnabled() { return true; }
    public boolean isFatalEnabled() { return true; }
    public boolean isInfoEnabled() { return false; }
    public boolean isTraceEnabled() { return false; }
    public boolean isWarnEnabled() { return true; }

    public void trace(Object m) { if (m instanceof Throwable) inspect((Throwable) m); }
    public void trace(Object m, Throwable t) { inspect(t); }
    public void debug(Object m) { if (m instanceof Throwable) inspect((Throwable) m); }
    public void debug(Object m, Throwable t) { inspect(t); }
    public void info(Object m) { if (m instanceof Throwable) inspect((Throwable) m); }
    public void info(Object m, Throwable t) { inspect(t); }
    public void warn(Object m) { if (m instanceof Throwable) inspect((Throwable) m); }
    public void warn(Object m, Throwable t) { inspect(t); }
    public void error(Object m) { if (m instanceof Throwable) inspect((Throwable) m); }
    public void error(Object m, Throwable t) { inspect(t); }
    public void fatal(Object m) { if (m instanceof Throwable) inspect((Throwable) m); }
    public void fatal(Object m, Throwable t) { inspect(t); }
}
