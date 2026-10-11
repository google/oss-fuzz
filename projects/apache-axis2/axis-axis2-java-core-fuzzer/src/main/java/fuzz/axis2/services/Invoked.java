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

package fuzz.axis2.services;

import org.apache.axis2.context.MessageContext;

/** Records which deployed service actually ran for the current request (dispatch oracle). */
public final class Invoked {
    private static final ThreadLocal<String> SERVICE = new ThreadLocal<>();

    private Invoked() {
    }

    public static void mark() {
        MessageContext mc = MessageContext.getCurrentMessageContext();
        SERVICE.set(mc != null && mc.getAxisService() != null ? mc.getAxisService().getName() : "?");
    }

    public static String take() {
        String s = SERVICE.get();
        SERVICE.remove();
        return s;
    }
}
