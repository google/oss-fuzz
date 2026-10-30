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

import jakarta.activation.DataHandler;
import org.apache.axiom.om.OMElement;

import java.io.IOException;
import java.io.InputStream;
import java.util.Calendar;

/**
 * Deliberately boring service: it only echoes what the framework deserialised. Anything
 * dangerous that happens while handling a request therefore happens in Axis2, not here.
 * Deployed under several names (FuzzService, Secret, Hidden) with RPCMessageReceiver.
 */
public class FuzzService {

    public String echo(String s) {
        Invoked.mark();
        return s;
    }

    public int[] ints(int[] a) {
        Invoked.mark();
        return a;
    }

    public String[] strings(String[] a) {
        Invoked.mark();
        return a;
    }

    public Bean echoBean(Bean b) {
        Invoked.mark();
        return b;
    }

    public Bean[] beans(Bean[] b) {
        Invoked.mark();
        return b;
    }

    public Node echoNode(Node n) {
        Invoked.mark();
        return n;
    }

    public Calendar date(Calendar c) {
        Invoked.mark();
        return c;
    }

    public OMElement raw(OMElement e) {
        Invoked.mark();
        return e;
    }

    public Object anything(Object o) {
        Invoked.mark();
        return o;
    }

    public void ping(String s) {
        Invoked.mark();
    }

    /** Reads an uploaded part completely, like a typical upload endpoint would. */
    public long upload(String name, DataHandler file) throws IOException {
        Invoked.mark();
        if (file == null) {
            return -1;
        }
        long n = 0;
        byte[] buf = new byte[8192];
        try (InputStream in = file.getInputStream()) {
            int r;
            while ((r = in.read(buf)) > 0) {
                n += r;
            }
        }
        return n;
    }
}
